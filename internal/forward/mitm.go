package forward

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// CertIssuer выпускает сертификаты доменов для разговора с клиентом.
// Интерфейс, а не конкретный тип, чтобы форвардер можно было тестировать
// с любым источником сертификатов.
type CertIssuer interface {
	// ServerConfig возвращает TLS-конфигурацию, подбирающую сертификат по SNI.
	ServerConfig(fallbackHost string) *tls.Config
}

// mitmTunnel обслуживает CONNECT с расшифровкой.
//
// Схема намеренно симметричная: одно клиентское TLS-соединение — одно
// TLS-соединение до цели через выбранный апстрим. Никакого пула: HTTP/1.1
// в рамках соединения всё равно последователен, зато замеры получаются
// точными, а поведение предсказуемым.
func (s *Server) mitmTunnel(w http.ResponseWriter, route *Route, target string) {
	domain := hostOnly(target)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "соединение не поддерживает перехват", http.StatusInternalServerError)
		return
	}
	clientRaw, _, err := hj.Hijack()
	if err != nil {
		s.logf("перехват соединения: %v", err)
		return
	}
	defer clientRaw.Close()

	if _, err := clientRaw.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	clientTLS := tls.Server(clientRaw, s.Issuer.ServerConfig(domain))
	handshakeCtx, cancel := context.WithTimeout(context.Background(), s.dialTimeout())
	err = clientTLS.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		// Три обычные причины, в порядке частоты: CA не импортирован на машину;
		// клиент проверяет отзыв, а у приватного CA нет CRL/OCSP; в клиенте
		// зашит pinning. Первые две лечатся на стороне клиента, третья —
		// только исключением домена (mitm: false).
		s.logf("%s: клиент отверг наш сертификат (%v) — проверьте, импортирован ли CA; если это pinning, добавьте домен в исключения", domain, err)
		return
	}
	defer clientTLS.Close()

	up := &mitmUpstream{route: route, target: target, timeout: s.dialTimeout(), origin: s.OriginTLS}
	defer up.close()

	clientReader := bufio.NewReader(clientTLS)
	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return // клиент закрыл соединение или прислал мусор
		}

		sample := s.roundTrip(up, clientTLS, req, domain, route.Name)
		s.observe(sample)

		if sample.Err != nil || req.Close {
			return
		}
	}
}

// roundTrip проводит один расшифрованный запрос до цели и обратно, попутно
// снимая замер. В отличие от непрозрачного туннеля здесь виден настоящий
// HTTP-статус — отсюда точный детект бана.
func (s *Server) roundTrip(up *mitmUpstream, client io.Writer, req *http.Request, domain, proxyName string) Sample {
	sample := Sample{Domain: domain, Upstream: proxyName}
	started := time.Now()

	req.URL.Scheme = "https"
	req.URL.Host = up.target
	req.RequestURI = ""
	removeHopByHop(req.Header)

	// Повторить можно только запрос без тела: перечитать тело нельзя.
	retriable := req.Body == nil || req.ContentLength == 0

	conn, connect, fresh, err := up.connection()
	sample.Connect = connect
	sample.Reused = !fresh
	if err != nil {
		return s.fail(sample, started, client, err, up)
	}

	resp, ttfb, err := exchange(conn, req)
	if err != nil && retriable && !fresh {
		// Цель могла закрыть keep-alive соединение, пока оно простаивало, —
		// это штатная ситуация, а не отказ прокси.
		up.close()
		conn, connect, fresh, err = up.connection()
		sample.Connect = connect
		sample.Reused = false
		if err == nil {
			resp, ttfb, err = exchange(conn, req)
		}
	}
	if err != nil {
		return s.fail(sample, started, client, err, up)
	}
	defer resp.Body.Close()

	sample.Status = resp.StatusCode
	sample.TTFB = ttfb

	counted := &countingReader{r: resp.Body}
	resp.Body = io.NopCloser(counted)
	if err := resp.Write(client); err != nil {
		sample.Err = err
	}
	sample.Bytes = counted.n
	sample.Duration = time.Since(started)

	if resp.Close {
		up.close()
	}
	return sample
}

// fail оформляет неудачу: сообщает клиенту и закрывает соединение к цели.
func (s *Server) fail(sample Sample, started time.Time, client io.Writer, err error, up *mitmUpstream) Sample {
	sample.Err = err
	sample.Duration = time.Since(started)
	writeGatewayError(client, err)
	up.close()
	return sample
}

// exchange отправляет запрос и читает ответ, замеряя время до первого байта.
func exchange(conn net.Conn, req *http.Request) (*http.Response, time.Duration, error) {
	sent := time.Now()
	if err := req.Write(conn); err != nil {
		return nil, 0, err
	}
	watcher := &firstByteWatcher{r: conn}
	resp, err := http.ReadResponse(bufio.NewReader(watcher), req)
	if err != nil {
		return nil, 0, err
	}
	var ttfb time.Duration
	if !watcher.first.IsZero() {
		ttfb = watcher.first.Sub(sent)
	}
	return resp, ttfb, nil
}

// mitmUpstream держит одно TLS-соединение до цели через выбранный апстрим.
type mitmUpstream struct {
	route   *Route
	target  string
	timeout time.Duration
	origin  *tls.Config

	conn net.Conn
}

// connection отдаёт живое соединение, устанавливая его при необходимости.
// Возвращает время установки и признак того, что соединение только что создано:
// на переиспользованном connect не измеряется и в рейтинг не попадает.
func (u *mitmUpstream) connection() (net.Conn, time.Duration, bool, error) {
	if u.conn != nil {
		return u.conn, 0, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()

	started := time.Now()
	raw, err := u.route.Upstream.DialTarget(ctx, u.target)
	if err != nil {
		return nil, time.Since(started), true, err
	}
	cfg := &tls.Config{}
	if u.origin != nil {
		cfg = u.origin.Clone()
	}
	cfg.ServerName = hostOnly(u.target)
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	cfg.NextProtos = []string{"http/1.1"} // разбирается только HTTP/1.x
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, time.Since(started), true, err
	}
	u.conn = tlsConn
	return u.conn, time.Since(started), true, nil
}

func (u *mitmUpstream) close() {
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
}

// countingReader считает прочитанные байты тела ответа.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

// firstByteWatcher запоминает момент, когда от цели пришёл первый байт.
type firstByteWatcher struct {
	r     io.Reader
	first time.Time
}

func (f *firstByteWatcher) Read(b []byte) (int, error) {
	n, err := f.r.Read(b)
	if n > 0 && f.first.IsZero() {
		f.first = time.Now()
	}
	return n, err
}

// writeGatewayError сообщает клиенту о неудаче внутри расшифрованного туннеля.
func writeGatewayError(w io.Writer, cause error) {
	body := "апстрим недоступен: " + cause.Error()
	resp := &http.Response{
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	_ = resp.Write(w)
}
