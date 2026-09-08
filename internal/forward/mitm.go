package forward

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"fairway/internal/challenge"
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
	// Brotli и zstd распаковывать нечем, а в сжатое тело не заглянуть —
	// оставляем клиенту только gzip и deflate. Так делают все MITM-прокси.
	if accept := challenge.AcceptEncoding(req.Header.Values("Accept-Encoding")); accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}

	// Тело до лимита читается в память: иначе повторить запрос нельзя,
	// а keep-alive соединение к цели умирает как раз в паузе между
	// запросами — и первый POST после паузы получал бы 502.
	rewind, err := bufferBody(req, s.replayBodyLimit())
	if err != nil {
		return s.fail(sample, started, client, err, up)
	}
	retriable := rewind != nil

	conn, connect, fresh, err := up.connection()
	sample.Connect = connect
	sample.Reused = !fresh
	if err != nil {
		return s.fail(sample, started, client, err, up)
	}

	resp, ttfb, received, err := exchange(conn, req)
	if err != nil && retriable && !fresh && !received {
		// Цель могла закрыть keep-alive соединение, пока оно простаивало, —
		// это штатная ситуация, а не отказ прокси. Повторяем только если от
		// цели не пришло ни байта: получив хотя бы начало ответа, нельзя
		// знать, выполнила ли она запрос, а повторять POST вслепую опасно.
		up.close()
		conn, connect, fresh, err = up.connection()
		sample.Connect = connect
		sample.Reused = false
		if err == nil {
			rewind()
			resp, ttfb, _, err = exchange(conn, req)
		}
	}
	if err != nil {
		return s.fail(sample, started, client, err, up)
	}
	defer resp.Body.Close()

	sample.Status = resp.StatusCode
	sample.TTFB = ttfb

	// Начало тела запоминается по дороге к клиенту: по нему видно, не
	// подсунул ли сайт вместо содержимого страницу проверки.
	counted := &countingReader{r: resp.Body}
	sniff := &prefixReader{r: counted, limit: challenge.PrefixSize}
	resp.Body = io.NopCloser(sniff)
	if err := resp.Write(client); err != nil {
		sample.Err = err
	}
	sample.Bytes = counted.n
	sample.Duration = time.Since(started)
	sample.Challenge = challenge.Detect(resp.StatusCode, resp.Header,
		challenge.Decode(resp.Header.Get("Content-Encoding"), sniff.buf))

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

// bufferBody вычитывает тело запроса в память, если оно не больше limit,
// и возвращает функцию, которая подставляет его заново перед повтором.
// nil означает «повторять нельзя»: тело слишком большое и уходит потоком.
// Запрос без тела повторяем всегда — перематывать там нечего.
func bufferBody(req *http.Request, limit int64) (rewind func(), err error) {
	// Пустое тело распознаём по самому телу, а не по длине: у запроса,
	// собранного клиентом, нулевая длина при живом Body значит «неизвестно».
	if req.Body == nil || req.Body == http.NoBody {
		return func() {}, nil
	}
	if limit < 0 || req.ContentLength > limit {
		return nil, nil
	}
	// Читаем на байт больше лимита: так видно, что тело неизвестной длины
	// (chunked) в лимит не влезло, не дочитывая его целиком.
	buf, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		// Не влезло: то, что уже прочитали, отдаём вперёд остатка потока.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
		return nil, nil
	}
	req.Body.Close()
	// Тело известной длины пишется с Content-Length, а не chunked: цели
	// так проще, а нам — единообразнее при повторе.
	req.ContentLength = int64(len(buf))
	req.TransferEncoding = nil
	rewind = func() { req.Body = io.NopCloser(bytes.NewReader(buf)) }
	rewind()
	return rewind, nil
}

func (s *Server) replayBodyLimit() int64 {
	if s.ReplayBodyLimit == 0 {
		return DefaultReplayBodyLimit
	}
	return s.ReplayBodyLimit
}

// exchange отправляет запрос и читает ответ, замеряя время до первого байта.
// received сообщает, пришёл ли от цели хотя бы один байт: по нему решается,
// можно ли повторять запрос после ошибки.
func exchange(conn net.Conn, req *http.Request) (resp *http.Response, ttfb time.Duration, received bool, err error) {
	sent := time.Now()
	if err := req.Write(conn); err != nil {
		return nil, 0, false, err
	}
	watcher := &firstByteWatcher{r: conn}
	resp, err = http.ReadResponse(bufio.NewReader(watcher), req)
	received = !watcher.first.IsZero()
	if err != nil {
		return nil, 0, received, err
	}
	if received {
		ttfb = watcher.first.Sub(sent)
	}
	return resp, ttfb, received, nil
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

// prefixReader пропускает поток через себя и оставляет копию первых
// limit байт.
type prefixReader struct {
	r     io.Reader
	limit int
	buf   []byte
}

func (p *prefixReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if room := p.limit - len(p.buf); n > 0 && room > 0 {
		if n < room {
			room = n
		}
		p.buf = append(p.buf, b[:room]...)
	}
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
