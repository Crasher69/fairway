// Package forward — ядро прокси: приём клиентских запросов, прокладка их
// через выбранный апстрим и замер качества соединения.
package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

// Server принимает подключения как обычный HTTP/HTTPS прокси.
// HTTPS либо туннелируется как есть, либо расшифровывается — это решает
// правило домена (mitm) и наличие Issuer.
type Server struct {
	// Pick выбирает маршрут для домена. Обязателен. Ошибка означает
	// «нет живого прокси» — клиент получит 503.
	Pick func(domain string) (*Route, error)
	// Observe вызывается по завершении каждого запроса. Может быть nil.
	Observe func(Sample)
	// Issuer выпускает сертификаты для расшифровки TLS. Без него правило
	// mitm: true не действует — соединение просто туннелируется.
	Issuer CertIssuer
	// OriginTLS — шаблон настроек TLS для соединения с целью в режиме MITM.
	// Обычно nil: сертификат цели проверяется по системным корням.
	OriginTLS *tls.Config
	// DialTimeout ограничивает установку соединения с целью через апстрим.
	DialTimeout time.Duration
	// ReplayBodyLimit — до какого размера тело запроса в режиме MITM
	// буферизуется в памяти, чтобы запрос можно было повторить, если цель
	// закрыла keep-alive соединение. 0 означает DefaultReplayBodyLimit,
	// отрицательное — не буферизовать (повторяются только запросы без тела).
	ReplayBodyLimit int64
	Logger          *log.Logger
}

const defaultDialTimeout = 15 * time.Second

// DefaultReplayBodyLimit — 1 МиБ: покрывает формы, JSON и мелкие загрузки,
// а большой файл держать в памяти ради редкого повтора незачем.
const DefaultReplayBodyLimit = 1 << 20

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// handleConnect обслуживает HTTPS: поднимает туннель до цели через апстрим
// и гоняет байты в обе стороны, попутно считая TTFB и объём трафика.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	sample := Sample{Domain: hostOnly(target)}
	started := time.Now()

	route, err := s.Pick(sample.Domain)
	if err != nil {
		http.Error(w, "нет доступного апстрима: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer route.release()
	up := route.Upstream
	sample.Upstream = route.Name

	if route.MITM {
		if s.Issuer == nil {
			s.logf("%s: MITM включён правилом, но выпуск сертификатов не настроен — туннелирую как есть", sample.Domain)
		} else {
			s.mitmTunnel(w, route, target)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.dialTimeout())
	defer cancel()

	dialStart := time.Now()
	upConn, err := up.DialTarget(ctx, target)
	sample.Connect = time.Since(dialStart)
	if err != nil {
		sample.Err = err
		sample.Duration = time.Since(started)
		s.observe(sample)
		http.Error(w, "апстрим недоступен: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upConn.Close()
	connected := time.Now()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "соединение не поддерживает перехват", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		s.logf("перехват соединения: %v", err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	counted := &countingConn{Conn: upConn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// clientBuf может держать байты, вычитанные вместе с заголовками.
		_, _ = io.Copy(upConn, clientBuf)
		closeWrite(upConn)
	}()
	_, _ = io.Copy(clientConn, counted)
	closeWrite(clientConn)
	<-done

	first, n := counted.stats()
	if !first.IsZero() {
		sample.TTFB = first.Sub(connected)
	}
	sample.Bytes = n
	sample.Duration = time.Since(started)
	s.observe(sample)
}

// handleHTTP обслуживает обычный HTTP. Через http-апстрим запрос уходит
// в absolute-form (так работает любой HTTP-прокси), через socks5 и direct —
// в origin-form по прямому соединению с целью.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "это прокси-сервер: ожидается запрос в absolute-form", http.StatusBadRequest)
		return
	}
	sample := Sample{Domain: hostOnly(r.Host)}
	started := time.Now()

	route, err := s.Pick(sample.Domain)
	if err != nil {
		http.Error(w, "нет доступного апстрима: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer route.release()
	sample.Upstream = route.Name

	// Запрос идёт через пул keep-alive соединений апстрима. Замеры снимаются
	// трассировкой: она одна знает, было ли соединение установлено заново
	// или взято из пула, и когда пришёл первый байт ответа.
	var (
		dialStart, gotConn, firstByte time.Time
		reused                        bool
	)
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			if dialStart.IsZero() {
				dialStart = time.Now()
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			gotConn = time.Now()
			reused = info.Reused
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	outReq := r.Clone(httptrace.WithClientTrace(r.Context(), trace))
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	resp, err := route.Upstream.Transport(s.dialTimeout()).RoundTrip(outReq)
	finishConnect := func() {
		sample.Reused = reused
		if !reused && !dialStart.IsZero() {
			end := gotConn
			if end.IsZero() {
				end = time.Now()
			}
			sample.Connect = end.Sub(dialStart)
		}
	}
	if err != nil {
		finishConnect()
		sample.Err = err
		sample.Duration = time.Since(started)
		s.observe(sample)
		http.Error(w, "апстрим недоступен: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	finishConnect()
	sample.Status = resp.StatusCode
	if !firstByte.IsZero() && !gotConn.IsZero() {
		sample.TTFB = firstByte.Sub(gotConn)
	}

	respHeader := w.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			respHeader.Add(k, v)
		}
	}
	removeHopByHop(respHeader)
	w.WriteHeader(resp.StatusCode)
	counted := &countingReader{r: resp.Body}
	if _, err := io.Copy(w, counted); err != nil && !errors.Is(err, io.EOF) {
		sample.Err = err
	}
	sample.Bytes = counted.n
	sample.Duration = time.Since(started)
	s.observe(sample)
}

func (s *Server) dialTimeout() time.Duration {
	if s.DialTimeout > 0 {
		return s.DialTimeout
	}
	return defaultDialTimeout
}

func (s *Server) observe(sample Sample) {
	if s.Observe != nil {
		s.Observe(sample)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

// hostOnly отрезает порт: "example.com:443" → "example.com".
func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

// hopByHop — заголовки одного участка соединения, их нельзя пересылать дальше.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	// Connection перечисляет дополнительные hop-by-hop заголовки — снести и их.
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if token = strings.TrimSpace(token); token != "" {
				h.Del(token)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// closeWrite закрывает передающую половину соединения, чтобы вторая сторона
// увидела EOF, а не ждала до таймаута.
func closeWrite(c net.Conn) {
	type writeCloser interface{ CloseWrite() error }
	if wc, ok := c.(writeCloser); ok {
		_ = wc.CloseWrite()
	}
}
