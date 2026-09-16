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
	"sync/atomic"
	"time"

	"fairway/internal/i18n"
)

// Server принимает подключения как обычный HTTP/HTTPS прокси.
// HTTPS либо туннелируется как есть, либо расшифровывается — это решает
// правило домена (mitm) и наличие Issuer.
type Server struct {
	// Pick выбирает маршрут для домена. Обязателен. Ошибка означает
	// «нет живого прокси» — клиент получит 503. avoid — имена маршрутов,
	// через которые этот запрос уже не прошёл; брать их снова нельзя.
	Pick func(domain string, avoid []string) (*Route, error)
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
	// IdleTimeout — сколько туннель может молчать в обе стороны, прежде
	// чем его закроют. 0 означает DefaultIdleTimeout, отрицательное —
	// без ограничения.
	IdleTimeout time.Duration
	Logger      *log.Logger
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
//
// Прокси, который принимает CONNECT и молчит, — самый неприятный случай:
// ошибки нет, замера нет, а браузер ждёт. Поэтому туннель живёт по трём
// правилам, и все три нужны вместе:
//
//   - пока клиенту не отвечено 200, неудачное подключение повторяется
//     через другой прокси — клиент ничего не замечает;
//   - после 200 цель обязана прислать первый байт за DialTimeout, иначе
//     это ошибка прокси для этого домена, и присланное клиентом (TLS
//     ClientHello) повторяется через другой прокси;
//   - туннель, в котором IdleTimeout нет движения, закрывается: он держит
//     слот рабочего набора и соединение у прокси, а не даёт ничего.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	domain := hostOnly(target)
	started := time.Now()

	route, err := s.Pick(domain, nil)
	if err != nil {
		http.Error(w, i18n.T("no upstream available: ")+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Маршрут меняется при повторе через другой прокси, поэтому
	// освобождается тот, что будет в переменной к концу, а не первый.
	defer func() { route.release() }()

	if route.MITM {
		if s.Issuer == nil {
			s.logf(i18n.T("%s: MITM enabled by rule, but certificate issuing is not configured — tunnelling as is"), domain)
		} else {
			s.mitmTunnel(w, route, target)
			return
		}
	}

	var (
		avoid  []string
		upConn net.Conn
		sample Sample
	)
	for {
		sample = Sample{Domain: domain, Upstream: route.Name}
		upConn, err = s.dialTunnel(r.Context(), route, target, &sample)
		if err == nil {
			break
		}
		sample.Duration = time.Since(started)
		s.observe(sample)
		var next *Route
		next, err = s.nextRoute(domain, route, &avoid)
		if err != nil {
			http.Error(w, i18n.T("upstream unavailable: ")+sample.Err.Error(), http.StatusBadGateway)
			return
		}
		route = next
	}
	defer func() { upConn.Close() }()
	connected := time.Now()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, i18n.T("connection does not support hijacking"), http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		s.logf(i18n.T("hijacking connection: %v"), err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	var activity atomic.Int64
	activity.Store(time.Now().UnixNano())
	head := &tunnelHead{dst: upConn, activity: &activity}
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 32<<10)
		for {
			// clientBuf может держать байты, вычитанные вместе с заголовками.
			n, err := clientBuf.Read(buf)
			if n > 0 {
				_ = head.write(buf[:n])
			}
			if err != nil {
				head.closeWrite()
				return
			}
		}
	}()
	finish := func() {
		clientConn.Close()
		<-pumpDone
	}

	// Ждём первый байт от цели. Если его нет, а клиент что-то прислал,
	// прокси для этого запроса провалился, и клиентские байты уходят
	// через другой.
	buf := make([]byte, 32<<10)
	var n int
	for {
		_ = upConn.SetReadDeadline(time.Now().Add(s.dialTimeout()))
		var rerr error
		n, rerr = upConn.Read(buf)
		if n > 0 {
			_ = upConn.SetReadDeadline(time.Time{})
			break
		}
		if rerr == nil {
			continue // пустое чтение без ошибки — ждём дальше
		}
		sent, replayable := head.state()
		upConn.Close()
		if !sent {
			// Клиент так ничего и не прислал: браузер открыл соединение
			// впрок и передумал. Прокси ни при чём — замера нет.
			finish()
			return
		}
		sample.Err = tunnelError(rerr, s.dialTimeout())
		sample.Duration = time.Since(started)
		s.observe(sample)
		if !replayable {
			finish()
			return
		}
		for {
			var next *Route
			next, err = s.nextRoute(domain, route, &avoid)
			if err != nil {
				finish()
				return
			}
			route = next
			sample = Sample{Domain: domain, Upstream: route.Name}
			upConn, err = s.dialTunnel(r.Context(), route, target, &sample)
			if err == nil {
				break
			}
			sample.Duration = time.Since(started)
			s.observe(sample)
		}
		connected = time.Now()
		// Ошибка записи всплывёт на следующем чтении как обрыв до ответа.
		_ = head.switchTo(upConn)
	}

	sample.TTFB = time.Since(connected)
	head.seal()
	total := int64(n)
	activity.Store(time.Now().UnixNano())
	stopIdle := watchIdle(s.idleTimeout(), &activity, func() {
		upConn.Close()
		clientConn.Close()
	})
	if _, err := clientConn.Write(buf[:n]); err == nil {
		for {
			n, err := upConn.Read(buf)
			if n > 0 {
				total += int64(n)
				activity.Store(time.Now().UnixNano())
				if _, werr := clientConn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}
	closeWrite(clientConn)
	<-pumpDone
	stopIdle()

	sample.Bytes = total
	sample.Duration = time.Since(started)
	s.observe(sample)
}

// dialTunnel открывает соединение с целью через маршрут и записывает в
// замер время подключения, а при неудаче — ошибку.
func (s *Server) dialTunnel(ctx context.Context, route *Route, target string, sample *Sample) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	defer cancel()
	dialStart := time.Now()
	conn, err := route.Upstream.DialTarget(ctx, target)
	sample.Connect = time.Since(dialStart)
	if err != nil {
		sample.Err = err
	}
	return conn, err
}

// nextRoute сдаёт маршрут, через который запрос не прошёл, и берёт другой,
// минуя все провалившиеся. Ошибка — попытки исчерпаны или брать некого;
// в этом случае возвращается прежний маршрут, чтобы вызывающему было что
// освобождать (повторное освобождение безвредно).
func (s *Server) nextRoute(domain string, failed *Route, avoid *[]string) (*Route, error) {
	*avoid = append(*avoid, failed.Name)
	failed.release()
	if len(*avoid) >= maxAttempts {
		return failed, i18n.Errorf("%d upstreams tried", len(*avoid))
	}
	next, err := s.Pick(domain, *avoid)
	if err != nil {
		return failed, err
	}
	return next, nil
}

// handleHTTP обслуживает обычный HTTP. Через http-апстрим запрос уходит
// в absolute-form (так работает любой HTTP-прокси), через socks5 и direct —
// в origin-form по прямому соединению с целью.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, i18n.T("this is a proxy server: an absolute-form request is expected"), http.StatusBadRequest)
		return
	}
	domain := hostOnly(r.Host)
	started := time.Now()

	route, err := s.Pick(domain, nil)
	if err != nil {
		http.Error(w, i18n.T("no upstream available: ")+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func() { route.release() }()

	// Запрос без тела повторяется через другой прокси, если через этот не
	// пришло ответа: заголовки повторить нетрудно, а ответа не было, так
	// что двойного выполнения GET не случится. Так же поступает
	// http.Transport при обрыве keep-alive. С телом — нет: оно уже могло
	// уйти по частям, и собрать его заново не из чего.
	var (
		avoid  []string
		sample Sample
		resp   *http.Response
	)
	for {
		sample = Sample{Domain: domain, Upstream: route.Name}
		resp, err = s.forwardHTTP(route, r, &sample)
		if err == nil {
			break
		}
		sample.Duration = time.Since(started)
		s.observe(sample)
		if r.Body != http.NoBody {
			http.Error(w, i18n.T("upstream unavailable: ")+err.Error(), http.StatusBadGateway)
			return
		}
		var next *Route
		next, err = s.nextRoute(domain, route, &avoid)
		if err != nil {
			http.Error(w, i18n.T("upstream unavailable: ")+sample.Err.Error(), http.StatusBadGateway)
			return
		}
		route = next
	}
	defer resp.Body.Close()
	sample.Status = resp.StatusCode

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

// forwardHTTP отправляет запрос через пул keep-alive соединений апстрима и
// снимает замер трассировкой: она одна знает, было ли соединение
// установлено заново или взято из пула, и когда пришёл первый байт ответа.
func (s *Server) forwardHTTP(route *Route, r *http.Request, sample *Sample) (*http.Response, error) {
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
	sample.Reused = reused
	if !reused && !dialStart.IsZero() {
		end := gotConn
		if end.IsZero() {
			end = time.Now()
		}
		sample.Connect = end.Sub(dialStart)
	}
	if err != nil {
		sample.Err = err
		return nil, err
	}
	if !firstByte.IsZero() && !gotConn.IsZero() {
		sample.TTFB = firstByte.Sub(gotConn)
	}
	return resp, nil
}

func (s *Server) dialTimeout() time.Duration {
	if s.DialTimeout > 0 {
		return s.DialTimeout
	}
	return defaultDialTimeout
}

func (s *Server) idleTimeout() time.Duration {
	switch {
	case s.IdleTimeout > 0:
		return s.IdleTimeout
	case s.IdleTimeout < 0:
		return 0
	}
	return DefaultIdleTimeout
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
