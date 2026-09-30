// Package forward — ядро прокси: приём клиентских запросов, прокладка их
// через выбранный апстрим и замер качества соединения.
package forward

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	// «нет живого прокси» — клиент получит 503. avoid — ключи маршрутов
	// (ID, а без него имя), через которые этот запрос уже не прошёл; брать
	// их снова нельзя.
	Pick func(domain string, avoid []string) (*Route, error)
	// Authorize решает, пускать ли клиента, по его логину и паролю из
	// Proxy-Authorization (ok — заголовок был и разобрался). nil — пускать
	// всех: прокси открыт, это поведение по умолчанию.
	Authorize func(login, password string, ok bool) bool
	// Observe вызывается по завершении каждого запроса. Может быть nil.
	Observe func(Sample)
	// Issuer выпускает сертификаты для расшифровки TLS. Без него правило
	// mitm: true не действует — соединение просто туннелируется.
	Issuer CertIssuer
	// OriginTLS — шаблон настроек TLS для соединения с целью в режиме MITM.
	// Обычно nil: сертификат цели проверяется по системным корням.
	OriginTLS *tls.Config
	// DialTimeout ограничивает установку соединения с целью через апстрим,
	// когда в правиле домена таймаут не задан (см. Route.ConnectTimeout).
	DialTimeout time.Duration
	// ResponseTimeout — сколько ждать первого байта ответа цели, когда в
	// правиле домена таймаут не задан. 0 — DefaultResponseTimeout.
	ResponseTimeout time.Duration
	// ReplayBodyLimit — до какого размера тело запроса в режиме MITM
	// буферизуется в памяти, чтобы запрос можно было повторить, если цель
	// закрыла keep-alive соединение. 0 означает DefaultReplayBodyLimit,
	// отрицательное — не буферизовать (повторяются только запросы без тела).
	ReplayBodyLimit int64
	// IdleTimeout — сколько туннель может молчать в обе стороны, прежде
	// чем его закроют. 0 означает DefaultIdleTimeout, отрицательное —
	// без ограничения.
	IdleTimeout time.Duration
	// Hooks — обработка запросов плагинами. nil — без неё. Видны ей
	// только обычный HTTP и расшифрованный (MITM) HTTPS: в непрозрачном
	// туннеле запросов не разобрать.
	Hooks  Hooks
	Logger *log.Logger
}

// Hooks — то, что пропускает запросы и ответы через плагины. Ошибки
// плагинов остаются внутри: запрос идёт дальше без их правки.
type Hooks interface {
	// OnRequest может поменять запрос на месте. Ответ не nil — вместо
	// цели отвечает плагин, и запрос никуда не уходит. URL запроса полный.
	OnRequest(domain string, req *http.Request) *http.Response
	// OnResponse может поменять ответ на месте; req — ушедший запрос.
	OnResponse(domain string, req *http.Request, resp *http.Response)
}

const defaultDialTimeout = 15 * time.Second

// DefaultResponseTimeout — сколько ждать первого байта ответа, если ни
// правило, ни сервер не задали своё.
const DefaultResponseTimeout = 60 * time.Second

// DefaultReplayBodyLimit — 1 МиБ: покрывает формы, JSON и мелкие загрузки,
// а большой файл держать в памяти ради редкого повтора незачем.
const DefaultReplayBodyLimit = 1 << 20

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Authorize != nil && !s.Authorize(ProxyCredentials(r)) {
		// 407 с Proxy-Authenticate: браузер на это спросит логин и пароль
		// сам, а программа поймёт, что их не хватает.
		w.Header().Set("Proxy-Authenticate", `Basic realm="fairway", charset="UTF-8"`)
		http.Error(w, i18n.T("proxy authorization required"), http.StatusProxyAuthRequired)
		return
	}
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
			// Маршрут возвращается: MITM меняет апстрим при отказе, и
			// освободить надо тот, на котором туннель закончил работу.
			route = s.mitmTunnel(w, route, target)
			return
		}
	}

	var (
		avoid  []string
		upConn net.Conn
		sample Sample
	)
	for {
		sample = route.sample(domain)
		upConn, err = s.dialTunnel(r.Context(), route, target, &sample)
		if err == nil {
			break
		}
		sample.Duration = time.Since(started)
		if r.Context().Err() != nil {
			// Клиент не дождался подключения — прокси не виноват, и
			// отвечать уже некому.
			sample.ClientGone = true
			s.observe(sample)
			return
		}
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
	// через другой. Ждём столько же, сколько подключения: в туннеле
	// первым приходит ответ TLS-рукопожатия, а не страница, и долго
	// думающий сайт его не задерживает.
	buf := make([]byte, 32<<10)
	var n int
	for {
		_ = upConn.SetReadDeadline(time.Now().Add(s.connectTimeout(route)))
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
		sample.Err = tunnelError(rerr, s.connectTimeout(route))
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
			sample = route.sample(domain)
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
	ctx, cancel := context.WithTimeout(ctx, s.connectTimeout(route))
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
	*avoid = append(*avoid, failed.key())
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

	if s.Hooks != nil {
		if resp := s.Hooks.OnRequest(domain, r); resp != nil {
			writeHookResponse(w, resp)
			return
		}
	}

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
		sample = route.sample(domain)
		resp, err = s.forwardHTTP(route, r, &sample)
		if err == nil {
			break
		}
		sample.Duration = time.Since(started)
		if r.Context().Err() != nil {
			// Клиент ушёл, не дождавшись ответа: запрос отменён с нашей
			// стороны, прокси тут ни при чём.
			sample.ClientGone = true
			s.observe(sample)
			return
		}
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
	if s.Hooks != nil {
		s.Hooks.OnResponse(domain, r, resp)
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
	out := &clientWriter{w: w}
	if _, err := io.Copy(out, counted); err != nil && !errors.Is(err, io.EOF) {
		sample.Err = err
		// Ушедший клиент рвёт и запись к себе, и чтение от апстрима: запрос
		// к апстриму идёт в контексте клиентского и отменяется вместе с ним.
		sample.ClientGone = out.err != nil || r.Context().Err() != nil
	}
	sample.Bytes = counted.n
	sample.Duration = time.Since(started)
	s.observe(sample)
}

// writeHookResponse отдаёт клиенту ответ, который плагин дал вместо цели.
func writeHookResponse(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		w.Header()[k] = vv
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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
	// Таймаут ответа у каждого домена свой, а пул соединений один на
	// апстрим, поэтому ResponseHeaderTimeout транспорта не годится: ждём
	// заголовков сами и отменяем запрос, если их нет. Таймаут подключения
	// транспорт берёт из контекста.
	wait := s.responseTimeout(route)
	ctx, cancel := context.WithCancel(withConnectTimeout(r.Context(), s.connectTimeout(route)))
	timer := time.AfterFunc(wait, cancel)
	outReq := r.Clone(httptrace.WithClientTrace(ctx, trace))
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	resp, err := route.Upstream.Transport(s.dialTimeout()).RoundTrip(outReq)
	if !timer.Stop() && r.Context().Err() == nil {
		// Сработал таймер, а не ушёл клиент: ответа не дождались.
		if err == nil {
			resp.Body.Close()
		}
		err = i18n.Errorf("no reply from target within %s", wait)
	}
	if err != nil {
		cancel()
	} else {
		// Контекст запроса живёт, пока читается тело ответа.
		resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	}
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

// connectTimeout — таймаут подключения к цели через этот маршрут.
func (s *Server) connectTimeout(route *Route) time.Duration {
	if route != nil && route.ConnectTimeout > 0 {
		return route.ConnectTimeout
	}
	return s.dialTimeout()
}

// responseTimeout — сколько ждать первого байта ответа цели.
func (s *Server) responseTimeout(route *Route) time.Duration {
	switch {
	case route != nil && route.ResponseTimeout > 0:
		return route.ResponseTimeout
	case s.ResponseTimeout > 0:
		return s.ResponseTimeout
	}
	return DefaultResponseTimeout
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

// ProxyCredentials достаёт логин и пароль из Proxy-Authorization: Basic.
// У http.Request есть BasicAuth, но только для Authorization — заголовка
// цели, а не прокси.
func ProxyCredentials(r *http.Request) (login, password string, ok bool) {
	header := r.Header.Get("Proxy-Authorization")
	scheme, encoded, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	login, password, ok = strings.Cut(string(raw), ":")
	if !ok {
		return "", "", false
	}
	return login, password, true
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
