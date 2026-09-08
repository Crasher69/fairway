package forward

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Upstream — апстрим-прокси, через который уходит трафик.
// Поддерживаются http, https, socks5 и direct (без прокси, для отладки).
type Upstream struct {
	Name   string
	Scheme string // direct | http | https | socks5
	Addr   string // host:port самого прокси; пусто для direct
	User   string
	Pass   string

	// transport — пул keep-alive соединений для обычного HTTP. Создаётся
	// при первом запросе и живёт вместе с апстримом.
	transportOnce sync.Once
	transport     *http.Transport
}

// Transport отдаёт пул соединений для обычных HTTP-запросов через этот
// апстрим. Один на апстрим: соединения к http-прокси переиспользуются между
// всеми целями, к socks5 и direct — по адресу цели, как в любом браузере.
//
// Раньше на каждый запрос открывалось новое соединение с Connection: close,
// и обычный HTTP работал в 14 раз медленнее туннелей (см. docs/BENCHMARK.md).
func (u *Upstream) Transport(dialTimeout time.Duration) *http.Transport {
	u.transportOnce.Do(func() {
		dialer := &net.Dialer{Timeout: dialTimeout}
		tr := &http.Transport{
			// Сжатие и разжатие — дело клиента и сайта, прокси передаёт как есть.
			DisableCompression:    true,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   dialTimeout,
			ExpectContinueTimeout: time.Second,
			// HTTP/2 к цели не разбираем — замеры считаются по HTTP/1.1.
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		}
		switch u.Scheme {
		case "http", "https":
			// Transport сам шлёт absolute-form и Proxy-Authorization,
			// а к https-прокси поднимает TLS.
			proxyURL := &url.URL{Scheme: u.Scheme, Host: u.Addr}
			if u.User != "" || u.Pass != "" {
				proxyURL.User = url.UserPassword(u.User, u.Pass)
			}
			tr.Proxy = http.ProxyURL(proxyURL)
			tr.DialContext = dialer.DialContext
		default:
			// socks5 и direct: соединение до цели прокладываем сами.
			tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(ctx, dialTimeout)
				defer cancel()
				return u.DialTarget(ctx, addr)
			}
		}
		u.transport = tr
	})
	return u.transport
}

// CloseIdle закрывает простаивающие соединения пула. Вызывается, когда
// апстрим выбывает из конфига: иначе его соединения жили бы до таймаута.
func (u *Upstream) CloseIdle() {
	if u.transport != nil {
		u.transport.CloseIdleConnections()
	}
}

var defaultPorts = map[string]string{"http": "80", "https": "443", "socks5": "1080"}

// ParseUpstream разбирает строку вида scheme://user:pass@host:port.
// Схему можно опустить — тогда подразумевается http. Строка "direct"
// означает прямое соединение без апстрима.
func ParseUpstream(raw string) (*Upstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "direct" {
		return &Upstream{Name: "direct", Scheme: "direct"}, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("апстрим %q: %w", raw, err)
	}

	scheme := u.Scheme
	if scheme == "socks5h" {
		scheme = "socks5"
	}
	if _, ok := defaultPorts[scheme]; !ok {
		return nil, fmt.Errorf("апстрим %q: неподдерживаемая схема %q", raw, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("апстрим %q: не указан хост", raw)
	}

	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), defaultPorts[scheme])
	}

	up := &Upstream{Scheme: scheme, Addr: addr}
	if u.User != nil {
		up.User = u.User.Username()
		up.Pass, _ = u.User.Password()
	}
	up.Name = scheme + "://" + addr // без кредов — имя попадёт в логи и метрики
	return up, nil
}

// IsHTTPProxy сообщает, умеет ли апстрим принимать запросы в absolute-form.
// Для обычного HTTP это дешевле, чем гонять CONNECT-туннель.
func (u *Upstream) IsHTTPProxy() bool {
	return u.Scheme == "http" || u.Scheme == "https"
}

// ProxyAuthorization возвращает значение заголовка Proxy-Authorization
// или пустую строку, если апстрим без авторизации.
func (u *Upstream) ProxyAuthorization() string {
	if u.User == "" && u.Pass == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User+":"+u.Pass))
}

// DialProxy устанавливает соединение с самим прокси-сервером.
// Для схемы https поверх TCP поднимается TLS.
func (u *Upstream) DialProxy(ctx context.Context) (net.Conn, error) {
	if u.Scheme == "direct" {
		return nil, errors.New("direct: нет прокси, к которому подключаться")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", u.Addr)
	if err != nil {
		return nil, fmt.Errorf("подключение к прокси %s: %w", u.Addr, err)
	}
	if u.Scheme == "https" {
		host, _, _ := net.SplitHostPort(u.Addr)
		tlsConn := tlsClient(conn, host)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS к прокси %s: %w", u.Addr, err)
		}
		return tlsConn, nil
	}
	return conn, nil
}

// DialTarget возвращает соединение до target (host:port), проложенное
// через апстрим: CONNECT для http/https, handshake для socks5.
func (u *Upstream) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	switch u.Scheme {
	case "direct":
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)

	case "socks5":
		var auth *proxy.Auth
		if u.User != "" || u.Pass != "" {
			auth = &proxy.Auth{User: u.User, Password: u.Pass}
		}
		d, err := proxy.SOCKS5("tcp", u.Addr, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("socks5 %s: %w", u.Addr, err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 %s: диалер не поддерживает контекст", u.Addr)
		}
		return cd.DialContext(ctx, "tcp", target)

	case "http", "https":
		conn, err := u.DialProxy(ctx)
		if err != nil {
			return nil, err
		}
		tunneled, err := u.connectTunnel(ctx, conn, target)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return tunneled, nil
	}
	return nil, fmt.Errorf("неизвестная схема апстрима %q", u.Scheme)
}

// connectTunnel проводит CONNECT-рукопожатие с HTTP-прокси.
func (u *Upstream) connectTunnel(ctx context.Context, conn net.Conn, target string) (net.Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if auth := u.ProxyAuthorization(); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("CONNECT %s через %s: %w", target, u.Name, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("ответ на CONNECT %s через %s: %w", target, u.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CONNECT %s через %s: апстрим ответил %s", target, u.Name, resp.Status)
	}

	// Апстрим мог прислать байты туннеля в том же чтении — их нельзя потерять.
	if n := br.Buffered(); n > 0 {
		head, _ := br.Peek(n)
		return &bufferedConn{Conn: conn, head: head}, nil
	}
	return conn, nil
}

// bufferedConn отдаёт сначала уже вычитанный из сокета хвост, потом само соединение.
type bufferedConn struct {
	net.Conn
	head []byte
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(b, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
