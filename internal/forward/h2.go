package forward

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttp2 "github.com/bogdanfinn/fhttp/http2"

	"fairway/internal/fingerprint"
)

// HTTP/2 до сайта нужен только ради профилей TLS-отпечатка: браузер
// объявляет h2 в ALPN, и сайт, выбравший h2, ждёт HTTP/2. Клиент — fhttp, а
// не x/net/http2: у того SETTINGS, окно соединения и порядок псевдозаголовков
// зашиты, и по ним (отпечаток Akamai) Go видно так же, как по ClientHello.

var (
	h2TransportsMu sync.Mutex
	h2Transports   = map[*fingerprint.Profile]*fhttp2.Transport{}
)

// h2Transport — настройки HTTP/2 под профиль. Пул транспорта не
// используется: соединения заводит mitmUpstream, по одному на туннель.
func h2Transport(p *fingerprint.Profile) *fhttp2.Transport {
	h2TransportsMu.Lock()
	defer h2TransportsMu.Unlock()
	if t, ok := h2Transports[p]; ok {
		return t
	}
	t := &fhttp2.Transport{
		DisableCompression: true,
		Settings:           map[fhttp2.SettingID]uint32{},
		ConnectionFlow:     p.H2.ConnectionFlow,
		PseudoHeaderOrder:  p.H2.PseudoHeaderOrder,
		InitialStreamID:    p.H2.FirstStreamID,
	}
	for _, s := range p.H2.Settings {
		id := fhttp2.SettingID(s[0])
		t.Settings[id] = s[1]
		t.SettingsOrder = append(t.SettingsOrder, id)
	}
	if hp := p.H2.HeaderPriority; hp != nil {
		t.HeaderPriority = &fhttp2.PriorityParam{StreamDep: hp.StreamDep, Exclusive: hp.Exclusive, Weight: hp.Weight}
	}
	for _, sp := range p.H2.Priorities {
		t.Priorities = append(t.Priorities, fhttp2.Priority{
			StreamID:      sp.StreamID,
			PriorityParam: fhttp2.PriorityParam{StreamDep: sp.StreamDep, Exclusive: sp.Exclusive, Weight: sp.Weight},
		})
	}
	h2Transports[p] = t
	return t
}

// h2Conn — HTTP/2-соединение с сайтом и профиль, под который оно говорит.
type h2Conn struct {
	cc      *fhttp2.ClientConn
	profile *fingerprint.Profile
}

// newH2Conn поднимает HTTP/2 поверх уже согласованного TLS-соединения.
func newH2Conn(conn net.Conn, p *fingerprint.Profile) (*h2Conn, error) {
	cc, err := h2Transport(p).NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	return &h2Conn{cc: cc, profile: p}, nil
}

func (c *h2Conn) CanTakeNewRequest() bool { return c.cc.CanTakeNewRequest() }
func (c *h2Conn) Close() error            { return c.cc.Close() }

// exchangeH2 — exchange для сайта, выбравшего HTTP/2. Ответ приводится к
// HTTP/1.1: клиенту он уходит по расшифрованному HTTP/1.1-соединению.
//
// Как и в exchange, на заголовки ответа отводится wait, и срок
// откладывается, пока уходит тело запроса. received — пришли ли заголовки:
// по HTTP/2 сайт шлёт служебные кадры и до ответа, так что «хоть один
// байт» здесь ничего не говорит.
func exchangeH2(c *h2Conn, req *http.Request, wait time.Duration) (resp *http.Response, ttfb time.Duration, first time.Time, received bool, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	var dog *watchdog
	if wait > 0 {
		dog = newWatchdog(wait, cancel)
		if req.Body != nil && req.Body != http.NoBody {
			req.Body = &kickReader{ReadCloser: req.Body, kick: dog.kick}
		}
	}
	sent := time.Now()
	fresp, err := c.cc.RoundTrip(toFHTTP(req, c.profile).WithContext(ctx))
	fired := dog != nil && dog.stop()
	if err != nil {
		cancel()
		if fired {
			err = &replyTimeout{wait: wait}
		}
		return nil, 0, time.Time{}, false, err
	}
	first = time.Now()
	ttfb = first.Sub(sent)
	resp = fromFHTTP(fresp, req)
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	// В HTTP/2 длина тела бывает неизвестна, а HTTP/1.1 без длины умеет
	// только «до закрытия соединения». Чанки сохраняют keep-alive с клиентом.
	if resp.ContentLength < 0 && bodyAllowed(req, resp.StatusCode) {
		resp.TransferEncoding = []string{"chunked"}
	}
	return resp, ttfb, first, true, nil
}

// toFHTTP переводит запрос в тип fhttp и задаёт браузерный порядок
// заголовков: обычный net/http его теряет, а он тоже часть отпечатка.
func toFHTTP(req *http.Request, p *fingerprint.Profile) *fhttp.Request {
	header := make(fhttp.Header, len(req.Header)+1)
	for k, v := range req.Header {
		header[k] = v
	}
	if len(p.H2.HeaderOrder) > 0 {
		header[fhttp.HeaderOrderKey] = p.H2.HeaderOrder
	}
	body := req.Body
	if body == http.NoBody {
		body = nil
	}
	return &fhttp.Request{
		Method:        req.Method,
		URL:           req.URL,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		Header:        header,
		Body:          body,
		ContentLength: req.ContentLength,
		Host:          req.Host,
	}
}

// fromFHTTP — ответ fhttp в виде net/http, уже как HTTP/1.1. Трейлеры
// разделяют карту с исходным ответом: fhttp заполняет её, дочитав тело.
func fromFHTTP(r *fhttp.Response, req *http.Request) *http.Response {
	return &http.Response{
		Status:        r.Status,
		StatusCode:    r.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header(r.Header),
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Trailer:       http.Header(r.Trailer),
		Request:       req,
	}
}

// bodyAllowed — может ли у ответа быть тело (RFC 9110, 6.4.1).
func bodyAllowed(req *http.Request, status int) bool {
	switch {
	case req.Method == http.MethodHead:
		return false
	case status >= 100 && status < 200, status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}
	return true
}
