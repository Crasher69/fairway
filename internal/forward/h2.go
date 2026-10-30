package forward

import (
	"context"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// h2Transport — настройки HTTP/2 до сайта. Нужен только ради профилей
// TLS-отпечатка: браузер объявляет h2 в ALPN, и сайт, выбравший h2, ждёт
// HTTP/2. Сам пул транспорта не используется — соединения заводит
// mitmUpstream, по одному на туннель.
//
// Размеры таблиц как у Chrome: SETTINGS тоже входят в отпечаток (Akamai).
var h2Transport = &http2.Transport{
	DisableCompression:        true,
	MaxDecoderHeaderTableSize: 65536,
	MaxHeaderListSize:         262144,
}

// newH2Conn поднимает HTTP/2 поверх уже согласованного TLS-соединения.
func newH2Conn(conn net.Conn) (*http2.ClientConn, error) {
	return h2Transport.NewClientConn(conn)
}

// exchangeH2 — exchange для сайта, выбравшего HTTP/2. Ответ приводится к
// HTTP/1.1: клиенту он уходит по расшифрованному HTTP/1.1-соединению.
//
// Как и в exchange, на заголовки ответа отводится wait, и срок
// откладывается, пока уходит тело запроса. received — пришли ли заголовки:
// по HTTP/2 сайт шлёт служебные кадры и до ответа, так что «хоть один
// байт» здесь ничего не говорит.
func exchangeH2(cc *http2.ClientConn, req *http.Request, wait time.Duration) (resp *http.Response, ttfb time.Duration, first time.Time, received bool, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	var dog *watchdog
	if wait > 0 {
		dog = newWatchdog(wait, cancel)
		if req.Body != nil && req.Body != http.NoBody {
			req.Body = &kickReader{ReadCloser: req.Body, kick: dog.kick}
		}
	}
	sent := time.Now()
	resp, err = cc.RoundTrip(req.WithContext(ctx))
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
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	// В HTTP/2 длина тела бывает неизвестна, а HTTP/1.1 без длины умеет
	// только «до закрытия соединения». Чанки сохраняют keep-alive с клиентом.
	if resp.ContentLength < 0 && bodyAllowed(req, resp.StatusCode) {
		resp.TransferEncoding = []string{"chunked"}
	}
	return resp, ttfb, first, true, nil
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
