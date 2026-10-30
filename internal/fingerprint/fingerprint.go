// Package fingerprint — TLS-отпечатки браузеров для соединения с сайтом в
// режиме MITM.
//
// Расшифровав трафик, соединение до сайта fairway поднимает сам, и без
// подмены сайт видит ClientHello Go-клиента. Анти-боты, которые смотрят на
// JA3/JA4, такой трафик режут, даже если запрос прислал настоящий браузер.
// Профиль заставляет рукопожатие выглядеть как у выбранного браузера, а
// заголовки User-Agent и sec-ch-ua — подставляются под тот же браузер.
package fingerprint

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sort"
	"strings"

	utls "github.com/bogdanfinn/utls"

	"fairway/internal/i18n"
)

// Profile — браузер, за который выдаёт себя соединение до сайта.
type Profile struct {
	Name  string
	hello utls.ClientHelloID
	// UserAgent — UA ровно той версии, чей ClientHello воспроизводится.
	UserAgent string
	// ClientHints — sec-ch-ua*, которые шлют Chromium-браузеры. У Firefox
	// и Safari их нет, и отсутствие — тоже часть отпечатка.
	ClientHints map[string]string
	// H2 — как браузер начинает HTTP/2-соединение. Это отдельный отпечаток
	// (Akamai), и Cloudflare с Akamai сверяют его с TLS-отпечатком.
	H2 H2
}

// H2 — параметры HTTP/2 браузера: всё, из чего складывается отпечаток
// Akamai, плюс порядок обычных заголовков.
type H2 struct {
	// Settings — кадр SETTINGS ровно в браузерном порядке: пары id, значение.
	Settings [][2]uint32
	// ConnectionFlow — WINDOW_UPDATE на всё соединение сразу после SETTINGS.
	ConnectionFlow uint32
	// PseudoHeaderOrder — порядок :method, :authority, :scheme, :path.
	PseudoHeaderOrder []string
	// HeaderPriority — приоритет в HEADERS; nil — как у Chrome
	// (exclusive, вес 256, от корня).
	HeaderPriority *Priority
	// Priorities — кадры PRIORITY до первого запроса (старый Firefox
	// строит из них дерево). FirstStreamID — с какого потока начинать.
	Priorities    []StreamPriority
	FirstStreamID uint32
	// HeaderOrder — порядок заголовков в нижнем регистре; не названные
	// идут следом по алфавиту.
	HeaderOrder []string
}

// Priority — поля приоритета HTTP/2; Weight — вес минус один, как в кадре.
type Priority struct {
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// StreamPriority — один кадр PRIORITY.
type StreamPriority struct {
	StreamID uint32
	Priority
}

// Идентификаторы SETTINGS из RFC 9113.
const (
	settingHeaderTableSize      = 0x1
	settingEnablePush           = 0x2
	settingMaxConcurrentStreams = 0x3
	settingInitialWindowSize    = 0x4
	settingMaxFrameSize         = 0x5
	settingMaxHeaderListSize    = 0x6
)

func chromeHints(brands string) map[string]string {
	return map[string]string{
		"Sec-Ch-Ua":          brands,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": `"Windows"`,
	}
}

// Значения HTTP/2 сняты с браузеров (tls.peet.ws, профили tls-client).
var (
	chromeH2 = H2{
		Settings: [][2]uint32{
			{settingHeaderTableSize, 65536},
			{settingEnablePush, 0},
			{settingInitialWindowSize, 6291456},
			{settingMaxHeaderListSize, 262144},
		},
		ConnectionFlow:    15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		HeaderOrder: []string{
			"cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "content-type", "accept",
			"origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
			"sec-fetch-dest", "referer", "accept-encoding", "accept-language",
			"cookie", "priority",
		},
	}
	firefoxH2 = H2{
		Settings: [][2]uint32{
			{settingHeaderTableSize, 65536},
			{settingInitialWindowSize, 131072},
			{settingMaxFrameSize, 16384},
		},
		ConnectionFlow:    12517377,
		PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		HeaderPriority:    &Priority{StreamDep: 13, Weight: 41},
		Priorities: []StreamPriority{
			{3, Priority{Weight: 200}},
			{5, Priority{Weight: 100}},
			{7, Priority{Weight: 0}},
			{9, Priority{StreamDep: 7, Weight: 0}},
			{11, Priority{StreamDep: 3, Weight: 0}},
			{13, Priority{Weight: 240}},
		},
		FirstStreamID: 15,
		HeaderOrder: []string{
			"user-agent", "accept", "accept-language", "accept-encoding",
			"content-type", "content-length", "origin", "referer", "cookie",
			"upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
			"sec-fetch-site", "sec-fetch-user", "priority", "te",
		},
	}
	safariHeaderOrder = []string{
		"content-type", "accept", "sec-fetch-site", "origin", "cookie",
		"sec-fetch-dest", "accept-language", "sec-fetch-mode", "user-agent",
		"referer", "accept-encoding", "priority",
	}
	safariH2 = H2{
		Settings: [][2]uint32{
			{settingInitialWindowSize, 4194304},
			{settingMaxConcurrentStreams, 100},
		},
		ConnectionFlow:    10485760,
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		HeaderOrder:       safariHeaderOrder,
	}
	iosH2 = H2{
		Settings: [][2]uint32{
			{settingInitialWindowSize, 2097152},
			{settingMaxConcurrentStreams, 100},
		},
		ConnectionFlow:    10485760,
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		HeaderOrder:       safariHeaderOrder,
	}
)

var profiles = map[string]*Profile{
	"chrome_133": {
		hello:       utls.HelloChrome_133,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		ClientHints: chromeHints(`"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`),
		H2:          chromeH2,
	},
	"chrome_131": {
		hello:       utls.HelloChrome_131,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		ClientHints: chromeHints(`"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`),
		H2:          chromeH2,
	},
	"chrome_120": {
		hello:       utls.HelloChrome_120,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		ClientHints: chromeHints(`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`),
		H2:          chromeH2,
	},
	"firefox_120": {
		hello:     utls.HelloFirefox_120,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		H2:        firefoxH2,
	},
	"safari_16": {
		hello:     utls.HelloSafari_16_0,
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
		H2:        safariH2,
	},
	"ios_14": {
		hello:     utls.HelloIOS_14,
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
		H2:        iosH2,
	},
}

func init() {
	for name, p := range profiles {
		p.Name = name
	}
}

// Lookup находит профиль по имени. Пустое имя — подмены нет.
func Lookup(name string) (*Profile, bool) {
	p, ok := profiles[name]
	return p, ok
}

// Names — имена всех профилей по алфавиту: для панели и сообщений об ошибке.
func Names() []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// UserAgent — режимы подстановки User-Agent в правиле домена.
const (
	// UAKeep — заголовки клиента не трогаются (пустое значение в конфиге).
	UAKeep = ""
	// UAProfile — User-Agent и client hints берутся из профиля.
	UAProfile = "profile"
)

// ApplyHeaders подставляет заголовки браузера под режим ua: "" — оставить
// клиентские, "profile" — из профиля, любая другая строка — свой UA.
// Client hints при этом приводятся к профилю: Chrome-хинты рядом с
// UA Firefox выдают подмену не хуже, чем отпечаток Go.
func (p *Profile) ApplyHeaders(h http.Header, ua string) {
	if ua == UAKeep {
		return
	}
	if ua == UAProfile {
		ua = p.UserAgent
	}
	h.Set("User-Agent", ua)
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Sec-Ch-") {
			delete(h, name)
		}
	}
	for name, value := range p.ClientHints {
		h.Set(name, value)
	}
}

// Client проводит TLS-рукопожатие с ClientHello профиля. Проверка
// сертификата берётся из base: RootCAs, InsecureSkipVerify, ServerName.
// h1only оставляет в ALPN только http/1.1 — так браузеры открывают
// WebSocket; иначе ALPN как у браузера, и сервер обычно выбирает h2.
// Возвращает соединение и согласованный протокол.
func (p *Profile) Client(ctx context.Context, raw net.Conn, base *tls.Config, h1only bool) (net.Conn, string, error) {
	cfg := &utls.Config{
		ServerName:         base.ServerName,
		RootCAs:            base.RootCAs,
		InsecureSkipVerify: base.InsecureSkipVerify,
	}
	spec, err := utls.UTLSIdToSpec(p.hello)
	if err != nil {
		return nil, "", i18n.Errorf("fingerprint %s: %w", p.Name, err)
	}
	if h1only {
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
	}
	conn := utls.UClient(raw, cfg, utls.HelloCustom, false, false, false)
	if err := conn.ApplyPreset(&spec); err != nil {
		return nil, "", i18n.Errorf("fingerprint %s: %w", p.Name, err)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}
