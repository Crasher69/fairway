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

	utls "github.com/refraction-networking/utls"

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
}

func chromeHints(brands string) map[string]string {
	return map[string]string{
		"Sec-Ch-Ua":          brands,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": `"Windows"`,
	}
}

var profiles = map[string]*Profile{
	"chrome_133": {
		hello:       utls.HelloChrome_133,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		ClientHints: chromeHints(`"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`),
	},
	"chrome_131": {
		hello:       utls.HelloChrome_131,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		ClientHints: chromeHints(`"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`),
	},
	"chrome_120": {
		hello:       utls.HelloChrome_120,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		ClientHints: chromeHints(`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`),
	},
	"firefox_120": {
		hello:     utls.HelloFirefox_120,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	},
	"safari_16": {
		hello:     utls.HelloSafari_16_0,
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
	},
	"ios_14": {
		hello:     utls.HelloIOS_14,
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
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
	conn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		return nil, "", i18n.Errorf("fingerprint %s: %w", p.Name, err)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}
