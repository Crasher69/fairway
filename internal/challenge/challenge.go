// Package challenge распознаёт страницы проверки — капчи и антибот-заслоны.
//
// Сайт под защитой Cloudflare, DataDome или Яндекса отвечает прокси не 403,
// а 200 (или 503) с HTML-страницей «Проверяем, что вы не робот». Для рейтинга
// это худший случай: запрос выглядит успешным, а пользователь получил
// заглушку. Пакет смотрит на статус, заголовки и начало тела и говорит,
// какой именно заслон встретился, — по этому признаку прокси банится для
// домена так же, как по 403.
//
// Ложное срабатывание здесь дороже пропуска: оно выключает живой прокси.
// Поэтому маркеры делятся на сильные (встречаются только на самих
// страницах проверки) и слабые (виджет reCAPTCHA стоит и на обычной форме
// логина) — слабые засчитываются только вместе с признаками заслона:
// статусом отказа или характерным заголовком страницы.
package challenge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
)

// PrefixSize — сколько байт тела достаточно прочитать: все маркеры стоят
// в <head> или в самом начале <body>, а страницы проверки маленькие.
const PrefixSize = 64 << 10

// Detect возвращает имя заслона («cloudflare», «datadome», …) или пустую
// строку. body — начало тела уже без сжатия (см. Decode).
func Detect(status int, header http.Header, body []byte) string {
	// Cloudflare честно помечает свои страницы проверки заголовком.
	if strings.EqualFold(header.Get("Cf-Mitigated"), "challenge") {
		return "cloudflare"
	}
	// Яндекс и некоторые другие не рисуют капчу сразу, а уводят на неё
	// редиректом — тело смотреть бессмысленно, всё в Location.
	if status >= 300 && status < 400 {
		loc := strings.ToLower(header.Get("Location"))
		switch {
		case strings.Contains(loc, "showcaptcha"):
			return "yandex"
		case strings.Contains(loc, "captcha-delivery.com"):
			return "datadome"
		case strings.Contains(loc, "/captcha"):
			return "captcha"
		}
		return ""
	}
	if !looksLikeHTML(header, body) {
		return ""
	}

	text := strings.ToLower(string(body))
	for _, m := range strongMarkers {
		if strings.Contains(text, m.needle) {
			return m.vendor
		}
	}

	// Слабые маркеры: сам по себе виджет капчи — не заслон.
	suspicious := status == http.StatusForbidden || status == http.StatusTooManyRequests ||
		status == http.StatusServiceUnavailable || titleSuggestsChallenge(text)
	if !suspicious {
		return ""
	}
	for _, m := range weakMarkers {
		if strings.Contains(text, m.needle) {
			return m.vendor
		}
	}
	return ""
}

type marker struct{ needle, vendor string }

// strongMarkers встречаются только на страницах проверки. Все в нижнем
// регистре: тело приводится к нему перед поиском.
var strongMarkers = []marker{
	{"_cf_chl_opt", "cloudflare"},
	{"challenge-platform", "cloudflare"},
	{"cf-chl-", "cloudflare"},
	{"<title>just a moment...</title>", "cloudflare"},
	{"attention required! | cloudflare", "cloudflare"},
	{"captcha-delivery.com", "datadome"},
	{"dd.js", "datadome"}, // <script src="…/dd.js"> ставит только DataDome
	{"_incapsula_resource", "imperva"},
	{"px-captcha", "perimeterx"},
	{"_pxhc", "perimeterx"},
	{"distil_r_captcha", "distil"},
	{"pardon our interruption", "distil"},
	{"smartcaptcha.yandexcloud.net", "yandex"},
	{"/showcaptcha", "yandex"},
	{"/checkcaptcha", "yandex"},
	{"awswaf-captcha", "aws-waf"},
	{"aws-waf-token", "aws-waf"},
	{"kasada", "kasada"},
	{"ak-challenge", "akamai"},
}

// weakMarkers — виджеты капчи, которые стоят и на обычных формах.
var weakMarkers = []marker{
	{"g-recaptcha", "recaptcha"},
	{"recaptcha/api.js", "recaptcha"},
	{"h-captcha", "hcaptcha"},
	{"hcaptcha.com", "hcaptcha"},
	{"cf-turnstile", "turnstile"},
	{"challenges.cloudflare.com/turnstile", "turnstile"},
}

// titleSuggestsChallenge смотрит на <title>: у страниц проверки он говорящий.
func titleSuggestsChallenge(text string) bool {
	start := strings.Index(text, "<title")
	if start < 0 {
		return false
	}
	end := strings.Index(text[start:], "</title>")
	if end < 0 {
		return false
	}
	title := text[start : start+end]
	for _, word := range []string{
		"captcha", "verify you are human", "are you a robot", "access denied",
		"security check", "bot detection", "проверка", "капча", "не робот",
		"доступ ограничен", "подтвердите",
	} {
		if strings.Contains(title, word) {
			return true
		}
	}
	return false
}

// looksLikeHTML отсекает JSON, картинки и прочее, где искать маркеры нечего.
func looksLikeHTML(header http.Header, body []byte) bool {
	ct := strings.ToLower(header.Get("Content-Type"))
	if ct != "" {
		return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
	}
	head := bytes.TrimSpace(body)
	if len(head) > 512 {
		head = head[:512]
	}
	return bytes.Contains(bytes.ToLower(head), []byte("<html")) || bytes.HasPrefix(head, []byte("<!"))
}

// Decode снимает сжатие с начала тела. Кусок может быть обрезан посреди
// потока — тогда берём столько, сколько распаковалось: маркеры стоят в
// начале, и полный поток не нужен. Незнакомое сжатие (brotli, zstd)
// возвращает nil: в него не заглянуть без сторонних библиотек, поэтому
// прокси заранее не даёт клиенту его запросить (см. forward.AcceptEncoding).
func Decode(encoding string, prefix []byte) []byte {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return prefix
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(prefix))
		if err != nil {
			return nil
		}
		zr.Multistream(false)
		r = zr
	case "deflate":
		// По RFC deflate — это zlib-обёртка, но часть серверов шлёт голый
		// flate. Пробуем обёртку, при неудаче — голый поток.
		if zr, err := zlib.NewReader(bytes.NewReader(prefix)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(prefix))
		}
	default:
		return nil
	}
	out, _ := io.ReadAll(io.LimitReader(r, PrefixSize))
	return out
}

// AcceptEncoding оставляет в Accept-Encoding только то, что мы умеем
// распаковать. Иначе браузер попросит brotli, сайт ответит им, и в тело
// заслона будет не заглянуть. Пустой список означает «заголовка не было».
func AcceptEncoding(values []string) string {
	if len(values) == 0 {
		return ""
	}
	kept := make([]string, 0, 3)
	for _, v := range values {
		for _, token := range strings.Split(v, ",") {
			name := strings.ToLower(strings.TrimSpace(strings.SplitN(token, ";", 2)[0]))
			switch name {
			case "gzip", "deflate", "identity":
				kept = append(kept, name)
			}
		}
	}
	if len(kept) == 0 {
		// Клиент просил только то, чего мы не понимаем. gzip умеют все.
		return "gzip, deflate"
	}
	return strings.Join(kept, ", ")
}
