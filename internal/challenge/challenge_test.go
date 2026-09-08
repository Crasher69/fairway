package challenge

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"testing"
)

func html(title, body string) []byte {
	return []byte("<!DOCTYPE html><html><head><title>" + title + "</title></head><body>" + body + "</body></html>")
}

func TestDetect(t *testing.T) {
	htmlHeader := http.Header{"Content-Type": {"text/html; charset=utf-8"}}
	cases := []struct {
		name   string
		status int
		header http.Header
		body   []byte
		want   string
	}{
		{"обычная страница", 200, htmlHeader, html("Магазин", "<p>Товары</p>"), ""},
		{"cloudflare по заголовку", 403, http.Header{"Cf-Mitigated": {"challenge"}}, nil, "cloudflare"},
		{"cloudflare по телу со статусом 200", 200, htmlHeader,
			html("Just a moment...", `<script>window._cf_chl_opt={cvId:"3"}</script>`), "cloudflare"},
		{"datadome", 403, htmlHeader,
			html("Доступ", `<script src="https://ct.captcha-delivery.com/c.js"></script>`), "datadome"},
		{"яндекс редирект", 302, http.Header{"Location": {"https://ya.ru/showcaptcha?cc=1"}}, nil, "yandex"},
		{"perimeterx", 403, htmlHeader, html("Access to this page has been denied", `<div id="px-captcha"></div>`), "perimeterx"},
		// Виджет на форме логина — не заслон: статус 200, заголовок обычный.
		{"recaptcha на форме логина", 200, htmlHeader,
			html("Вход", `<div class="g-recaptcha" data-sitekey="x"></div>`), ""},
		// Тот же виджет на странице отказа — заслон.
		{"recaptcha на 403", 403, htmlHeader,
			html("Forbidden", `<div class="g-recaptcha" data-sitekey="x"></div>`), "recaptcha"},
		{"recaptcha с говорящим заголовком", 200, htmlHeader,
			html("Проверка, что вы не робот", `<div class="g-recaptcha"></div>`), "recaptcha"},
		{"hcaptcha на 429", 429, htmlHeader, html("Slow down", `<div class="h-captcha"></div>`), "hcaptcha"},
		// JSON с упоминанием капчи в данных — не страница.
		{"json с словом captcha", 200, http.Header{"Content-Type": {"application/json"}},
			[]byte(`{"error":"g-recaptcha failed"}`), ""},
		{"без content-type, но html", 503, nil,
			html("Attention Required! | Cloudflare", "<p>…</p>"), "cloudflare"},
		{"без content-type и не html", 200, nil, []byte("_cf_chl_opt в тексте"), ""},
		{"пустое тело 200", 200, htmlHeader, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			header := c.header
			if header == nil {
				header = http.Header{}
			}
			if got := Detect(c.status, header, c.body); got != c.want {
				t.Errorf("Detect = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

func TestDecodeTruncatedGzip(t *testing.T) {
	page := html("Just a moment...", strings.Repeat("<p>заглушка</p>", 5000))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(page)
	zw.Close()

	// Обрезанный поток: распаковывается то, что есть, без ошибки.
	half := buf.Bytes()[:buf.Len()/2]
	got := Decode("gzip", half)
	if !bytes.Contains(got, []byte("Just a moment")) {
		t.Errorf("из обрезанного gzip не извлечено начало страницы (%d байт)", len(got))
	}
	if Decode("br", half) != nil {
		t.Error("brotli распаковывать нечем — должен быть nil")
	}
	if got := Decode("", []byte("как есть")); string(got) != "как есть" {
		t.Errorf("без сжатия тело должно вернуться как есть: %q", got)
	}
}

func TestAcceptEncoding(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"gzip, deflate, br, zstd"}, "gzip, deflate"},
		{[]string{"br"}, "gzip, deflate"},
		{[]string{"gzip;q=1.0, identity; q=0.5"}, "gzip, identity"},
		{[]string{"gzip", "br"}, "gzip"},
	}
	for _, c := range cases {
		if got := AcceptEncoding(c.in); got != c.want {
			t.Errorf("AcceptEncoding(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}
