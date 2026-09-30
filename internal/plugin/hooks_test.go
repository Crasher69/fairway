package plugin

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"fairway/internal/config"
)

func hookManifest(name string, hooks Hooks) string {
	m := Manifest{Name: name, Version: "1.0.0", Kind: KindHook, Permissions: []Permission{Requests}, Hooks: &hooks}
	data, _ := json.Marshal(m)
	return string(data)
}

func newRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// startHook включает плагин-обработчик и ждёт, пока его экземпляры для
// запросов поднимутся: до этого запросы идут мимо него.
func (e *env) startHook(name string, hooks Hooks, greeting string) {
	e.t.Helper()
	e.install(name, hookManifest(name, hooks))
	e.setPlugins(config.Plugin{Name: name, Enabled: true, Granted: []string{string(Requests)},
		Settings: settings(map[string]any{"greeting": greeting})})
	e.waitState(name, StateRunning)
	e.waitHooks(name)
}

func (e *env) waitHooks(name string) {
	e.t.Helper()
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if pools := e.manager.hooks.Load(); pools != nil {
			for _, p := range *pools {
				if p.name == name && p.alive.Load() == int32(hookWorkers) {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("%s: обработчики запросов не поднялись\nлог:\n%s", name, e.logs.String())
}

func TestHookRequest(t *testing.T) {
	e := newEnv(t)
	e.startHook("headers", Hooks{Domains: []string{"*.example.com"}, Request: true}, "hi")

	req := newRequest(t, "GET", "https://api.example.com:443/path?q=1", "")
	req.Header.Set("X-Secret", "1")
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	if resp := e.manager.OnRequest("api.example.com", req); resp != nil {
		t.Fatalf("плагин ответил сам: %d", resp.StatusCode)
	}
	if got := req.Header.Get("X-Greeting"); got != "hi" {
		t.Fatalf("X-Greeting = %q, заголовки %v", got, req.Header)
	}
	if req.Header.Get("X-Secret") != "" || req.Header.Get("X-Leak") != "" || req.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("заголовки %v", req.Header)
	}
	if req.URL.String() != "https://api.example.com:443/path?q=1" {
		t.Fatalf("URL %s", req.URL)
	}

	// Домен не подходит под маску — плагин не вызывается.
	other := newRequest(t, "GET", "http://example.com/", "")
	e.manager.OnRequest("example.com", other)
	if other.Header.Get("X-Greeting") != "" {
		t.Fatal("плагин вызван для чужого домена")
	}

	rewrite := newRequest(t, "GET", "http://a.example.com/rewrite", "")
	e.manager.OnRequest("a.example.com", rewrite)
	if rewrite.Method != "PUT" || rewrite.URL.String() != "http://a.example.com/rewritten?by=plugin" {
		t.Fatalf("%s %s", rewrite.Method, rewrite.URL)
	}

	// Хост менять нельзя: правка не применяется целиком.
	host := newRequest(t, "GET", "http://a.example.com/host", "")
	e.manager.OnRequest("a.example.com", host)
	if host.URL.Host != "a.example.com" {
		t.Fatalf("хост сменился: %s", host.URL)
	}
	e.waitLog("not the host")

	blocked := newRequest(t, "GET", "http://a.example.com/blocked", "")
	resp := e.manager.OnRequest("a.example.com", blocked)
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("ответ плагина: %+v", resp)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "blocked by hi" || resp.ContentLength != int64(len(body)) || resp.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("%q %d %v", body, resp.ContentLength, resp.Header)
	}

	// Ошибка плагина — запрос идёт как был.
	failed := newRequest(t, "GET", "http://a.example.com/fail", "")
	if resp := e.manager.OnRequest("a.example.com", failed); resp != nil || failed.Header.Get("X-Greeting") != "" {
		t.Fatalf("после ошибки плагина: %+v %v", resp, failed.Header)
	}
	e.waitLog("request hook: refused by plugin")
}

func TestHookRequestBody(t *testing.T) {
	e := newEnv(t)
	e.startHook("bodies", Hooks{Domains: []string{"*"}, Request: true, Body: true}, "hi")

	req := newRequest(t, "POST", "http://x.test/", "hello")
	e.manager.OnRequest("x.test", req)
	body, _ := io.ReadAll(req.Body)
	if string(body) != "HELLO" || req.ContentLength != 5 {
		t.Fatalf("%q %d", body, req.ContentLength)
	}

	big := strings.Repeat("a", MaxHookBody+10)
	req = newRequest(t, "POST", "http://x.test/", big)
	req.ContentLength = -1 // как у chunked: длина заранее неизвестна
	e.manager.OnRequest("x.test", req)
	body, _ = io.ReadAll(req.Body)
	if string(body) != big || req.Header.Get("X-Body") != "skipped" {
		t.Fatalf("большое тело: %d байт, заголовки %v", len(body), req.Header)
	}
}

func TestHookResponse(t *testing.T) {
	e := newEnv(t)
	e.startHook("responses", Hooks{Domains: []string{"x.test"}, Response: true, Body: true}, "плагин")

	req := newRequest(t, "GET", "http://x.test/page", "")
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	zw.Write([]byte("hello world"))
	zw.Close()
	resp := &http.Response{
		StatusCode:    404,
		Header:        http.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"99"}},
		Body:          io.NopCloser(bytes.NewReader(zipped.Bytes())),
		ContentLength: int64(zipped.Len()),
	}
	e.manager.OnResponse("x.test", req, resp)
	body, _ := io.ReadAll(resp.Body)
	want := "hello плагин"
	if string(body) != want || resp.StatusCode != 200 {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.ContentLength != int64(len(want)) ||
		resp.Header.Get("Content-Length") != strconv.Itoa(len(want)) || resp.Header.Get("X-Seen") != "GET http://x.test/page" {
		t.Fatalf("%d %v", resp.ContentLength, resp.Header)
	}

	// Поток событий не копится: тело идёт как есть.
	stream := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"text/event-stream"}},
		Body:          io.NopCloser(strings.NewReader("data: world\n\n")),
		ContentLength: -1,
	}
	e.manager.OnResponse("x.test", req, stream)
	body, _ = io.ReadAll(stream.Body)
	if string(body) != "data: world\n\n" || stream.Header.Get("X-Body") != "skipped" || stream.Header.Get("Content-Length") != "" {
		t.Fatalf("%q %v", body, stream.Header)
	}
}

// Зависший или упавший плагин не держит запрос дольше таймаута, а его
// экземпляр заменяется новым.
func TestHookTimeoutAndCrash(t *testing.T) {
	e := newEnv(t)
	e.startHook("flaky", Hooks{Domains: []string{"*"}, Request: true}, "hi")

	started := time.Now()
	req := newRequest(t, "GET", "http://x.test/slow", "")
	e.manager.OnRequest("x.test", req)
	if took := time.Since(started); took > hookTimeout+time.Second {
		t.Fatalf("запрос ждал %s", took)
	}
	if req.Header.Get("X-Greeting") != "" {
		t.Fatal("правка от прерванного вызова")
	}

	req = newRequest(t, "GET", "http://x.test/crash", "")
	e.manager.OnRequest("x.test", req)

	// Экземпляры поднимаются заново, плагин продолжает работать.
	e.waitHooks("flaky")
	req = newRequest(t, "GET", "http://x.test/", "")
	e.manager.OnRequest("x.test", req)
	if req.Header.Get("X-Greeting") != "hi" {
		t.Fatalf("после перезапуска: %v\nлог:\n%s", req.Header, e.logs.String())
	}
	if st := e.waitState("flaky", StateRunning); st.Kind != KindHook || st.Hooks == nil {
		t.Fatalf("статус %+v", st)
	}

	// Выключенный плагин запросы не трогает.
	e.setPlugins(config.Plugin{Name: "flaky", Enabled: false})
	e.waitState("flaky", StateDisabled)
	req = newRequest(t, "GET", "http://x.test/", "")
	e.manager.OnRequest("x.test", req)
	if req.Header.Get("X-Greeting") != "" {
		t.Fatal("выключенный плагин обработал запрос")
	}
}

func TestHooksMatches(t *testing.T) {
	h := Hooks{Domains: []string{"exact.com", "*.wild.net"}}
	for domain, want := range map[string]bool{
		"exact.com":    true,
		"EXACT.com.":   true,
		"a.exact.com":  false,
		"a.wild.net":   true,
		"a.b.wild.net": true,
		"wild.net":     false,
		"xwild.net":    false,
	} {
		if got := h.Matches(domain); got != want {
			t.Errorf("%s: %v", domain, got)
		}
	}
	if !(&Hooks{Domains: []string{"*"}}).Matches("anything.test") {
		t.Error("* не подошла")
	}
}
