package forward

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeHooks — обработчик как у плагина: добавляет заголовок, на /answer
// отвечает сам, в ответе меняет тело.
type fakeHooks struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeHooks) OnRequest(domain string, req *http.Request) *http.Response {
	f.mu.Lock()
	f.seen = append(f.seen, domain+" "+req.URL.String())
	f.mu.Unlock()
	if req.URL.Path == "/answer" {
		body := "from hook"
		return &http.Response{
			StatusCode:    http.StatusTeapot,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"X-Hook": {"answered"}, "Content-Length": {strconv.Itoa(len(body))}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	}
	req.Header.Set("X-Hook", "request")
	return nil
}

func (f *fakeHooks) OnResponse(domain string, req *http.Request, resp *http.Response) {
	data, _ := io.ReadAll(resp.Body)
	data = []byte(strings.ReplaceAll(string(data), "target", "hooked"))
	resp.Body = io.NopCloser(strings.NewReader(string(data)))
	resp.ContentLength = int64(len(data))
	resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
	resp.Header.Set("X-Hook", "response "+req.Header.Get("X-Hook"))
}

func (f *fakeHooks) urls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func hookTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Got-Hook", r.Header.Get("X-Hook"))
	io.WriteString(w, "from target")
}

func checkHooked(t *testing.T, resp *http.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from hooked" {
		t.Fatalf("тело %q", body)
	}
	if resp.Header.Get("X-Got-Hook") != "request" || resp.Header.Get("X-Hook") != "response request" {
		t.Fatalf("заголовки %v", resp.Header)
	}
}

func checkAnswered(t *testing.T, resp *http.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTeapot || string(body) != "from hook" || resp.Header.Get("X-Hook") != "answered" {
		t.Fatalf("%d %q %v", resp.StatusCode, body, resp.Header)
	}
}

func TestHooksOnHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(hookTarget))
	defer target.Close()
	direct, _ := ParseUpstream("direct")
	hooks := &fakeHooks{}
	var picked int
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string, []string) (*Route, error) {
			picked++
			return &Route{Upstream: direct, Name: direct.Name}, nil
		},
		Hooks: hooks,
	})
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/page")
	checkHooked(t, resp, err)

	resp, err = client.Get(target.URL + "/answer")
	checkAnswered(t, resp, err)
	if picked != 1 {
		t.Fatalf("маршрут выбран %d раз: на ответ плагина прокси не нужен", picked)
	}
	if seen := hooks.urls(); len(seen) != 2 || seen[0] != "127.0.0.1 "+target.URL+"/page" {
		t.Fatalf("плагин видел %v", seen)
	}
}

func TestHooksOnMITM(t *testing.T) {
	h := newMITMHarness(t, hookTarget)
	hooks := &fakeHooks{}
	h.proxy.Config.Handler.(*Server).Hooks = hooks

	// Ответ плагина не рвёт соединение: следующий запрос идёт по нему же.
	resp, err := h.client.Get(h.target.URL + "/answer")
	checkAnswered(t, resp, err)
	resp, err = h.client.Get(h.target.URL + "/page")
	checkHooked(t, resp, err)

	// Замер — только за запрос, дошедший до цели.
	if samples := h.waitSamples(t, 1); len(samples) != 1 || samples[0].Status != http.StatusOK {
		t.Fatalf("замеры %+v", samples)
	}
	host := mustHost(t, h.target.URL)
	seen := hooks.urls()
	if len(seen) != 2 || seen[1] != hostOnly(host)+" https://"+host+"/page" {
		t.Fatalf("плагин видел %v", seen)
	}
}
