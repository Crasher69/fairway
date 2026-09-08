package forward

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRemoveHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, X-Custom-Hop")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic zzz")
	h.Set("X-Custom-Hop", "должен исчезнуть")
	h.Set("Content-Type", "text/html")

	removeHopByHop(h)

	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authorization", "X-Custom-Hop"} {
		if h.Get(name) != "" {
			t.Errorf("заголовок %s должен был быть удалён", name)
		}
	}
	if h.Get("Content-Type") != "text/html" {
		t.Error("сквозной заголовок Content-Type потерян")
	}
}

func TestHostOnly(t *testing.T) {
	tests := map[string]string{
		"example.com:443": "example.com",
		"example.com":     "example.com",
		"[::1]:8080":      "::1",
	}
	for in, want := range tests {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestServeHTTPThroughDirect гоняет обычный HTTP-запрос через прокси
// в режиме direct и проверяет и ответ, и снятый замер.
func TestServeHTTPThroughDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Connection") != "" {
			t.Error("hop-by-hop заголовок Proxy-Connection дошёл до цели")
		}
		w.Header().Set("X-Test", "ok")
		io.WriteString(w, strings.Repeat("a", 4096))
	}))
	defer target.Close()

	direct, err := ParseUpstream("direct")
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		samples []Sample
	)
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string) (*Route, error) { return &Route{Upstream: direct, Name: direct.Name}, nil },
		Observe: func(s Sample) {
			mu.Lock()
			samples = append(samples, s)
			mu.Unlock()
		},
	})
	defer proxySrv.Close()

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("статус = %d, ожидалось 200", resp.StatusCode)
	}
	if len(body) != 4096 {
		t.Errorf("получено %d байт тела, ожидалось 4096", len(body))
	}
	if resp.Header.Get("X-Test") != "ok" {
		t.Error("заголовок ответа X-Test не проброшен клиенту")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(samples) != 1 {
		t.Fatalf("снято замеров: %d, ожидался 1", len(samples))
	}
	s := samples[0]
	if s.Err != nil {
		t.Errorf("замер с ошибкой: %v", s.Err)
	}
	if s.Status != http.StatusOK {
		t.Errorf("Sample.Status = %d, ожидалось 200", s.Status)
	}
	if s.Domain != hostOnly(mustHost(t, target.URL)) {
		t.Errorf("Sample.Domain = %q", s.Domain)
	}
	if s.Upstream != "direct" {
		t.Errorf("Sample.Upstream = %q, ожидалось direct", s.Upstream)
	}
	if s.Bytes < 4096 {
		t.Errorf("Sample.Bytes = %d, ожидалось не меньше 4096", s.Bytes)
	}
}

// TestConnectTunnelThroughDirect проверяет CONNECT-туннель: прокси должен
// прозрачно пробросить байты и снять замер без HTTP-статуса.
func TestConnectTunnelThroughDirect(t *testing.T) {
	// Эхо-сервер вместо реального TLS: туннелю всё равно, что внутри.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	direct, _ := ParseUpstream("direct")
	// После Hijack httptest перестаёт отслеживать соединение, поэтому Close()
	// не дожидается обработчика — ждём замер через канал.
	samples := make(chan Sample, 1)
	proxySrv := httptest.NewServer(&Server{
		Pick:    func(string) (*Route, error) { return &Route{Upstream: direct, Name: direct.Name}, nil },
		Observe: func(s Sample) { samples <- s },
	})
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", mustHost(t, proxySrv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	target := ln.Addr().String()
	if _, err := conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	const established = "HTTP/1.1 200 Connection established\r\n\r\n"
	buf := make([]byte, len(established))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), "200") {
		t.Fatalf("ответ на CONNECT: %q", buf)
	}

	const payload = "привет через туннель"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != payload {
		t.Errorf("через туннель вернулось %q, ожидалось %q", echo, payload)
	}
	conn.Close()

	select {
	case s := <-samples:
		if s.Status != 0 {
			t.Errorf("Sample.Status = %d, у непрозрачного туннеля статуса быть не должно", s.Status)
		}
		if s.Bytes != int64(len(payload)) {
			t.Errorf("Sample.Bytes = %d, ожидалось %d", s.Bytes, len(payload))
		}
		// Ноль допустим: на loopback ответ приходит быстрее шага таймера.
		if s.TTFB < 0 {
			t.Errorf("TTFB = %s, отрицательным быть не может", s.TTFB)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("замер по CONNECT-туннелю так и не пришёл")
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestHTTPReusesUpstreamConnection — обычный HTTP идёт через пул: второй
// запрос должен уйти по тому же соединению, и connect в нём не измеряется.
func TestHTTPReusesUpstreamConnection(t *testing.T) {
	var mu sync.Mutex
	remotes := map[string]int{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr]++
		mu.Unlock()
		io.WriteString(w, "ок")
	}))
	defer target.Close()

	direct, _ := ParseUpstream("direct")
	var samples []Sample
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string) (*Route, error) { return &Route{Upstream: direct, Name: direct.Name}, nil },
		Observe: func(s Sample) {
			mu.Lock()
			samples = append(samples, s)
			mu.Unlock()
		},
	})
	defer proxySrv.Close()

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(remotes) != 1 {
		t.Errorf("цель видела %d разных соединений от прокси, ожидалось одно (keep-alive)", len(remotes))
	}
	if len(samples) != 3 {
		t.Fatalf("замеров %d, ожидалось 3", len(samples))
	}
	if samples[0].Reused {
		t.Errorf("первый запрос: reused=%v connect=%s — ожидалось новое соединение", samples[0].Reused, samples[0].Connect)
	}
	for i, s := range samples[1:] {
		if !s.Reused || s.Connect != 0 {
			t.Errorf("запрос %d: reused=%v connect=%s — ожидалось переиспользование без замера connect", i+2, s.Reused, s.Connect)
		}
		if s.Status != http.StatusOK || s.Err != nil {
			t.Errorf("запрос %d: статус %d, ошибка %v", i+2, s.Status, s.Err)
		}
	}
}

// TestHTTPThroughHTTPProxyUpstream — через http-апстрим запрос уходит в
// absolute-form с Proxy-Authorization; вторым прокси служит ещё один
// экземпляр Server в режиме direct.
func TestHTTPThroughHTTPProxyUpstream(t *testing.T) {
	var gotAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "цель")
	}))
	defer target.Close()

	direct, _ := ParseUpstream("direct")
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Proxy-Authorization")
		if !r.URL.IsAbs() {
			t.Errorf("до апстрима дошёл запрос не в absolute-form: %s", r.RequestURI)
		}
		(&Server{Pick: func(string) (*Route, error) { return &Route{Upstream: direct, Name: "direct"}, nil }}).ServeHTTP(w, r)
	}))
	defer upstreamProxy.Close()

	up, err := ParseUpstream("http://bob:secret@" + mustHost(t, upstreamProxy.URL))
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string) (*Route, error) { return &Route{Upstream: up, Name: "up"}, nil },
	})
	defer proxySrv.Close()

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target.URL + "/путь")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "цель" {
		t.Errorf("тело %q", body)
	}
	if gotAuth != up.ProxyAuthorization() {
		t.Errorf("Proxy-Authorization до апстрима: %q, ожидалось %q", gotAuth, up.ProxyAuthorization())
	}
}
