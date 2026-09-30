package forward

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdempotent(t *testing.T) {
	for method, want := range map[string]bool{
		"GET": true, "HEAD": true, "OPTIONS": true, "TRACE": true, "PUT": true, "DELETE": true,
		"POST": false, "PATCH": false,
	} {
		req, _ := http.NewRequest(method, "http://example.com/", nil)
		if got := idempotent(req); got != want {
			t.Errorf("%s: %v, ожидалось %v", method, got, want)
		}
	}
	req, _ := http.NewRequest("POST", "http://example.com/", nil)
	req.Header.Set("Idempotency-Key", "k1")
	if !idempotent(req) {
		t.Error("POST с Idempotency-Key должен считаться идемпотентным")
	}
}

// slowTarget отвечает позже таймаута ответа и считает, сколько раз
// запрос до неё дошёл.
func slowTarget(hits *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		time.Sleep(400 * time.Millisecond)
		io.WriteString(w, "поздно")
	}
}

// mitmSlowCase поднимает MITM с таймаутом ответа 100 мс перед медленной
// целью; каждый выбор маршрута считается.
func mitmSlowCase(t *testing.T, hits, picks *atomic.Int64) *mitmHarness {
	t.Helper()
	h := newMITMHarness(t, slowTarget(hits))
	direct, _ := ParseUpstream("direct")
	h.srv.ResponseTimeout = 100 * time.Millisecond
	h.srv.Pick = func(string, []string) (*Route, error) {
		picks.Add(1)
		return &Route{Upstream: direct, Name: "direct", MITM: true}, nil
	}
	return h
}

// TestMITMDoesNotRetryPostAfterTimeout — главное в правиле повтора: POST
// дошёл до цели, та думает дольше таймаута. Повтор через другой прокси
// выполнил бы его ещё раз, поэтому клиент получает 504, а цель — один
// запрос.
func TestMITMDoesNotRetryPostAfterTimeout(t *testing.T) {
	var hits, picks atomic.Int64
	h := mitmSlowCase(t, &hits, &picks)

	resp, err := h.client.Post(h.target.URL+"/pay", "text/plain", strings.NewReader("сумма=100"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("статус %d, ожидался 504", resp.StatusCode)
	}
	time.Sleep(500 * time.Millisecond) // дать повтору, если он есть, дойти до цели
	if got := hits.Load(); got != 1 {
		t.Errorf("POST выполнен целью %d раз, ожидался один", got)
	}
	if got := picks.Load(); got != 1 {
		t.Errorf("маршрут выбирался %d раз: POST после таймаута не повторяется", got)
	}
}

// TestMITMRetriesIdempotentAfterTimeout — GET и POST с Idempotency-Key
// по-прежнему уходят через другой прокси: это и спасает от прокси,
// который принимает запрос и молчит.
func TestMITMRetriesIdempotentAfterTimeout(t *testing.T) {
	for name, build := range map[string]func(string) *http.Request{
		"GET": func(u string) *http.Request {
			req, _ := http.NewRequest("GET", u, nil)
			return req
		},
		"POST с Idempotency-Key": func(u string) *http.Request {
			req, _ := http.NewRequest("POST", u, strings.NewReader("x"))
			req.Header.Set("Idempotency-Key", "k1")
			return req
		},
	} {
		t.Run(name, func(t *testing.T) {
			var hits, picks atomic.Int64
			h := mitmSlowCase(t, &hits, &picks)
			resp, err := h.client.Do(build(h.target.URL + "/"))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if got := picks.Load(); got != maxAttempts {
				t.Errorf("маршрут выбирался %d раз, ожидалось %d", got, maxAttempts)
			}
		})
	}
}

// TestMITMRetriesPostWhenNotConnected — POST через прокси, который не
// соединился, уходит через другой: до цели он не доходил.
func TestMITMRetriesPostWhenNotConnected(t *testing.T) {
	var hits atomic.Int64
	h := newMITMHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "принято")
	})
	dead := deadUpstream(t)
	direct, _ := ParseUpstream("direct")
	h.srv.Pick = func(_ string, avoid []string) (*Route, error) {
		if len(avoid) == 0 {
			return &Route{Upstream: dead, Name: "dead", MITM: true}, nil
		}
		return &Route{Upstream: direct, Name: "alive", MITM: true}, nil
	}
	resp, err := h.client.Post(h.target.URL+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "принято" || hits.Load() != 1 {
		t.Errorf("статус %d, тело %q, запросов к цели %d", resp.StatusCode, body, hits.Load())
	}
}

// httpSlowCase — то же для обычного HTTP.
func httpSlowCase(t *testing.T, hits, picks *atomic.Int64) (*http.Client, string) {
	t.Helper()
	target := httptest.NewServer(slowTarget(hits))
	t.Cleanup(target.Close)
	direct, _ := ParseUpstream("direct")
	proxySrv := httptest.NewServer(&Server{
		ResponseTimeout: 100 * time.Millisecond,
		Pick: func(string, []string) (*Route, error) {
			picks.Add(1)
			return &Route{Upstream: direct, Name: "direct"}, nil
		},
	})
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}, target.URL
}

// TestHTTPDoesNotRetryEmptyPostAfterTimeout — POST без тела тоже может
// что-то выполнять («подтвердить заказ»): ушедший к медленной цели, он не
// повторяется. Раньше повторялся любой запрос без тела.
func TestHTTPDoesNotRetryEmptyPostAfterTimeout(t *testing.T) {
	var hits, picks atomic.Int64
	client, target := httpSlowCase(t, &hits, &picks)

	resp, err := client.Post(target+"/confirm", "text/plain", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("статус %d, ожидался 504", resp.StatusCode)
	}
	time.Sleep(500 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Errorf("POST выполнен целью %d раз, ожидался один", got)
	}
	if got := picks.Load(); got != 1 {
		t.Errorf("маршрут выбирался %d раз", got)
	}
}

// TestHTTPRetriesGetAfterTimeout — GET через молчащий прокси уходит через
// другой, как и раньше.
func TestHTTPRetriesGetAfterTimeout(t *testing.T) {
	var hits, picks atomic.Int64
	client, target := httpSlowCase(t, &hits, &picks)

	resp, err := client.Get(target + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := picks.Load(); got != maxAttempts {
		t.Errorf("маршрут выбирался %d раз, ожидалось %d", got, maxAttempts)
	}
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("статус %d, ожидался 504", resp.StatusCode)
	}
}
