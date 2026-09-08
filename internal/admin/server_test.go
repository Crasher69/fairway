package admin

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fairway/internal/config"
	"fairway/internal/forward"
	"fairway/internal/mitmca"
	"fairway/internal/proxypool"
	"fairway/internal/rating"
	"fairway/internal/stats"
)

const testConfig = `{
  "defaults": {"list": "", "allow_direct": false, "ban_duration": "5m"},
  "proxies": [
    {"name": "fast", "url": "http://1.1.1.1:8080"},
    {"name": "slow", "url": "http://2.2.2.2:8080"}
  ],
  "lists": [{"name": "main", "proxies": ["fast", "slow"]}],
  "domains": [{"pattern": "example.com", "list": "main", "max_conns_per_proxy": 8, "mitm": true}]
}`

func newTestServer(t *testing.T, token string) (*Server, *httptest.Server) {
	t.Helper()

	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := proxypool.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ratings := rating.NewRegistry()
	ratings.BanDuration = func(string) time.Duration { return 5 * time.Minute }
	recorder := stats.New(100)
	ca, err := mitmca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		Pool:     pool,
		Ratings:  ratings,
		Recorder: recorder,
		Issuer:   mitmca.NewIssuer(ca),
		CA:       ca,
		Config:   func() *config.Config { return cfg },
		Token:    token,
		Version:  "test",
		Started:  time.Now().Add(-time.Minute),
	}
	http := httptest.NewServer(srv.Handler())
	t.Cleanup(http.Close)
	return srv, http
}

// observe прогоняет замер через оба приёмника — так же, как это делает main.
func observe(srv *Server, s forward.Sample) {
	srv.Ratings.Observe(s)
	srv.Recorder.Observe(s)
}

func sample(domain, proxy string, ttfb time.Duration, status int, err error) forward.Sample {
	return forward.Sample{
		Domain:   domain,
		Upstream: proxy,
		Connect:  10 * time.Millisecond,
		TTFB:     ttfb,
		Duration: ttfb + time.Second,
		Bytes:    100_000,
		Status:   status,
		Err:      err,
	}
}

func getJSON(t *testing.T, base, path string, into any) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: статус %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestTokenRequired(t *testing.T) {
	_, ts := newTestServer(t, "секрет")

	resp, err := http.Get(ts.URL + "/api/overview")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("без токена статус %d, ожидался 401", resp.StatusCode)
	}

	// Токен в query должен и пускать, и ставить cookie, чтобы дальше панель
	// работала без токена в адресной строке.
	resp, err = http.Get(ts.URL + "/api/overview?token=секрет")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("с токеном статус %d", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "fairway_token" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("cookie с токеном не выставлена")
	}

	// Токен может быть каким угодно, а в cookie допустим только ASCII —
	// значение обязано пережить кодирование и открыть доступ повторно.
	req, _ := http.NewRequest("GET", ts.URL+"/api/overview", nil)
	req.AddCookie(cookie)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("по cookie статус %d, ожидался 200", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/overview", nil)
	req.Header.Set("Authorization", "Bearer секрет")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("с заголовком Authorization статус %d", resp.StatusCode)
	}
}

func TestOverview(t *testing.T) {
	srv, ts := newTestServer(t, "")
	observe(srv, sample("example.com", "fast", 20*time.Millisecond, 200, nil))

	var got overviewResponse
	getJSON(t, ts.URL, "/api/overview", &got)

	if got.Version != "test" || got.Requests != 1 || got.Proxies != 2 || got.Domains != 1 {
		t.Errorf("сводка: %+v", got)
	}
	if got.UptimeSec < 59 {
		t.Errorf("аптайм %v, ожидалось около минуты", got.UptimeSec)
	}
	if !strings.Contains(got.CASubject, "Fairway") {
		t.Errorf("в сводке нет корневого CA: %q", got.CASubject)
	}
}

func TestDomainViewShowsRatingAndShares(t *testing.T) {
	srv, ts := newTestServer(t, "")
	for i := 0; i < 10; i++ {
		observe(srv, sample("example.com", "fast", 20*time.Millisecond, 200, nil))
		observe(srv, sample("example.com", "slow", 500*time.Millisecond, 200, nil))
	}

	var got domainResponse
	getJSON(t, ts.URL, "/api/domains/example.com", &got)

	if !got.Rule.Known || got.Rule.List != "main" || !got.Rule.MITM {
		t.Errorf("правило домена: %+v", got.Rule)
	}
	if got.Rule.MaxConnsPerProxy != 8 {
		t.Errorf("лимит соединений: %d", got.Rule.MaxConnsPerProxy)
	}
	if len(got.Proxies) != 2 {
		t.Fatalf("прокси в ответе: %d", len(got.Proxies))
	}
	// Сортировка по цене: быстрый должен идти первым.
	if got.Proxies[0].Name != "fast" {
		t.Errorf("первым идёт %s, ожидался fast", got.Proxies[0].Name)
	}
	if !(got.Proxies[0].Share > got.Proxies[1].Share) {
		t.Errorf("доли не отражают преимущество: %v и %v", got.Proxies[0].Share, got.Proxies[1].Share)
	}
	if got.Proxies[0].Status != "ок" {
		t.Errorf("статус быстрого прокси: %q", got.Proxies[0].Status)
	}
}

func TestDomainViewShowsBan(t *testing.T) {
	srv, ts := newTestServer(t, "")
	observe(srv, sample("example.com", "fast", 20*time.Millisecond, 200, nil))
	observe(srv, sample("example.com", "slow", 20*time.Millisecond, 403, nil))

	var got domainResponse
	getJSON(t, ts.URL, "/api/domains/example.com", &got)

	var banned *proxyState
	for i := range got.Proxies {
		if got.Proxies[i].Name == "slow" {
			banned = &got.Proxies[i]
		}
	}
	if banned == nil {
		t.Fatal("забаненный прокси пропал из выдачи — его как раз и надо видеть")
	}
	if !banned.Banned || banned.BanReason == "" {
		t.Errorf("бан не показан: %+v", banned)
	}
	if banned.Share != 0 {
		t.Errorf("забаненному прокси приписана доля трафика %v", banned.Share)
	}
	// Забаненные уходят вниз таблицы.
	if got.Proxies[len(got.Proxies)-1].Name != "slow" {
		t.Error("забаненный прокси не опущен в конец списка")
	}
}

func TestEventsAndErrors(t *testing.T) {
	srv, ts := newTestServer(t, "")
	observe(srv, sample("example.com", "fast", 20*time.Millisecond, 200, nil))
	observe(srv, sample("example.com", "slow", 0, 0, errors.New("таймаут")))
	observe(srv, sample("other.com", "fast", 30*time.Millisecond, 200, nil))

	var all []stats.Event
	getJSON(t, ts.URL, "/api/events?limit=10", &all)
	if len(all) != 3 {
		t.Fatalf("событий: %d, ожидалось 3", len(all))
	}
	// Новые первыми.
	if all[0].Domain != "other.com" {
		t.Errorf("первым идёт %s, ожидалось последнее событие", all[0].Domain)
	}

	var byDomain []stats.Event
	getJSON(t, ts.URL, "/api/events?domain=example.com&limit=10", &byDomain)
	if len(byDomain) != 2 {
		t.Fatalf("событий домена: %d, ожидалось 2", len(byDomain))
	}
	if byDomain[0].Error == "" {
		t.Error("ошибка запроса не попала в живой лог")
	}
}

func TestStreamPushesEvents(t *testing.T) {
	srv, ts := newTestServer(t, "")

	req, _ := http.NewRequest("GET", ts.URL+"/api/stream?domain=example.com", nil)
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}

	// Подписка появляется асинхронно — дожидаемся её, иначе событие уйдёт в пустоту.
	waitFor(t, 3*time.Second, "подписчик не зарегистрировался", func() bool {
		return srv.Recorder.Subscribers() == 1
	})

	observe(srv, sample("other.com", "fast", 10*time.Millisecond, 200, nil))   // отфильтруется
	observe(srv, sample("example.com", "fast", 42*time.Millisecond, 204, nil)) // должно прийти

	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("строка потока: %q", line)
	}
	var event stats.Event
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
		t.Fatal(err)
	}
	if event.Domain != "example.com" || event.Status != 204 {
		t.Errorf("в поток пришло не то событие: %+v", event)
	}
}

func TestStreamUnsubscribes(t *testing.T) {
	srv, ts := newTestServer(t, "")

	ctx, cancel := contextWithTimeout(5 * time.Second)
	req, _ := http.NewRequest("GET", ts.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "подписчик не зарегистрировался", func() bool {
		return srv.Recorder.Subscribers() == 1
	})

	cancel()
	resp.Body.Close()
	// Без отписки канал остался бы в рассылке навсегда.
	waitFor(t, 3*time.Second, "подписчик не удалён после разрыва", func() bool {
		return srv.Recorder.Subscribers() == 0
	})
}

func TestDownloadCA(t *testing.T) {
	_, ts := newTestServer(t, "")
	resp, err := http.Get(ts.URL + "/ca")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("статус %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "fairway-ca.crt") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	body := make([]byte, 64)
	resp.Body.Read(body)
	if !strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("отдан не PEM: %q", string(body))
	}
}

func TestStaticIsServed(t *testing.T) {
	_, ts := newTestServer(t, "")
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: статус %d — файл не вшит в бинарник", path, resp.StatusCode)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8081": true,
		"localhost:8081": true,
		"[::1]:8081":     true,
		"0.0.0.0:8081":   false,
		":8081":          false,
		"192.168.1.5:80": false,
	}
	for addr, want := range tests {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, ожидалось %v", addr, got, want)
		}
	}
}

// TestHealthzIsOpen — проба живости обязана работать без токена, иначе
// Docker и systemd будут считать здоровый процесс мёртвым.
func TestHealthzIsOpen(t *testing.T) {
	_, ts := newTestServer(t, "секрет")

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("статус %d, проба должна отвечать без токена", resp.StatusCode)
	}

	// А всё остальное по-прежнему закрыто.
	other, err := http.Get(ts.URL + "/api/overview")
	if err != nil {
		t.Fatal(err)
	}
	other.Body.Close()
	if other.StatusCode != http.StatusUnauthorized {
		t.Errorf("api без токена вернул %d", other.StatusCode)
	}
}

func TestOverviewHasRuntime(t *testing.T) {
	_, ts := newTestServer(t, "")
	var got overviewResponse
	getJSON(t, ts.URL, "/api/overview", &got)
	if got.Goroutines <= 0 || got.HeapMB <= 0 {
		t.Errorf("рантайм не заполнен: горутин %d, куча %v МБ", got.Goroutines, got.HeapMB)
	}
}

func TestCAInfoExposesFingerprintAndTrust(t *testing.T) {
	_, ts := newTestServer(t, "")

	var got caResponse
	getJSON(t, ts.URL, "/api/ca", &got)

	if !strings.Contains(got.Subject, "Fairway") {
		t.Errorf("subject = %q", got.Subject)
	}
	// Отпечаток SHA-256 в hex — 64 символа в верхнем регистре: его сверяют
	// глазами с тем, что показывает системное хранилище.
	if len(got.Fingerprint) != 64 || got.Fingerprint != strings.ToUpper(got.Fingerprint) {
		t.Errorf("отпечаток = %q", got.Fingerprint)
	}
	if got.Trust.Store == "" {
		t.Error("не указано, в какое хранилище ставится сертификат")
	}
	// Свежесозданный CA в системе стоять не может.
	if got.Trust.Installed {
		t.Error("только что созданный сертификат числится установленным")
	}
}

func TestCAActionsRequireToken(t *testing.T) {
	_, ts := newTestServer(t, "секрет")
	for _, path := range []string{"/api/ca", "/api/ca/install", "/api/ca/uninstall"} {
		method := "GET"
		if strings.Contains(path, "install") {
			method = "POST"
		}
		req, _ := http.NewRequest(method, ts.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s без токена вернул %d", method, path, resp.StatusCode)
		}
	}
}

func TestUnbanFromPanel(t *testing.T) {
	srv, ts := newTestServer(t, "")
	for i := 0; i < 3; i++ {
		observe(srv, sample("example.com", "slow", 0, 0, errors.New("connection refused")))
	}
	var view domainResponse
	getJSON(t, ts.URL, "/api/domains/example.com", &view)
	if !view.Proxies[len(view.Proxies)-1].Banned {
		t.Fatal("прокси не забанен, проверять нечего")
	}

	resp, err := http.Post(ts.URL+"/api/domains/example.com/unban/slow", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("снятие бана: статус %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	for _, p := range view.Proxies {
		if p.Banned {
			t.Errorf("после снятия бана %s всё ещё забанен", p.Name)
		}
	}

	// Повторно снимать нечего.
	again, err := http.Post(ts.URL+"/api/domains/example.com/unban/slow", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusNotFound {
		t.Errorf("повторное снятие: статус %d, ожидался 404", again.StatusCode)
	}
}
