package forward

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fairway/internal/mitmca"
)

// mitmHarness — цель по HTTPS, наш прокси с расшифровкой и клиент,
// доверяющий нашему CA. Ровно та схема, что получается в бою.
type mitmHarness struct {
	target  *httptest.Server
	proxy   *httptest.Server
	client  *http.Client
	mu      sync.Mutex
	samples []Sample
}

func newMITMHarness(t *testing.T, handler http.HandlerFunc) *mitmHarness {
	t.Helper()

	h := &mitmHarness{}
	h.target = httptest.NewTLSServer(handler)
	t.Cleanup(h.target.Close)
	h.wire(t)
	return h
}

// wire поднимает прокси с расшифровкой и клиента вокруг уже запущенной цели.
func (h *mitmHarness) wire(t *testing.T) {
	t.Helper()
	ca, err := mitmca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := ParseUpstream("direct")
	if err != nil {
		t.Fatal(err)
	}

	// Цель — самоподписанный сервер httptest, поэтому её корень подкладываем
	// прокси явно: в бою тут работают системные корни.
	originRoots := x509.NewCertPool()
	originRoots.AddCert(h.target.Certificate())

	h.proxy = httptest.NewServer(&Server{
		Pick: func(string) (*Route, error) {
			return &Route{Upstream: direct, Name: "direct", MITM: true}, nil
		},
		Issuer:    mitmca.NewIssuer(ca),
		OriginTLS: &tls.Config{RootCAs: originRoots},
		Observe: func(s Sample) {
			h.mu.Lock()
			h.samples = append(h.samples, s)
			h.mu.Unlock()
		},
	})
	t.Cleanup(h.proxy.Close)

	// Клиент доверяет нашему CA — так же, как машина сети после импорта.
	ourRoots := x509.NewCertPool()
	if !ourRoots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("корневой сертификат не разобрался")
	}
	proxyURL, _ := url.Parse(h.proxy.URL)
	h.client = &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: ourRoots},
	}}
}

func (h *mitmHarness) taken() []Sample {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Sample(nil), h.samples...)
}

// waitSamples дожидается n замеров: клиент получает ответ раньше, чем прокси
// дописывает тело и снимает замер, поэтому сразу после запроса их может не быть.
func (h *mitmHarness) waitSamples(t *testing.T, n int) []Sample {
	t.Helper()
	var got []Sample
	waitFor(t, 5*time.Second, "замеры так и не сняты", func() bool {
		got = h.taken()
		return len(got) >= n
	})
	return got
}

func TestMITMDecryptsRequest(t *testing.T) {
	var gotPath, gotHeader string
	h := newMITMHarness(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHeader = r.Header.Get("X-From-Client")
		w.Header().Set("X-From-Target", "да")
		io.WriteString(w, strings.Repeat("y", 50_000))
	})

	req, _ := http.NewRequest("GET", h.target.URL+"/секретный/путь", nil)
	req.Header.Set("X-From-Client", "проверка")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || len(body) != 50_000 {
		t.Fatalf("ответ: статус %d, тело %d Б", resp.StatusCode, len(body))
	}
	if resp.Header.Get("X-From-Target") != "да" {
		t.Error("заголовок цели не дошёл до клиента")
	}
	if gotPath != "/секретный/путь" || gotHeader != "проверка" {
		t.Errorf("до цели дошло path=%q header=%q", gotPath, gotHeader)
	}

	samples := h.waitSamples(t, 1)
	s := samples[0]
	// Главное отличие от непрозрачного туннеля: виден настоящий статус.
	if s.Status != http.StatusOK {
		t.Errorf("Sample.Status = %d, при расшифровке должен быть настоящий статус", s.Status)
	}
	if s.Bytes < 50_000 {
		t.Errorf("Sample.Bytes = %d, ожидалось не меньше 50000", s.Bytes)
	}
	if s.Err != nil {
		t.Errorf("замер с ошибкой: %v", s.Err)
	}
}

// TestMITMSeesBanStatus — ради этого расшифровка и нужна рейтингу:
// по туннелю 403 неотличим от медленного ответа.
func TestMITMSeesBanStatus(t *testing.T) {
	h := newMITMHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "нет", http.StatusForbidden)
	})

	resp, err := h.client.Get(h.target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	samples := h.waitSamples(t, 1)
	if samples[0].Status != http.StatusForbidden {
		t.Errorf("Sample.Status = %d, ожидался 403 — на нём строится детект бана", samples[0].Status)
	}
}

// TestMITMKeepAliveMarksReuse — на переиспользованном соединении установки
// не было, и ноль не должен попасть в среднее время подключения.
func TestMITMKeepAliveMarksReuse(t *testing.T) {
	h := newMITMHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ок")
	})

	for i := 0; i < 3; i++ {
		resp, err := h.client.Get(h.target.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	samples := h.waitSamples(t, 3)
	if samples[0].Reused {
		t.Error("первый запрос помечен как переиспользованный")
	}
	if samples[0].Connect <= 0 {
		t.Error("на первом запросе не замерено время подключения")
	}
	for i, s := range samples[1:] {
		if !s.Reused {
			t.Errorf("запрос %d по keep-alive не помечен как переиспользованный", i+2)
		}
		if s.Connect != 0 {
			t.Errorf("запрос %d: connect = %s, на переиспользовании его быть не должно", i+2, s.Connect)
		}
	}
}

// TestMITMDisabledLeavesTunnelOpaque — правило mitm: false обязано давать
// обычный туннель, иначе домены с pinning не заработают никогда.
func TestMITMDisabledLeavesTunnelOpaque(t *testing.T) {
	h := newMITMHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ок")
	})

	// Переключаем маршрут на прозрачный туннель.
	direct, _ := ParseUpstream("direct")
	srv := h.proxy.Config.Handler.(*Server)
	srv.Pick = func(string) (*Route, error) {
		return &Route{Upstream: direct, Name: "direct", MITM: false}, nil
	}

	// Клиент теперь должен доверять сертификату самой цели, а не нашему.
	roots := x509.NewCertPool()
	roots.AddCert(h.target.Certificate())
	proxyURL, _ := url.Parse(h.proxy.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}

	resp, err := client.Get(h.target.URL + "/")
	if err != nil {
		t.Fatalf("без расшифровки соединение должно проходить насквозь: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("статус %d", resp.StatusCode)
	}
	// Тело нужно дочитать и закрыть: пока оно открыто, соединение не считается
	// простаивающим и CloseIdleConnections его не тронет.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Замер по туннелю пишется только когда обе половины досчитают байты,
	// то есть после закрытия соединения клиентом.
	client.CloseIdleConnections()
	waitFor(t, 5*time.Second, "замер по прозрачному туннелю не снят", func() bool {
		for _, s := range h.taken() {
			if s.Status == 0 && s.Bytes > 0 {
				return true // статуса в непрозрачном туннеле нет — так и должно быть
			}
		}
		return false
	})
}

func waitFor(t *testing.T, limit time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error(msg)
}

// newIdleClosingHarness — цель, которая закрывает простаивающее keep-alive
// соединение очень быстро и молча, как это делают реальные сайты и
// балансировщики перед ними. Первый запрос после паузы попадает в мёртвое
// соединение.
func newIdleClosingHarness(t *testing.T, handler http.HandlerFunc) *mitmHarness {
	t.Helper()
	h := &mitmHarness{}
	h.target = httptest.NewUnstartedServer(handler)
	h.target.Config.IdleTimeout = 50 * time.Millisecond
	h.target.StartTLS()
	t.Cleanup(h.target.Close)
	h.wire(t)
	return h
}

// TestMITMReplaysPostAfterIdleClose — раньше повторялись только запросы
// без тела, и первый POST после паузы получал 502 на ровном месте.
func TestMITMReplaysPostAfterIdleClose(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	h := newIdleClosingHarness(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.Method+":"+string(body))
		mu.Unlock()
		io.WriteString(w, "ок")
	})

	// Первый запрос открывает keep-alive соединение прокси → цель.
	resp, err := h.client.Get(h.target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Цель закрывает простаивающее соединение, прокси об этом не знает.
	time.Sleep(200 * time.Millisecond)

	// Тело неизвестной длины: клиент шлёт его chunked. Буферизация должна
	// справиться и с этим, а до цели оно должно дойти ровно один раз.
	resp, err = h.client.Post(h.target.URL+"/submit", "text/plain", io.MultiReader(strings.NewReader("платёж №"), strings.NewReader("42")))
	if err != nil {
		t.Fatalf("POST после паузы: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST после паузы: статус %d, ожидался 200 через повтор на новом соединении", resp.StatusCode)
	}

	mu.Lock()
	got := append([]string(nil), bodies...)
	mu.Unlock()
	if len(got) != 2 || got[1] != "POST:платёж №42" {
		t.Errorf("до цели дошло %v, ожидался один GET и один POST с телом целиком", got)
	}

	samples := h.waitSamples(t, 2)
	if s := samples[1]; s.Err != nil || s.Reused || s.Connect <= 0 {
		t.Errorf("замер повторённого POST: err=%v reused=%v connect=%s — ожидалось новое соединение без ошибки", s.Err, s.Reused, s.Connect)
	}
}

// TestMITMDoesNotReplayLargeBody — тело больше лимита уходит потоком и не
// повторяется: держать мегабайты в памяти ради редкого повтора незачем.
func TestMITMDoesNotReplayLargeBody(t *testing.T) {
	var calls int32
	h := newIdleClosingHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		atomic.AddInt32(&calls, 1)
		io.WriteString(w, "ок")
	})
	h.proxy.Config.Handler.(*Server).ReplayBodyLimit = 16

	resp, err := h.client.Get(h.target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(200 * time.Millisecond)

	resp, err = h.client.Post(h.target.URL+"/upload", "text/plain", strings.NewReader(strings.Repeat("x", 1000)))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("большой POST в мёртвое соединение: статус %d, ожидался 502 — повторять такое тело нельзя", resp.StatusCode)
		}
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("цель получила %d запросов, большой POST не должен был повторяться", calls)
	}
}

func TestBufferBody(t *testing.T) {
	// Без тела — повторяем, ничего не читая.
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if rewind, err := bufferBody(req, 10); err != nil || rewind == nil {
		t.Errorf("GET без тела: rewind=%t err=%v", rewind != nil, err)
	}

	// Влезает: буферизуется, перематывается, длина проставлена.
	req, _ = http.NewRequest("POST", "https://example.com/", strings.NewReader("abc"))
	rewind, err := bufferBody(req, 10)
	if err != nil || rewind == nil {
		t.Fatalf("POST 3 байта при лимите 10: rewind=%t err=%v", rewind != nil, err)
	}
	first, _ := io.ReadAll(req.Body)
	rewind()
	second, _ := io.ReadAll(req.Body)
	if string(first) != "abc" || string(second) != "abc" || req.ContentLength != 3 {
		t.Errorf("после перемотки тело %q/%q, длина %d", first, second, req.ContentLength)
	}

	// Chunked тело (длина неизвестна) тоже влезает и становится известным.
	req, _ = http.NewRequest("POST", "https://example.com/", io.MultiReader(strings.NewReader("ab"), strings.NewReader("c")))
	if rewind, err := bufferBody(req, 10); err != nil || rewind == nil || req.ContentLength != 3 {
		t.Errorf("chunked 3 байта: rewind=%t err=%v длина=%d", rewind != nil, err, req.ContentLength)
	}

	// Не влезает: не повторяется, но тело доходит целиком.
	req, _ = http.NewRequest("POST", "https://example.com/", io.MultiReader(strings.NewReader("abcdef"), strings.NewReader("ghijkl")))
	rewind, err = bufferBody(req, 4)
	if err != nil || rewind != nil {
		t.Fatalf("12 байт при лимите 4: rewind=%t err=%v", rewind != nil, err)
	}
	if body, _ := io.ReadAll(req.Body); string(body) != "abcdefghijkl" {
		t.Errorf("тело сверх лимита дошло не целиком: %q", body)
	}

	// Отрицательный лимит выключает буферизацию.
	req, _ = http.NewRequest("POST", "https://example.com/", strings.NewReader("abc"))
	if rewind, _ := bufferBody(req, -1); rewind != nil {
		t.Error("при отрицательном лимите тело не должно буферизоваться")
	}
}
