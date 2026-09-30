package forward

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDomainOf(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM:443":  "example.com",
		"example.com.:443": "example.com",
		"EXAMPLE.com.":     "example.com",
		"[::1]:8080":       "::1",
	} {
		if got := domainOf(in); got != want {
			t.Errorf("domainOf(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestTransferMeterSkipsIdle — простой keep-alive между ответами в
// скорость туннеля не входит: браузер держит сокет минутами, и скорость
// по всему времени жизни была бы в сотни раз меньше настоящей.
func TestTransferMeterSkipsIdle(t *testing.T) {
	m := transferMeter{last: time.Now().Add(-100 * time.Millisecond)}
	m.add(64 << 10)
	if m.bytes != 64<<10 || m.active < 100*time.Millisecond || m.active > time.Second {
		t.Fatalf("порция внутри отдачи не учтена: %d байт за %s", m.bytes, m.active)
	}
	// Пауза в пять минут — следующий запрос браузера, а не медленный прокси.
	active := m.active
	m.last = time.Now().Add(-5 * time.Minute)
	m.add(1 << 20)
	if m.bytes != 64<<10 || m.active != active {
		t.Errorf("простой учтён в скорости: %d байт за %s", m.bytes, m.active)
	}
}

// slowUpload — тело запроса, которое уходит порциями с паузами: всего
// дольше таймаута ответа, но каждая пауза короче него.
func slowUpload(parts int, pause time.Duration) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < parts; i++ {
			time.Sleep(pause)
			if _, err := pw.Write([]byte(strings.Repeat("x", 1024))); err != nil {
				return
			}
		}
		pw.Close()
	}()
	return pr
}

// echoLength отвечает, сколько байт тела пришло.
func echoLength(w http.ResponseWriter, r *http.Request) {
	n, _ := io.Copy(io.Discard, r.Body)
	io.WriteString(w, strings.Repeat("y", int(n)))
}

// TestHTTPSlowUploadIsNotTimeout — таймаут ответа отсчитывается от конца
// отправки. Раньше он шёл с начала запроса: загрузка дольше таймаута
// обрывалась 502, а ошибка записывалась прокси и после трёх подряд
// приводила к бану.
func TestHTTPSlowUploadIsNotTimeout(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(echoLength))
	defer target.Close()
	direct, _ := ParseUpstream("direct")

	var (
		mu      sync.Mutex
		samples []Sample
	)
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string, []string) (*Route, error) {
			return &Route{Upstream: direct, Name: "direct", ResponseTimeout: 200 * time.Millisecond}, nil
		},
		Observe: func(s Sample) {
			mu.Lock()
			samples = append(samples, s)
			mu.Unlock()
		},
	})
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(target.URL, "text/plain", slowUpload(6, 100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(body) != 6*1024 {
		t.Fatalf("статус %d, тело %d байт", resp.StatusCode, len(body))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(samples) != 1 || samples[0].Err != nil {
		t.Fatalf("замеры: %+v", samples)
	}
	// Время загрузки тела к скорости ответа цели отношения не имеет.
	if samples[0].TTFB > 300*time.Millisecond {
		t.Errorf("TTFB %s включает загрузку тела", samples[0].TTFB)
	}
}

// TestMITMSlowUploadIsNotTimeout — то же в режиме MITM для тела, которое
// не буферизуется и уходит потоком: раньше дедлайн ставился от начала
// отправки и к её концу был уже в прошлом.
func TestMITMSlowUploadIsNotTimeout(t *testing.T) {
	h := newMITMHarness(t, echoLength)
	h.srv.ReplayBodyLimit = -1
	h.srv.ResponseTimeout = 200 * time.Millisecond

	resp, err := h.client.Post(h.target.URL, "text/plain", slowUpload(6, 100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(body) != 6*1024 {
		t.Fatalf("статус %d, тело %d байт", resp.StatusCode, len(body))
	}
	s := h.waitSamples(t, 1)[0]
	if s.Err != nil {
		t.Fatalf("замер с ошибкой: %v", s.Err)
	}
	if s.TTFB > 300*time.Millisecond {
		t.Errorf("TTFB %s включает загрузку тела", s.TTFB)
	}
	if s.TransferBytes == 0 {
		t.Errorf("объём отдачи не записан: %d", s.TransferBytes)
	}
}

// TestWatchdogKickAfterStop — толчок после остановки не заводит таймер
// заново: иначе тело запроса, дописанное транспортом уже после ответа,
// через wait отменило бы скачивание этого ответа.
func TestWatchdogKickAfterStop(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	w := newWatchdog(50*time.Millisecond, func() { cancelled <- struct{}{} })
	if w.stop() {
		t.Fatal("таймер сработал раньше срока")
	}
	w.kick()
	select {
	case <-cancelled:
		t.Error("толчок после stop отменил запрос")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestWatchdogFires — без толчков таймер срабатывает, и stop это видит.
func TestWatchdogFires(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	w := newWatchdog(20*time.Millisecond, func() { cancelled <- struct{}{} })
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("таймер не сработал")
	}
	if !w.stop() {
		t.Error("stop не сообщил о сработавшем таймере")
	}
}
