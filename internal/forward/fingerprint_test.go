package forward

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"fairway/internal/fingerprint"
)

// helloLog запоминает, что предлагали цели в ClientHello.
type helloLog struct {
	mu     sync.Mutex
	alpn   [][]string
	grease bool
}

func (l *helloLog) record(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.alpn = append(l.alpn, append([]string(nil), hello.SupportedProtos...))
	for _, c := range hello.CipherSuites {
		// GREASE (RFC 8701) шлют браузеры, а не crypto/tls.
		if c&0x0f0f == 0x0a0a && c>>8 == c&0xff {
			l.grease = true
		}
	}
	return nil, nil
}

func (l *helloLog) snapshot() ([][]string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]string(nil), l.alpn...), l.grease
}

// newFingerprintHarness — MITM-стенд, где цель умеет HTTP/2, а маршрут
// подделывает рукопожатие под профиль.
func newFingerprintHarness(t *testing.T, profile, ua string, handler http.HandlerFunc) (*mitmHarness, *helloLog) {
	t.Helper()
	fp, ok := fingerprint.Lookup(profile)
	if !ok {
		t.Fatalf("нет профиля %s", profile)
	}
	log := &helloLog{}
	h := &mitmHarness{}
	h.target = httptest.NewUnstartedServer(handler)
	h.target.EnableHTTP2 = true
	h.target.TLS = &tls.Config{GetConfigForClient: log.record}
	h.target.StartTLS()
	t.Cleanup(h.target.Close)
	h.wire(t)
	direct, _ := ParseUpstream("direct")
	h.srv.Pick = func(string, []string) (*Route, error) {
		return &Route{Upstream: direct, Name: "direct", MITM: true, Fingerprint: fp, UserAgent: ua}, nil
	}
	return h, log
}

func TestFingerprintSpeaksH2WithBrowserHeaders(t *testing.T) {
	type seen struct{ proto, ua, hints, body string }
	var (
		mu  sync.Mutex
		got []seen
	)
	h, log := newFingerprintHarness(t, "chrome_133", fingerprint.UAProfile, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seen{r.Proto, r.UserAgent(), r.Header.Get("Sec-Ch-Ua"), string(body)})
		mu.Unlock()
		// Длина заранее неизвестна: клиенту ответ должен уйти чанками.
		w.Write([]byte("часть-1/"))
		w.(http.Flusher).Flush()
		w.Write([]byte("часть-2"))
	})

	for i, method := range []string{"GET", "POST", "GET"} {
		var body io.Reader
		if method == "POST" {
			body = strings.NewReader("тело-запроса")
		}
		req, _ := http.NewRequest(method, h.target.URL+"/", body)
		req.Header.Set("User-Agent", "curl/8.0")
		req.Header.Set("Sec-Ch-Ua-Arch", `"x86"`)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("запрос %d: %v", i, err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(data) != "часть-1/часть-2" {
			t.Fatalf("запрос %d: статус %d, тело %q", i, resp.StatusCode, data)
		}
		if resp.Close {
			t.Errorf("запрос %d: ответ без длины закрыл соединение с клиентом", i)
		}
	}

	profile, _ := fingerprint.Lookup("chrome_133")
	mu.Lock()
	defer mu.Unlock()
	for i, s := range got {
		if s.proto != "HTTP/2.0" {
			t.Errorf("запрос %d ушёл по %s, ожидался HTTP/2", i, s.proto)
		}
		if s.ua != profile.UserAgent || s.hints != profile.ClientHints["Sec-Ch-Ua"] {
			t.Errorf("запрос %d: UA %q, sec-ch-ua %q — не из профиля", i, s.ua, s.hints)
		}
	}
	if got[1].body != "тело-запроса" {
		t.Errorf("тело POST: %q", got[1].body)
	}

	alpn, grease := log.snapshot()
	if !grease {
		t.Error("в ClientHello нет GREASE — рукопожатие не браузерное")
	}
	// Три запроса — одно соединение: HTTP/2 переиспользуется.
	if len(alpn) != 1 || strings.Join(alpn[0], ",") != "h2,http/1.1" {
		t.Errorf("ALPN рукопожатий: %v", alpn)
	}
	samples := h.waitSamples(t, 3)
	if !samples[1].Reused || !samples[2].Reused {
		t.Error("соединение HTTP/2 не переиспользовалось")
	}
}

// Каждый профиль должен договориться с обычным сервером: uTLS знает не все
// расширения, и профиль, который рвёт рукопожатие, лучше поймать здесь.
func TestEveryProfileHandshakes(t *testing.T) {
	for _, name := range fingerprint.Names() {
		t.Run(name, func(t *testing.T) {
			h, _ := newFingerprintHarness(t, name, fingerprint.UAProfile, func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "ок")
			})
			resp, err := h.client.Get(h.target.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "ок" {
				t.Errorf("статус %d, тело %q", resp.StatusCode, body)
			}
		})
	}
}

// Отпечаток Akamai складывается из SETTINGS по порядку, окна соединения и
// порядка псевдозаголовков — транспорт должен взять их из профиля как есть.
func TestH2TransportFollowsProfile(t *testing.T) {
	chrome, _ := fingerprint.Lookup("chrome_133")
	tr := h2Transport(chrome)
	var got []string
	for _, id := range tr.SettingsOrder {
		got = append(got, fmt.Sprintf("%d:%d", id, tr.Settings[id]))
	}
	if strings.Join(got, ";") != "1:65536;2:0;4:6291456;6:262144" {
		t.Errorf("SETTINGS: %v", got)
	}
	if tr.ConnectionFlow != 15663105 || strings.Join(tr.PseudoHeaderOrder, ",") != ":method,:authority,:scheme,:path" {
		t.Errorf("окно %d, псевдозаголовки %v", tr.ConnectionFlow, tr.PseudoHeaderOrder)
	}
	if h2Transport(chrome) != tr {
		t.Error("транспорт профиля должен создаваться один раз")
	}

	firefox, _ := fingerprint.Lookup("firefox_120")
	if ff := h2Transport(firefox); len(ff.Priorities) != 6 || ff.InitialStreamID != 15 || ff.HeaderPriority == nil {
		t.Errorf("Firefox: PRIORITY %d, первый поток %d", len(ff.Priorities), ff.InitialStreamID)
	}
}

func TestFingerprintKeepsClientUserAgentByDefault(t *testing.T) {
	var ua string
	h, _ := newFingerprintHarness(t, "firefox_120", fingerprint.UAKeep, func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
	})
	req, _ := http.NewRequest("GET", h.target.URL+"/", nil)
	req.Header.Set("User-Agent", "свой-UA")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ua != "свой-UA" {
		t.Errorf("UA клиента заменён: %q", ua)
	}
}

func TestApplyHeadersMatchesProfile(t *testing.T) {
	firefox, _ := fingerprint.Lookup("firefox_120")
	h := http.Header{}
	h.Set("User-Agent", "Chrome")
	h.Set("Sec-Ch-Ua", "chrome")
	h.Set("Sec-Ch-Ua-Platform", "Windows")
	firefox.ApplyHeaders(h, fingerprint.UAProfile)
	if h.Get("User-Agent") != firefox.UserAgent || h.Get("Sec-Ch-Ua") != "" || h.Get("Sec-Ch-Ua-Platform") != "" {
		t.Errorf("Firefox с хинтами Chrome: %v", h)
	}

	h = http.Header{}
	firefox.ApplyHeaders(h, "мой UA")
	if h.Get("User-Agent") != "мой UA" {
		t.Errorf("свой UA не подставлен: %v", h)
	}
}

// WebSocket по HTTP/2 не ходит: для апгрейда открывается отдельное
// соединение с одним http/1.1 в ALPN, как это делает браузер.
func TestFingerprintWebSocketUsesHTTP1(t *testing.T) {
	h, log := newFingerprintHarness(t, "chrome_133", "", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			io.WriteString(w, "обычный ответ")
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		io.Copy(conn, buf)
	})

	raw, err := net.Dial("tcp", mustHost(t, h.proxy.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	targetHost := mustHost(t, h.target.URL)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost, targetHost)
	if resp, err := http.ReadResponse(bufio.NewReader(raw), nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v / %v", resp, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{RootCAs: h.roots, ServerName: hostOnly(targetHost)})
	defer tlsConn.Close()
	reader := bufio.NewReader(tlsConn)

	// Сначала обычный запрос — соединение до цели встаёт по HTTP/2.
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Fprintf(tlsConn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n", targetHost)
	resp, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("ответ на апгрейд: %d", resp.StatusCode)
	}
	const frame = "кадр"
	io.WriteString(tlsConn, frame)
	echo := make([]byte, len(frame))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != frame {
		t.Fatalf("эхо %q: %v", echo, err)
	}

	alpn, _ := log.snapshot()
	if len(alpn) != 2 || strings.Join(alpn[0], ",") != "h2,http/1.1" || strings.Join(alpn[1], ",") != "http/1.1" {
		t.Errorf("ALPN рукопожатий: %v", alpn)
	}
}
