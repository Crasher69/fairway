package forward

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// silentProxy — HTTP-прокси, который на CONNECT отвечает 200 и дальше
// молчит: байты от клиента глотает, от «цели» не присылает ничего. Ровно
// так ведут себя мёртвые платные прокси: подключение есть, трафика нет.
func silentProxy(t *testing.T) *Upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := http.ReadRequest(r); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				_, _ = io.Copy(io.Discard, r)
			}()
		}
	}()
	up, err := ParseUpstream("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	up.Name = "silent"
	return up
}

// echoTarget — TCP-цель, которая возвращает всё, что получила.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

type sampleLog struct {
	mu      sync.Mutex
	samples []Sample
}

func (l *sampleLog) observe(s Sample) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.samples = append(l.samples, s)
}

func (l *sampleLog) list() []Sample {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Sample(nil), l.samples...)
}

// connectThrough открывает CONNECT-туннель через прокси-сервер и
// возвращает соединение после ответа 200.
func connectThrough(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ответ на CONNECT: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT: статус %d", resp.StatusCode)
	}
	return conn
}

// TestTunnelRetriesThroughAnotherUpstreamWhenTargetIsSilent — прокси принял
// CONNECT и молчит. Раньше это длилось, пока браузер не сдастся, и
// считалось успехом. Теперь: ошибка для молчащего прокси, а присланное
// клиентом уходит через другой, и клиент получает ответ как ни в чём не
// бывало.
func TestTunnelRetriesThroughAnotherUpstreamWhenTargetIsSilent(t *testing.T) {
	silent := silentProxy(t)
	direct, err := ParseUpstream("direct")
	if err != nil {
		t.Fatal(err)
	}
	target := echoTarget(t)

	var log sampleLog
	srv := &Server{
		DialTimeout: 300 * time.Millisecond,
		Observe:     log.observe,
		Pick: func(_ string, avoid []string) (*Route, error) {
			if len(avoid) == 0 {
				return &Route{Upstream: silent, Name: "silent"}, nil
			}
			for _, a := range avoid {
				if a == "direct" {
					t.Fatal("прямой маршрут попал в список провалившихся")
				}
			}
			return &Route{Upstream: direct, Name: "direct"}, nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = http.Serve(ln, srv) }()

	conn := connectThrough(t, ln.Addr().String(), target)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	const hello = "hello through the tunnel"
	if _, err := io.WriteString(conn, hello); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ответ через запасной прокси не пришёл: %v", err)
	}
	if string(got) != hello {
		t.Fatalf("эхо искажено: %q", got)
	}
	conn.Close()

	// Замер по туннелю снимается, когда он закрыт; дождёмся.
	deadline := time.Now().Add(3 * time.Second)
	for len(log.list()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	samples := log.list()
	if len(samples) != 2 {
		t.Fatalf("ожидалось два замера (ошибка и успех), получено %d: %+v", len(samples), samples)
	}
	if samples[0].Upstream != "silent" || samples[0].Err == nil {
		t.Errorf("молчащий прокси должен получить ошибку, замер: %+v", samples[0])
	}
	if !strings.Contains(samples[0].Err.Error(), "no reply") {
		t.Errorf("ошибка должна говорить об отсутствии ответа, а не о чём-то ещё: %v", samples[0].Err)
	}
	if samples[1].Upstream != "direct" || samples[1].Err != nil || samples[1].Bytes != int64(len(hello)) {
		t.Errorf("запасной прокси должен дать успешный замер с байтами, замер: %+v", samples[1])
	}
}

// TestTunnelIgnoresClientThatSentNothing — браузер открывает соединения
// впрок и часть из них закрывает, не отправив ни байта. Цель при этом
// молчит по понятной причине, и прокси тут ни при чём: замера быть не
// должно, иначе живой прокси набирал бы ошибки на ровном месте.
func TestTunnelIgnoresClientThatSentNothing(t *testing.T) {
	silent := silentProxy(t)
	var log sampleLog
	srv := &Server{
		DialTimeout: 200 * time.Millisecond,
		Observe:     log.observe,
		Pick: func(string, []string) (*Route, error) {
			return &Route{Upstream: silent, Name: "silent"}, nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = http.Serve(ln, srv) }()

	conn := connectThrough(t, ln.Addr().String(), "example.test:443")
	conn.Close()

	time.Sleep(500 * time.Millisecond)
	if samples := log.list(); len(samples) != 0 {
		t.Errorf("клиент ничего не прислал, а замеры есть: %+v", samples)
	}
}

// TestTunnelGivesUpAfterMaxAttempts — если все запасные прокси такие же
// молчаливые, попытки кончаются, туннель закрывается, и на каждый прокси
// записана ошибка. Клиент не должен ждать вечно.
func TestTunnelGivesUpAfterMaxAttempts(t *testing.T) {
	silent := silentProxy(t)
	var log sampleLog
	var picks int
	var mu sync.Mutex
	srv := &Server{
		DialTimeout: 150 * time.Millisecond,
		Observe:     log.observe,
		Pick: func(_ string, avoid []string) (*Route, error) {
			mu.Lock()
			defer mu.Unlock()
			picks++
			return &Route{Upstream: silent, Name: "silent-" + string(rune('a'+len(avoid)))}, nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = http.Serve(ln, srv) }()

	conn := connectThrough(t, ln.Addr().String(), "example.test:443")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "ping")

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("туннель должен закрыться без данных")
	}
	samples := log.list()
	if len(samples) != maxAttempts {
		t.Fatalf("ожидалось %d ошибок (по одной на попытку), получено %d: %+v", maxAttempts, len(samples), samples)
	}
	for _, s := range samples {
		if s.Err == nil {
			t.Errorf("каждая попытка должна быть ошибкой: %+v", s)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if picks != maxAttempts {
		t.Errorf("маршрут выбирался %d раз, ожидалось %d", picks, maxAttempts)
	}
}
