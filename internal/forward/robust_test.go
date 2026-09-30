package forward

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lockedBuffer — лог сервера, который читают из теста.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTunnelSilentThenDeadDoesNotPanic — первый прокси молчит, второй не
// соединяется, третьего нет. Раньше отложенный Close вызывался на nil и
// net/http писал в лог стек паники на каждый такой туннель.
func TestTunnelSilentThenDeadDoesNotPanic(t *testing.T) {
	silent := silentProxy(t)
	dead := deadUpstream(t)
	target := echoTarget(t)

	srv := &Server{
		DialTimeout: 300 * time.Millisecond,
		Pick: func(_ string, avoid []string) (*Route, error) {
			switch len(avoid) {
			case 0:
				return &Route{Upstream: silent, Name: "silent"}, nil
			case 1:
				return &Route{Upstream: dead, Name: "dead"}, nil
			}
			return nil, io.EOF // больше некого
		},
	}
	logs := &lockedBuffer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	httpSrv := &http.Server{Handler: srv, ErrorLog: log.New(logs, "", 0)}
	go func() { _ = httpSrv.Serve(ln) }()

	conn := connectThrough(t, ln.Addr().String(), target)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "hello")
	// Туннель закроется, когда прокси кончатся.
	_, _ = io.ReadAll(conn)

	time.Sleep(100 * time.Millisecond) // лог паники пишется после закрытия
	if strings.Contains(logs.String(), "panic") {
		t.Fatalf("паника в обработчике туннеля:\n%s", logs.String())
	}
}

// blockingConn — соединение, запись в которое висит, пока его не
// отпустят: так ведёт себя апстрим, переставший читать.
type blockingConn struct {
	net.Conn
	release chan struct{}
	writes  atomic.Int64
}

func (c *blockingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	<-c.release
	return len(p), nil
}

// TestTunnelHeadSealDoesNotWaitForWrite — запись в апстрим, который
// перестал читать, раньше держала замок, и seal вставал вместе с ней:
// туннель висел ещё до того, как запускался таймер простоя.
func TestTunnelHeadSealDoesNotWaitForWrite(t *testing.T) {
	dst := &blockingConn{release: make(chan struct{})}
	defer close(dst.release)
	var activity atomic.Int64
	head := &tunnelHead{dst: dst, activity: &activity}

	go func() { _ = head.write([]byte("upload")) }()
	waitFor(t, time.Second, "запись так и не началась", func() bool { return dst.writes.Load() == 1 })

	sealed := make(chan struct{})
	go func() {
		head.seal()
		close(sealed)
	}()
	select {
	case <-sealed:
	case <-time.After(time.Second):
		t.Fatal("seal ждёт зависшую запись в апстрим")
	}
}

// recordingConn запоминает, закрыта ли его передающая половина.
type recordingConn struct {
	net.Conn
	mu        sync.Mutex
	got       []byte
	writeDone bool
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, p...)
	return len(p), nil
}

func (c *recordingConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDone = true
	return nil
}

// TestTunnelHeadReplaysClientEOF — клиент прислал запрос и закрыл свою
// сторону. При повторе через другой прокси новое соединение должно
// получить и данные, и EOF, иначе цель ждала бы продолжения до таймаута.
func TestTunnelHeadReplaysClientEOF(t *testing.T) {
	var activity atomic.Int64
	first := &recordingConn{}
	head := &tunnelHead{dst: first, activity: &activity}
	_ = head.write([]byte("GET / HTTP/1.0\r\n\r\n"))
	head.closeWrite()

	second := &recordingConn{}
	if err := head.switchTo(second); err != nil {
		t.Fatal(err)
	}
	if string(second.got) != "GET / HTTP/1.0\r\n\r\n" || !second.writeDone {
		t.Errorf("новое соединение: данные %q, EOF %v", second.got, second.writeDone)
	}
}

// TestMITMIdleConnectionIsClosed — расшифрованное соединение, в котором
// клиент давно ничего не шлёт, закрывается, как и прозрачный туннель:
// оно держит маршрут — слот рабочего набора домена и соединение у прокси.
func TestMITMIdleConnectionIsClosed(t *testing.T) {
	h := newMITMHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	h.srv.IdleTimeout = 300 * time.Millisecond
	var released atomic.Int64
	direct, _ := ParseUpstream("direct")
	h.srv.Pick = func(string, []string) (*Route, error) {
		return &Route{Upstream: direct, Name: "direct", MITM: true, Release: func() { released.Add(1) }}, nil
	}

	resp, err := h.client.Get(h.target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// Клиент держит соединение открытым (keep-alive) и молчит.
	waitFor(t, 3*time.Second, "простаивающее соединение не закрыто, маршрут не освобождён", func() bool {
		return released.Load() == 1
	})
}
