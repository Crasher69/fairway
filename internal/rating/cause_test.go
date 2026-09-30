package rating

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// refusedErr — настоящая ошибка отказа с этой ОС: на Windows её текст
// «No connection could be made because the target machine actively
// refused it», и она не равна syscall.ECONNREFUSED.
func refusedErr(t *testing.T) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Skip("порт внезапно занят")
	}
	return fmt.Errorf("connecting to proxy %s: %w", addr, err)
}

func TestFailureCause(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"отказ соединения": {refusedErr(t), "connection refused"},
		"таймаут":          {fmt.Errorf("CONNECT x: %w", os.ErrDeadlineExceeded), "no reply (timeout)"},
		"DNS":              {&net.DNSError{Err: "no such host", Name: "nope.invalid"}, "host not found"},
		"обрыв до ответа":  {fmt.Errorf("reading: %w", io.ErrUnexpectedEOF), "connection closed before a reply"},
		"незнакомая":       {errors.New("CONNECT a via b: upstream answered 502 Bad Gateway"), "upstream answered 502 Bad Gateway"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := failureCause(c.err); got != c.want {
				t.Errorf("failureCause = %q, ожидалось %q (ошибка: %v)", got, c.want, c.err)
			}
		})
	}
}

func TestFailureCauseIsShort(t *testing.T) {
	long := errors.New("context: " + strings.Repeat("очень длинная причина ", 20))
	got := failureCause(long)
	if n := utf8.RuneCountInString(got); n > causeLimit {
		t.Errorf("причина в %d символов длиннее предела %d", n, causeLimit)
	}
	if !utf8.ValidString(got) {
		t.Error("обрезка разрезала символ пополам")
	}
}

// TestBanReasonIsShort — в причину бана попадает суть, а не системный
// текст ошибки целиком: он в таблице панели не читается.
func TestBanReasonIsShort(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	r := deadRegistry(&now)
	stats := r.Stats("example.com", "dead")
	fail := sample("example.com", "dead", 0, 0, 0, 0, refusedErr(t))

	for i := 0; i < failsBeforeBan; i++ {
		r.Observe(fail)
	}
	if _, _, reason := stats.Banned(now); reason != "3 failures in a row: connection refused" {
		t.Errorf("причина первого бана: %q", reason)
	}
	now = now.Add(banLeft(t, stats, now))
	r.Observe(fail)
	if _, _, reason := stats.Banned(now); reason != "failed the check after a ban: connection refused" {
		t.Errorf("причина бана после пробы: %q", reason)
	}
}
