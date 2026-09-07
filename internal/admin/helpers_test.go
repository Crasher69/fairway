package admin

import (
	"context"
	"testing"
	"time"
)

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// waitFor ждёт наступления условия: подписка на поток и её снятие происходят
// в другой горутине, мгновенной проверкой их не поймать.
func waitFor(t *testing.T, limit time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
