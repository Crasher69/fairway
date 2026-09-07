package stats

import (
	"errors"
	"sync"
	"testing"
	"time"

	"fairway/internal/forward"
)

func sample(domain, proxy string) forward.Sample {
	return forward.Sample{
		Domain:   domain,
		Upstream: proxy,
		Connect:  10 * time.Millisecond,
		TTFB:     20 * time.Millisecond,
		Duration: time.Second,
		Bytes:    100_000,
		Status:   200,
	}
}

func TestRingKeepsLastEvents(t *testing.T) {
	r := New(3)
	for i := 0; i < 5; i++ {
		s := sample("example.com", "p")
		s.Status = 200 + i
		r.Observe(s)
	}

	got := r.Recent("", 10)
	if len(got) != 3 {
		t.Fatalf("в кольце %d событий, вместимость 3", len(got))
	}
	// Новые первыми, старые вытеснены.
	for i, want := range []int{204, 203, 202} {
		if got[i].Status != want {
			t.Errorf("событие %d: статус %d, ожидался %d", i, got[i].Status, want)
		}
	}
	if r.Total() != 5 {
		t.Errorf("Total = %d, ожидалось 5", r.Total())
	}
}

func TestRecentFiltersByDomain(t *testing.T) {
	r := New(10)
	r.Observe(sample("a.com", "p1"))
	r.Observe(sample("b.com", "p2"))
	r.Observe(sample("a.com", "p3"))

	got := r.Recent("a.com", 10)
	if len(got) != 2 {
		t.Fatalf("событий домена: %d, ожидалось 2", len(got))
	}
	for _, e := range got {
		if e.Domain != "a.com" {
			t.Errorf("в выборку попал домен %s", e.Domain)
		}
	}
}

func TestRecentOnEmptyRing(t *testing.T) {
	r := New(10)
	if got := r.Recent("", 10); len(got) != 0 {
		t.Errorf("на пустом кольце вернулось %d событий", len(got))
	}
}

func TestErrorIsRecorded(t *testing.T) {
	r := New(10)
	s := sample("a.com", "p")
	s.Err = errors.New("таймаут")
	r.Observe(s)

	got := r.Recent("", 1)
	if len(got) != 1 || got[0].Error != "таймаут" {
		t.Errorf("ошибка не сохранена: %+v", got)
	}
}

func TestSinceCutsOldEvents(t *testing.T) {
	r := New(10)
	r.Observe(sample("a.com", "p"))

	if got := r.Since("a.com", time.Minute); len(got) != 1 {
		t.Errorf("свежее событие не попало в окно: %d", len(got))
	}
	// Окно меряем миллисекундами, а не наносекундами: на Windows шаг таймера
	// крупный, и наносекундное окно проверяло бы часы, а не код.
	time.Sleep(20 * time.Millisecond)
	if got := r.Since("a.com", 5*time.Millisecond); len(got) != 0 {
		t.Errorf("в окно 5 мс попало %d событий, хотя прошло 20 мс", len(got))
	}
}

func TestSubscribeReceivesEvents(t *testing.T) {
	r := New(10)
	events, unsubscribe := r.Subscribe()
	defer unsubscribe()

	r.Observe(sample("a.com", "p"))

	select {
	case e := <-events:
		if e.Domain != "a.com" {
			t.Errorf("пришло событие домена %s", e.Domain)
		}
	case <-time.After(time.Second):
		t.Fatal("подписчик не получил событие")
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	r := New(10)
	_, unsubscribe := r.Subscribe()
	if r.Subscribers() != 1 {
		t.Fatalf("подписчиков: %d", r.Subscribers())
	}
	unsubscribe()
	if r.Subscribers() != 0 {
		t.Errorf("после отписки осталось %d подписчиков", r.Subscribers())
	}
	unsubscribe() // повторная отписка не должна ломаться
}

// TestSlowSubscriberDoesNotBlock — рассылка обязана быть неблокирующей,
// иначе один зависший читатель остановил бы проксирование целиком.
func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	r := New(10)
	_, unsubscribe := r.Subscribe() // никто не читает
	defer unsubscribe()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			r.Observe(sample("a.com", "p"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("запись событий заблокировалась на медленном подписчике")
	}
}

// TestConcurrentObserveAndUnsubscribe ловит гонку, из-за которой рассылка
// могла писать в уже закрытый канал: это паника, а не просто потеря события.
func TestConcurrentObserveAndUnsubscribe(t *testing.T) {
	r := New(100)
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Observe(sample("a.com", "p"))
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				events, unsubscribe := r.Subscribe()
				select {
				case <-events:
				default:
				}
				unsubscribe()
			}
		}()
	}
	wg.Wait()

	if r.Subscribers() != 0 {
		t.Errorf("после всех отписок осталось %d подписчиков", r.Subscribers())
	}
}
