package events

import (
	"testing"
	"time"
)

func receive(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("канал закрыт")
		}
		return e
	case <-time.After(time.Second):
		t.Fatal("событие не пришло")
	}
	return Event{}
}

func TestPublishReachesAllSubscribers(t *testing.T) {
	var bus Bus
	a, unsubA := bus.Subscribe()
	defer unsubA()
	b, unsubB := bus.Subscribe()
	defer unsubB()

	bus.Publish(ConfigApplied, ConfigAppliedData{Proxies: 3})

	for _, ch := range []<-chan Event{a, b} {
		e := receive(t, ch)
		if e.Type != ConfigApplied || e.At.IsZero() {
			t.Fatalf("событие %+v", e)
		}
		if data, ok := e.Data.(ConfigAppliedData); !ok || data.Proxies != 3 {
			t.Fatalf("данные %+v", e.Data)
		}
	}
}

func TestSubscribeFiltersByType(t *testing.T) {
	var bus Bus
	bans, unsub := bus.Subscribe(ProxyBanned)
	defer unsub()

	bus.Publish(ConfigApplied, nil)
	bus.Publish(ProxyBanned, ProxyBannedData{Domain: "example.com", Proxy: "id-1"})

	if e := receive(t, bans); e.Type != ProxyBanned {
		t.Fatalf("пришло %s, ожидался только бан", e.Type)
	}
	select {
	case e := <-bans:
		t.Fatalf("лишнее событие %+v", e)
	default:
	}
}

// Медленный подписчик теряет события, но публикующий не блокируется.
func TestPublishDoesNotBlockOnSlowSubscriber(t *testing.T) {
	var bus Bus
	ch, unsub := bus.Subscribe()
	defer unsub()

	done := make(chan struct{})
	go func() {
		for range subscriberBuffer * 3 {
			bus.Publish(ConfigApplied, nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish заблокировался на медленном подписчике")
	}
	if got := len(ch); got != subscriberBuffer {
		t.Fatalf("в канале %d событий, ожидалось %d", got, subscriberBuffer)
	}
}

func TestUnsubscribeIsIdempotentAndClosesChannel(t *testing.T) {
	var bus Bus
	ch, unsub := bus.Subscribe()
	unsub()
	unsub()
	if _, ok := <-ch; ok {
		t.Fatal("канал не закрыт после отписки")
	}
	if n := bus.Subscribers(); n != 0 {
		t.Fatalf("подписчиков %d", n)
	}
	// После отписки публикация не паникует.
	bus.Publish(ConfigApplied, nil)
}
