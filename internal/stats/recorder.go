// Package stats — живая история запросов: кольцевой буфер последних событий
// и подписка на поток для админки.
//
// Всё держится в памяти и намеренно ограничено по размеру: это витрина для
// глаз оператора, а не хранилище. Долговременные выводы делает рейтинг.
package stats

import (
	"sync"
	"time"

	"fairway/internal/forward"
)

// DefaultCapacity — сколько последних запросов помним.
const DefaultCapacity = 5000

// Event — одна строка живого лога.
type Event struct {
	At        time.Time `json:"at"`
	Domain    string    `json:"domain"`
	Proxy     string    `json:"proxy"`
	Status    int       `json:"status"`
	ConnectMS float64   `json:"connect_ms"`
	TTFBMS    float64   `json:"ttfb_ms"`
	TotalMS   float64   `json:"total_ms"`
	Bytes     int64     `json:"bytes"`
	Speed     float64   `json:"speed"`
	Reused    bool      `json:"reused"`
	Error     string    `json:"error,omitempty"`
	Challenge string    `json:"challenge,omitempty"`
}

// Recorder хранит последние события и рассылает их подписчикам.
type Recorder struct {
	mu       sync.RWMutex
	ring     []Event
	next     int
	filled   bool
	total    uint64
	subs     map[int]chan Event
	nextSub  int
	capacity int
}

// New создаёт запись на capacity событий (0 — значение по умолчанию).
func New(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Recorder{
		ring:     make([]Event, capacity),
		subs:     make(map[int]chan Event),
		capacity: capacity,
	}
}

// Observe принимает замер запроса. Вызывается на горячем пути, поэтому
// делает минимум: одну запись в кольцо и неблокирующую рассылку.
func (r *Recorder) Observe(s forward.Sample) {
	event := Event{
		At:        time.Now(),
		Domain:    s.Domain,
		Proxy:     s.Upstream,
		Status:    s.Status,
		ConnectMS: msOf(s.Connect),
		TTFBMS:    msOf(s.TTFB),
		TotalMS:   msOf(s.Duration),
		Bytes:     s.Bytes,
		Speed:     s.Throughput(),
		Reused:    s.Reused,
		Challenge: s.Challenge,
	}
	if s.Err != nil {
		event.Error = s.Err.Error()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.ring[r.next] = event
	r.next = (r.next + 1) % r.capacity
	if r.next == 0 {
		r.filled = true
	}
	r.total++

	// Рассылка идёт под тем же замком, что и отписка: иначе подписчик успел бы
	// закрыть канал между снятием замка и отправкой, а это паника.
	// Отправка неблокирующая, поэтому замок держится ровно один проход по карте:
	// медленный подписчик пропустит событие, а не затормозит проксирование.
	for _, ch := range r.subs {
		select {
		case ch <- event:
		default:
		}
	}
}

// Recent возвращает последние события, новые первыми.
// Пустой domain — по всем доменам.
func (r *Recorder) Recent(domain string, limit int) []Event {
	if limit <= 0 {
		limit = 100
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Event, 0, limit)
	count := r.capacity
	if !r.filled {
		count = r.next
	}
	for i := 0; i < count && len(out) < limit; i++ {
		idx := (r.next - 1 - i + r.capacity*2) % r.capacity
		event := r.ring[idx]
		if event.At.IsZero() {
			continue
		}
		if domain != "" && event.Domain != domain {
			continue
		}
		out = append(out, event)
	}
	return out
}

// Since возвращает события домена за последний период, старые первыми —
// в таком виде их удобно рисовать на графике.
func (r *Recorder) Since(domain string, window time.Duration) []Event {
	cutoff := time.Now().Add(-window)
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := r.capacity
	if !r.filled {
		count = r.next
	}
	out := make([]Event, 0, 256)
	for i := count - 1; i >= 0; i-- {
		idx := (r.next - 1 - i + r.capacity*2) % r.capacity
		event := r.ring[idx]
		if event.At.IsZero() || event.At.Before(cutoff) {
			continue
		}
		if domain != "" && event.Domain != domain {
			continue
		}
		out = append(out, event)
	}
	return out
}

// Total — сколько запросов прошло через прокси с момента запуска.
func (r *Recorder) Total() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.total
}

// Subscribe открывает поток событий. Вызов возвращённой функции обязателен,
// иначе канал останется в рассылке навсегда.
func (r *Recorder) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)

	r.mu.Lock()
	id := r.nextSub
	r.nextSub++
	r.subs[id] = ch
	r.mu.Unlock()

	// Отписка идемпотентна: её принято ставить в defer и вызывать явно,
	// а повторное закрытие канала — паника.
	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, ok := r.subs[id]; !ok {
			return
		}
		delete(r.subs, id)
		close(ch)
	}
}

// Subscribers — сколько сейчас открытых потоков (для диагностики).
func (r *Recorder) Subscribers() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.subs)
}

func msOf(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
