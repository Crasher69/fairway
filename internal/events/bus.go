// Package events — шина событий fairway: что поменялось в конфиге, кого
// забанили. Подписчики — панель и плагины.
//
// Это не поток замеров запросов (он в internal/stats и идёт на каждый
// запрос): сюда попадают редкие события о состоянии, по которым имеет смысл
// что-то делать.
package events

import (
	"sync"
	"time"
)

// Type — вид события. Имена в духе «объект.что_случилось»: по ним
// подписываются плагины, так что это часть внешнего API — не переименовывать.
type Type string

const (
	// ConfigApplied — применена новая версия конфига: из панели, правкой
	// файла или плагином. Data — ConfigApplied.
	ConfigApplied Type = "config.applied"
	// ProxyBanned — прокси забанен для домена. Data — ProxyBanned.
	ProxyBanned Type = "proxy.banned"
)

// Event — одно событие шины.
type Event struct {
	Type Type      `json:"type"`
	At   time.Time `json:"at"`
	Data any       `json:"data,omitempty"`
}

// ConfigAppliedData — подробности ConfigApplied.
type ConfigAppliedData struct {
	Proxies int `json:"proxies"`
	Lists   int `json:"lists"`
	Domains int `json:"domains"`
}

// ProxyBannedData — подробности ProxyBanned. Прокси — по id: имя можно
// поменять, id нет.
type ProxyBannedData struct {
	Domain string    `json:"domain"`
	Proxy  string    `json:"proxy"`
	Reason string    `json:"reason"`
	Until  time.Time `json:"until"`
}

// subscriberBuffer — сколько событий подписчик может не забирать, прежде
// чем начнёт их терять. События редкие, запаса хватает с избытком.
const subscriberBuffer = 64

type subscriber struct {
	ch    chan Event
	types map[Type]bool // пусто — все события
}

// Bus рассылает события подписчикам. Нулевое значение готово к работе.
type Bus struct {
	mu      sync.Mutex
	nextSub int
	subs    map[int]*subscriber
}

// Publish рассылает событие. Не блокируется: медленный подписчик пропустит
// событие, а не затормозит того, кто его публикует (бан, например,
// публикуется из рейтинга на пути запроса).
func (b *Bus) Publish(t Type, data any) {
	event := Event{Type: t, At: time.Now(), Data: data}

	// Рассылка под тем же замком, что и отписка: иначе подписчик успел бы
	// закрыть канал между снятием замка и отправкой, а это паника.
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.subs {
		if len(s.types) > 0 && !s.types[t] {
			continue
		}
		select {
		case s.ch <- event:
		default:
		}
	}
}

// Subscribe открывает поток событий указанных видов (без видов — всех).
// Вызов возвращённой функции обязателен, иначе канал останется в рассылке
// навсегда. Отписка идемпотентна.
func (b *Bus) Subscribe(types ...Type) (<-chan Event, func()) {
	s := &subscriber{ch: make(chan Event, subscriberBuffer)}
	if len(types) > 0 {
		s.types = make(map[Type]bool, len(types))
		for _, t := range types {
			s.types[t] = true
		}
	}

	b.mu.Lock()
	if b.subs == nil {
		b.subs = make(map[int]*subscriber)
	}
	id := b.nextSub
	b.nextSub++
	b.subs[id] = s
	b.mu.Unlock()

	return s.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[id]; !ok {
			return
		}
		delete(b.subs, id)
		close(s.ch)
	}
}

// Subscribers — сколько сейчас открытых подписок (для диагностики).
func (b *Bus) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
