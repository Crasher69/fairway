package rating

import (
	"math"
	"strconv"
	"sync"
	"time"
)

// Настройки рейтинга. Вынесены в константы, чтобы их было где крутить,
// когда появится реальная статистика с боевых прокси.
const (
	// defaultAlpha — вес свежего замера в EWMA.
	defaultAlpha = 0.25

	// minSamples — пока замеров меньше, прокси считается непроверенным
	// и получает приоритет в ротации (холодный старт).
	minSamples = 3

	// throughputMinBytes — ответы мельче игнорируются при замере скорости:
	// тело приходит вместе с первым байтом, знаменатель вырождается и
	// скорость скачет от нуля до мегабайт в секунду.
	throughputMinBytes = 32 * 1024

	// refBytes — эталонный размер ответа, на котором сравниваются прокси.
	// Задержка и скорость сводятся к одному числу: сколько секунд заняла бы
	// отдача такого объёма.
	refBytes = 64 * 1024

	// failsBeforeBan — столько подряд ошибок соединения выводят прокси
	// из ротации: дохлый прокси не должен получать запросы каждый раунд.
	failsBeforeBan = 3

	// slowThroughput — подстраховка, когда скорость ещё не измерена:
	// 256 КБ/с, чтобы неизвестная скорость не выглядела бесконечной.
	slowThroughput = 256 * 1024
)

// Stats — накопленное качество одной пары (домен, прокси).
type Stats struct {
	mu sync.Mutex

	connect    EWMA // мс до установленного соединения с целью
	ttfb       EWMA // мс до первого байта ответа
	throughput EWMA // байт/с на ответах крупнее throughputMinBytes
	errorRate  EWMA // доля неудач, 0..1

	requests int64
	errors   int64
	bans     int64

	consecutiveFails int
	bannedUntil      time.Time
	banReason        string
	lastUsed         time.Time
}

func newStats() *Stats {
	return &Stats{
		connect:    NewEWMA(defaultAlpha),
		ttfb:       NewEWMA(defaultAlpha),
		throughput: NewEWMA(defaultAlpha),
		errorRate:  NewEWMA(defaultAlpha),
	}
}

// observation — то, что рейтинг берёт из замера запроса.
type observation struct {
	connect    time.Duration
	ttfb       time.Duration
	bytes      int64
	throughput float64
	status     int
	failed     bool
	reused     bool // соединение переиспользовано: connect не измерялся
	at         time.Time
}

// add обновляет статистику и, если нужно, отправляет прокси в бан.
// Возвращает причину бана, если он только что случился.
func (s *Stats) add(o observation, banFor time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests++
	s.lastUsed = o.at

	if o.failed {
		s.errors++
		s.errorRate.Add(1)
		s.consecutiveFails++
		// Соединение не установилось — по нему нельзя судить о скорости,
		// поэтому connect/ttfb не трогаем, чтобы не портить среднее.
		if s.consecutiveFails >= failsBeforeBan {
			return s.banLocked(o.at, banFor, "подряд ошибок: "+strconv.Itoa(s.consecutiveFails))
		}
		return ""
	}

	s.consecutiveFails = 0
	s.errorRate.Add(0)
	// На keep-alive соединении установки не было — ноль сюда добавлять нельзя,
	// иначе среднее времени подключения уедет в пол.
	if !o.reused {
		s.connect.Add(float64(o.connect.Microseconds()) / 1000)
	}
	s.ttfb.Add(float64(o.ttfb.Microseconds()) / 1000)
	if o.bytes >= throughputMinBytes && o.throughput > 0 {
		s.throughput.Add(o.throughput)
	}

	if reason := banReasonForStatus(o.status); reason != "" {
		return s.banLocked(o.at, banFor, reason)
	}
	return ""
}

// banReasonForStatus отличает «прокси мёртв для этого домена» от «медленно».
// Это разные вещи: медленный прокси остаётся в ротации с низким весом,
// забаненный выключается целиком, но только для этого домена.
func banReasonForStatus(status int) string {
	switch status {
	case 403:
		return "403 — доступ запрещён"
	case 429:
		return "429 — слишком много запросов"
	case 451:
		return "451 — заблокировано по требованию"
	case 407:
		return "407 — прокси не принял авторизацию"
	}
	return ""
}

func (s *Stats) banLocked(now time.Time, d time.Duration, reason string) string {
	if d <= 0 {
		return ""
	}
	s.bannedUntil = now.Add(d)
	s.banReason = reason
	s.bans++
	return reason
}

// Banned сообщает, выключен ли прокси для домена прямо сейчас.
func (s *Stats) Banned(now time.Time) (bool, time.Time, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.bannedUntil) {
		return true, s.bannedUntil, s.banReason
	}
	return false, time.Time{}, ""
}

// Samples — сколько успешных замеров накоплено.
//
// Считается по TTFB, а не по времени подключения: на keep-alive соединении
// установки нет, и по connect прокси навсегда остался бы «непроверенным».
func (s *Stats) Samples() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ttfb.Count()
}

// Cost — ожидаемое время (в секундах) на отдачу эталонного ответа через этот
// прокси. Именно по нему сравниваются прокси: одно число, в котором учтены
// и задержка, и скорость, и доля ошибок. Чем меньше, тем лучше.
func (s *Stats) Cost() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.costLocked()
}

func (s *Stats) costLocked() float64 {
	latency := (s.connect.Value() + s.ttfb.Value()) / 1000 // мс -> с

	speed := s.throughput.Value()
	if s.throughput.Count() == 0 || speed <= 0 {
		speed = slowThroughput
	}
	cost := latency + refBytes/speed

	// Ошибки дороже медленности: неудачный запрос придётся повторять,
	// поэтому цена растёт нелинейно и при errorRate → 1 уходит в потолок.
	errRate := math.Min(math.Max(s.errorRate.Value(), 0), 0.99)
	cost /= (1 - errRate) * (1 - errRate)

	if cost <= 0 || math.IsNaN(cost) || math.IsInf(cost, 0) {
		return math.MaxFloat64
	}
	return cost
}

// Snapshot — копия состояния без блокировок, для админки и сохранения на диск.
type Snapshot struct {
	ConnectMS   float64   `json:"connect_ms"`
	TTFBMS      float64   `json:"ttfb_ms"`
	Throughput  float64   `json:"throughput"`
	ErrorRate   float64   `json:"error_rate"`
	Samples     int       `json:"samples"`
	Requests    int64     `json:"requests"`
	Errors      int64     `json:"errors"`
	Bans        int64     `json:"bans"`
	Cost        float64   `json:"cost"`
	BannedUntil time.Time `json:"banned_until,omitempty"`
	BanReason   string    `json:"ban_reason,omitempty"`
	LastUsed    time.Time `json:"last_used,omitempty"`
}

// Snapshot снимает состояние пары (домен, прокси).
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		ConnectMS:   s.connect.Value(),
		TTFBMS:      s.ttfb.Value(),
		Throughput:  s.throughput.Value(),
		ErrorRate:   s.errorRate.Value(),
		Samples:     s.ttfb.Count(),
		Requests:    s.requests,
		Errors:      s.errors,
		Bans:        s.bans,
		Cost:        s.costLocked(),
		BannedUntil: s.bannedUntil,
		BanReason:   s.banReason,
		LastUsed:    s.lastUsed,
	}
}

// restore поднимает состояние из снапшота, снятого прошлым запуском.
func (s *Stats) restore(snap Snapshot, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	seed := func(e *EWMA, v float64, count int) {
		if count <= 0 {
			return
		}
		e.value = v
		e.count = count
	}
	seed(&s.connect, snap.ConnectMS, snap.Samples)
	seed(&s.ttfb, snap.TTFBMS, snap.Samples)
	seed(&s.errorRate, snap.ErrorRate, snap.Samples)
	if snap.Throughput > 0 {
		seed(&s.throughput, snap.Throughput, snap.Samples)
	}
	s.requests = snap.Requests
	s.errors = snap.Errors
	s.bans = snap.Bans
	s.lastUsed = snap.LastUsed
	// Протухший бан не восстанавливаем: за время простоя всё могло измениться.
	if now.Before(snap.BannedUntil) {
		s.bannedUntil = snap.BannedUntil
		s.banReason = snap.BanReason
	}
}
