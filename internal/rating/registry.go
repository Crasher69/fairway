package rating

import (
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"mitm/internal/forward"
	"mitm/internal/proxypool"
)

// DefaultEpsilon — доля запросов, уходящих на разведку вместо лучшего прокси.
//
// Без разведки система слепнет: победитель забирает весь трафик, а о том,
// что аутсайдер починился (или что лидер деградировал под нагрузкой), узнать
// становится неоткуда.
const DefaultEpsilon = 0.1

// DefaultSharpness — степень, в которую возводится обратная цена при выборе.
// Двойка даёт лидеру уверенное преимущество, но не выключает остальных:
// прокси вдвое дешевле получает вчетверо больше трафика.
const DefaultSharpness = 2

// Registry — рейтинги всех пар (домен, прокси).
type Registry struct {
	// Epsilon — доля разведочных запросов. 0 означает DefaultEpsilon.
	Epsilon float64
	// Sharpness — насколько резко преимущество в цене превращается в долю
	// трафика: вес прокси = (1/цена)^Sharpness. При 1 прокси вдвое дешевле
	// получит лишь вдвое больше запросов, и заметная доля трафика будет уходить
	// аутсайдерам. 0 означает DefaultSharpness.
	Sharpness float64
	// BanDuration отдаёт срок бана для домена (обычно из правила конфига).
	// Если nil или возвращает 0, баны не выставляются.
	BanDuration func(domain string) time.Duration
	// OnBan вызывается, когда прокси выключается для домена. Может быть nil.
	OnBan func(domain, proxy, reason string, until time.Time)
	// Now подменяется в тестах.
	Now func() time.Time
	// Rand подменяется в тестах, чтобы выбор был воспроизводим.
	Rand func() float64

	mu       sync.RWMutex
	byDomain map[string]map[string]*Stats
}

// NewRegistry создаёт пустой реестр.
func NewRegistry() *Registry {
	return &Registry{byDomain: make(map[string]map[string]*Stats)}
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Registry) random() float64 {
	if r.Rand != nil {
		return r.Rand()
	}
	return rand.Float64()
}

func (r *Registry) sharpness() float64 {
	if r.Sharpness > 0 {
		return r.Sharpness
	}
	return DefaultSharpness
}

func (r *Registry) epsilon() float64 {
	if r.Epsilon > 0 {
		return r.Epsilon
	}
	return DefaultEpsilon
}

// Stats возвращает статистику пары, создавая её при необходимости.
func (r *Registry) Stats(domain, proxy string) *Stats {
	r.mu.RLock()
	if byProxy, ok := r.byDomain[domain]; ok {
		if s, ok := byProxy[proxy]; ok {
			r.mu.RUnlock()
			return s
		}
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	byProxy, ok := r.byDomain[domain]
	if !ok {
		byProxy = make(map[string]*Stats)
		r.byDomain[domain] = byProxy
	}
	s, ok := byProxy[proxy]
	if !ok {
		s = newStats()
		byProxy[proxy] = s
	}
	return s
}

// Observe скармливает рейтингу замер завершённого запроса.
func (r *Registry) Observe(sample forward.Sample) {
	if sample.Domain == "" || sample.Upstream == "" {
		return
	}
	now := r.now()
	stats := r.Stats(sample.Domain, sample.Upstream)

	var banFor time.Duration
	if r.BanDuration != nil {
		banFor = r.BanDuration(sample.Domain)
	}

	reason := stats.add(observation{
		connect:    sample.Connect,
		ttfb:       sample.TTFB,
		bytes:      sample.Bytes,
		throughput: sample.Throughput(),
		status:     sample.Status,
		failed:     sample.Err != nil,
		at:         now,
	}, banFor)

	if reason != "" && r.OnBan != nil {
		_, until, _ := stats.Banned(now)
		r.OnBan(sample.Domain, sample.Upstream, reason, until)
	}
}

// Select — стратегия выбора прокси для пула (proxypool.Selector).
//
// Порядок такой:
//  1. забаненные для домена исключаются целиком;
//  2. непроверенные (замеров меньше minSamples) идут первыми — иначе
//     новый прокси никогда не наберёт статистику и останется невидимым;
//  3. с вероятностью Epsilon — случайный из оставшихся (разведка);
//  4. иначе — взвешенный случайный выбор с весом (1/цена)^Sharpness.
//
// Взвешенный случайный, а не «всегда лучший»: постоянный победитель забрал бы
// весь трафик, упёрся в лимит соединений и деградировал, а его замеры перестали
// бы отражать реальность.
func (r *Registry) Select(domain string, candidates []*proxypool.Proxy) *proxypool.Proxy {
	if len(candidates) == 0 {
		return nil
	}
	now := r.now()

	alive := make([]*proxypool.Proxy, 0, len(candidates))
	fresh := make([]*proxypool.Proxy, 0, len(candidates))
	for _, c := range candidates {
		stats := r.Stats(domain, c.Name)
		if banned, _, _ := stats.Banned(now); banned {
			continue
		}
		alive = append(alive, c)
		if stats.Samples() < minSamples {
			fresh = append(fresh, c)
		}
	}
	// Все забанены — пусть пул решает, что с этим делать.
	if len(alive) == 0 {
		return nil
	}
	if len(fresh) > 0 {
		return fresh[r.intn(len(fresh))]
	}
	if r.random() < r.epsilon() {
		return alive[r.intn(len(alive))]
	}

	weights := make([]float64, len(alive))
	var total float64
	for i, c := range alive {
		cost := r.Stats(domain, c.Name).Cost()
		if cost <= 0 || math.IsNaN(cost) || math.IsInf(cost, 0) {
			continue // цена не определена — в лотерее не участвует
		}
		weights[i] = math.Pow(1/cost, r.sharpness())
		total += weights[i]
	}
	if total <= 0 {
		return alive[r.intn(len(alive))]
	}

	point := r.random() * total
	for i, w := range weights {
		point -= w
		if point <= 0 {
			return alive[i]
		}
	}
	return alive[len(alive)-1]
}

func (r *Registry) intn(n int) int {
	if n <= 1 {
		return 0
	}
	idx := int(r.random() * float64(n))
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// DomainSnapshot — состояние всех прокси одного домена, для админки.
type DomainSnapshot struct {
	Domain  string              `json:"domain"`
	Proxies map[string]Snapshot `json:"proxies"`
}

// Snapshot отдаёт состояние одного домена.
func (r *Registry) Snapshot(domain string) DomainSnapshot {
	r.mu.RLock()
	byProxy := r.byDomain[domain]
	names := make([]string, 0, len(byProxy))
	stats := make([]*Stats, 0, len(byProxy))
	for name, s := range byProxy {
		names = append(names, name)
		stats = append(stats, s)
	}
	r.mu.RUnlock()

	out := DomainSnapshot{Domain: domain, Proxies: make(map[string]Snapshot, len(names))}
	for i, name := range names {
		out.Proxies[name] = stats[i].Snapshot()
	}
	return out
}

// Domains перечисляет домены, по которым есть статистика.
func (r *Registry) Domains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byDomain))
	for d := range r.byDomain {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
