package proxypool

import (
	"slices"
	"sync"
)

// domainState — живое состояние одного домена: сколько соединений сейчас
// держит каждый прокси именно на этом домене. Отсюда работает лимит
// max_parallel_proxies (сколько РАЗНЫХ прокси домен использует одновременно).
type domainState struct {
	domain string

	mu     sync.Mutex
	active map[string]int // имя прокси -> активных соединений на этом домене
	rr     uint64         // курсор round-robin, пока нет рейтинга
}

// pick отбирает кандидатов по лимитам и выбирает одного.
// Возвращает nil, если свободных прокси нет.
//
// avoid — прокси, через которые этот запрос уже не прошёл; они выбывают
// до всех остальных проверок, как и забаненные внутри стратегии.
func (s *domainState) pick(members []*Proxy, rule Rule, sel Selector, avoid []string) *Proxy {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidates := make([]Candidate, 0, len(members))
	inUse := 0
	for _, m := range members {
		if s.active[m.Name] > 0 {
			inUse++
		}
		if rule.MaxConnsPerProxy > 0 && int(m.Active()) >= rule.MaxConnsPerProxy {
			continue
		}
		if slices.Contains(avoid, m.Name) {
			continue
		}
		candidates = append(candidates, Candidate{Proxy: m, InFlight: s.active[m.Name]})
	}

	// Рабочий набор набран — новые прокси в ротацию не пускаем,
	// выбираем только среди тех, что уже работают на этом домене.
	if rule.MaxParallelProxies > 0 && inUse >= rule.MaxParallelProxies {
		narrowed := candidates[:0:0]
		for _, c := range candidates {
			if c.InFlight > 0 {
				narrowed = append(narrowed, c)
			}
		}
		candidates = narrowed
	}
	if len(candidates) == 0 {
		return nil
	}

	// Отказ стратегии — это осмысленный ответ («все забанены»), а не сбой,
	// поэтому подменять его round-robin нельзя: бан перестал бы работать.
	var chosen *Proxy
	if sel != nil {
		chosen = sel(s.domain, candidates)
	} else {
		chosen = candidates[int(s.rr%uint64(len(candidates)))].Proxy
		s.rr++
	}
	if chosen == nil {
		return nil
	}

	s.active[chosen.Name]++
	return chosen
}

func (s *domainState) release(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[name] <= 1 {
		delete(s.active, name) // не копим мёртвые ключи по редким прокси
		return
	}
	s.active[name]--
}

// snapshot — активные соединения по прокси на этом домене (для админки).
func (s *domainState) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.active))
	for k, v := range s.active {
		out[k] = v
	}
	return out
}
