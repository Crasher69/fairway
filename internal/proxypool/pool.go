// Package proxypool — реестр прокси и листов, привязка доменов к листам,
// лимиты параллелизма и выбор прокси под конкретный запрос.
package proxypool

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"fairway/internal/config"
	"fairway/internal/forward"
	"fairway/internal/i18n"
)

var (
	// ErrNoRule — для домена не подобрано правило и direct запрещён.
	ErrNoRule = errors.New("no rule for domain")
	// ErrNoProxy — правило есть, но все прокси листа сейчас недоступны
	// (выбраны лимиты параллелизма; позже добавятся баны).
	ErrNoProxy = errors.New("no free proxy")
)

// Proxy — прокси с живым состоянием. Объект переживает перезагрузку конфига:
// пул сопоставляет прокси по имени, чтобы не потерять счётчики и (позже) рейтинг.
type Proxy struct {
	Name     string
	Upstream *forward.Upstream

	active atomic.Int64 // соединений прямо сейчас, по всем доменам
}

// Active — сколько соединений держит прокси прямо сейчас.
func (p *Proxy) Active() int64 { return p.active.Load() }

// Selector выбирает прокси из уже отфильтрованных кандидатов.
// На этапе 3 сюда встанет рейтинг по (домен, прокси); пока round-robin.
type Selector func(domain string, candidates []*Proxy) *Proxy

// Pool — текущее состояние: прокси, листы, правила.
type Pool struct {
	// Select задаёт стратегию выбора. Если nil — round-robin.
	Select Selector

	mu          sync.RWMutex
	proxies     map[string]*Proxy
	lists       map[string][]*Proxy
	rules       *ruleSet
	allowDirect bool
	direct      *Proxy

	states sync.Map // domain string -> *domainState
}

// New создаёт пул из конфига.
func New(cfg *config.Config) (*Pool, error) {
	p := &Pool{proxies: map[string]*Proxy{}, lists: map[string][]*Proxy{}}
	direct, err := forward.ParseUpstream("direct")
	if err != nil {
		return nil, err
	}
	p.direct = &Proxy{Name: "direct", Upstream: direct}
	if err := p.Apply(cfg); err != nil {
		return nil, err
	}
	return p, nil
}

// Apply заменяет конфигурацию пула на лету. Прокси с теми же именами
// сохраняют состояние — активные соединения не теряются при hot-reload.
func (p *Pool) Apply(cfg *config.Config) error {
	proxies := make(map[string]*Proxy, len(cfg.Proxies))

	p.mu.RLock()
	previous := p.proxies
	p.mu.RUnlock()

	for _, pc := range cfg.Proxies {
		up, err := forward.ParseUpstream(pc.ConnectURL())
		if err != nil {
			return i18n.Errorf("proxy %s: %w", pc.Name, err)
		}
		if old, ok := previous[pc.Name]; ok && old.Upstream.Name == up.Name {
			proxies[pc.Name] = old // тот же прокси — сохраняем счётчики
			continue
		}
		proxies[pc.Name] = &Proxy{Name: pc.Name, Upstream: up}
	}

	lists := make(map[string][]*Proxy, len(cfg.Lists))
	for _, lc := range cfg.Lists {
		members := make([]*Proxy, 0, len(lc.Proxies))
		for _, ref := range lc.Proxies {
			pr, ok := proxies[ref]
			if !ok {
				return i18n.Errorf("list %s references unknown proxy %q", lc.Name, ref)
			}
			members = append(members, pr)
		}
		lists[lc.Name] = members
	}

	p.mu.Lock()
	p.proxies = proxies
	p.lists = lists
	p.rules = compileRules(cfg)
	p.allowDirect = cfg.Defaults.AllowDirect
	p.mu.Unlock()

	// Выбывшие апстримы закрывают простаивающие соединения пула: иначе они
	// висели бы до таймаута, а прокси уже вычеркнут из конфига.
	for name, old := range previous {
		if proxies[name] != old {
			old.Upstream.CloseIdle()
		}
	}
	return nil
}

// Lease — выданное на время запроса право использовать прокси.
// Release обязателен, иначе счётчики параллелизма будут течь.
type Lease struct {
	Proxy *Proxy
	Rule  Rule

	pool     *Pool
	domain   string
	released atomic.Bool
}

// Release возвращает прокси в пул. Повторный вызов безвреден.
func (l *Lease) Release() {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	l.Proxy.active.Add(-1)
	if st, ok := l.pool.states.Load(l.domain); ok {
		st.(*domainState).release(l.Proxy.Name)
	}
}

// Acquire подбирает прокси для домена и занимает под него слот.
func (p *Pool) Acquire(domain string) (*Lease, error) {
	p.mu.RLock()
	rules, lists, allowDirect, direct := p.rules, p.lists, p.allowDirect, p.direct
	p.mu.RUnlock()

	rule, ok := rules.match(domain)
	if !ok {
		if !allowDirect {
			return nil, fmt.Errorf("%w: %s", ErrNoRule, domain)
		}
		// Прямое соединение: правил нет, но defaults.allow_direct разрешает.
		direct.active.Add(1)
		return &Lease{Proxy: direct, Rule: Rule{Pattern: "(direct)"}, pool: p, domain: domain}, nil
	}

	members := lists[rule.List]
	if len(members) == 0 {
		return nil, i18n.Errorf("%w: list %s is empty", ErrNoProxy, rule.List)
	}

	st := p.stateFor(domain)
	chosen := st.pick(members, rule, p.selector())
	if chosen == nil {
		return nil, i18n.Errorf("%w: domain %s, list %s", ErrNoProxy, domain, rule.List)
	}
	chosen.active.Add(1)
	return &Lease{Proxy: chosen, Rule: rule, pool: p, domain: domain}, nil
}

func (p *Pool) selector() Selector {
	if p.Select != nil {
		return p.Select
	}
	return nil // domainState сам применит round-robin
}

func (p *Pool) stateFor(domain string) *domainState {
	if st, ok := p.states.Load(domain); ok {
		return st.(*domainState)
	}
	st, _ := p.states.LoadOrStore(domain, &domainState{domain: domain, active: map[string]int{}})
	return st.(*domainState)
}

// Proxies возвращает снимок реестра — для админки и логов.
func (p *Pool) Proxies() []*Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Proxy, 0, len(p.proxies))
	for _, pr := range p.proxies {
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Rule возвращает правило, под которое попадает домен.
func (p *Pool) Rule(domain string) (Rule, bool) {
	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()
	return rules.match(domain)
}
