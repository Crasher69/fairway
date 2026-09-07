package proxypool

import (
	"sort"
	"strings"
	"time"

	"mitm/internal/config"
)

// Rule — правило, применённое к конкретному домену: лимиты уже нормализованы
// (0 означает «без ограничения»), значения унаследованы из defaults.
type Rule struct {
	Pattern            string
	List               string
	MaxParallelProxies int
	MaxConnsPerProxy   int
	MITM               bool
	BanDuration        time.Duration
}

// ruleSet — скомпилированные правила: точные имена, wildcard-суффиксы и
// правило по умолчанию. Матчинг идёт от частного к общему.
type ruleSet struct {
	exact     map[string]Rule
	wildcards []wildcardRule // отсортированы по длине суффикса, длинные первыми
	catchAll  *Rule          // паттерн "*"
	fallback  *Rule          // defaults, если в нём указан лист
}

type wildcardRule struct {
	suffix string // ".example.com"
	rule   Rule
}

func compileRules(cfg *config.Config) *ruleSet {
	rs := &ruleSet{exact: make(map[string]Rule, len(cfg.Domains))}
	d := cfg.Defaults

	for _, dom := range cfg.Domains {
		r := Rule{
			Pattern:            dom.Pattern,
			List:               dom.List,
			MaxParallelProxies: inheritLimit(dom.MaxParallelProxies, d.MaxParallelProxies),
			MaxConnsPerProxy:   inheritLimit(dom.MaxConnsPerProxy, d.MaxConnsPerProxy),
			MITM:               d.MITM,
			BanDuration:        dom.BanDuration.Duration(),
		}
		if dom.MITM != nil {
			r.MITM = *dom.MITM
		}
		if r.BanDuration == 0 {
			r.BanDuration = d.BanDuration.Duration()
		}

		switch {
		case dom.Pattern == "*":
			catch := r
			rs.catchAll = &catch
		case strings.HasPrefix(dom.Pattern, "*."):
			rs.wildcards = append(rs.wildcards, wildcardRule{suffix: dom.Pattern[1:], rule: r})
		default:
			rs.exact[strings.ToLower(dom.Pattern)] = r
		}
	}

	// Длинный суффикс — более частное правило, поэтому проверяется раньше:
	// "*.cdn.example.com" должен выигрывать у "*.example.com".
	sort.Slice(rs.wildcards, func(i, j int) bool {
		return len(rs.wildcards[i].suffix) > len(rs.wildcards[j].suffix)
	})

	if d.List != "" {
		rs.fallback = &Rule{
			Pattern:            "(defaults)",
			List:               d.List,
			MaxParallelProxies: normalizeLimit(d.MaxParallelProxies),
			MaxConnsPerProxy:   normalizeLimit(d.MaxConnsPerProxy),
			MITM:               d.MITM,
			BanDuration:        d.BanDuration.Duration(),
		}
	}
	return rs
}

// match подбирает правило: точное совпадение → самый длинный wildcard →
// "*" → defaults. Второе значение false, если правила нет вовсе.
func (rs *ruleSet) match(domain string) (Rule, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if r, ok := rs.exact[domain]; ok {
		return r, true
	}
	for _, w := range rs.wildcards {
		if strings.HasSuffix(domain, w.suffix) {
			return w.rule, true
		}
	}
	if rs.catchAll != nil {
		return *rs.catchAll, true
	}
	if rs.fallback != nil {
		return *rs.fallback, true
	}
	return Rule{}, false
}

// inheritLimit: 0 — взять из defaults, -1 — явно без ограничения.
func inheritLimit(v, def int) int {
	if v == 0 {
		return normalizeLimit(def)
	}
	return normalizeLimit(v)
}

// normalizeLimit приводит «без ограничения» к нулю, удобному для проверок.
func normalizeLimit(v int) int {
	if v < 0 {
		return 0
	}
	return v
}
