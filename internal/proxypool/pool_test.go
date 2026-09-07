package proxypool

import (
	"errors"
	"testing"
	"time"

	"fairway/internal/config"
)

func mustConfig(t *testing.T, raw string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const threeProxies = `{
  "defaults": {"list": "", "allow_direct": false, "ban_duration": "5m"},
  "proxies": [
    {"name": "a", "url": "http://1.1.1.1:8080"},
    {"name": "b", "url": "http://2.2.2.2:8080"},
    {"name": "c", "url": "http://3.3.3.3:8080"}
  ],
  "lists": [{"name": "main", "proxies": ["a", "b", "c"]}],
  "domains": [{"pattern": "example.com", "list": "main"}]
}`

func TestRuleMatchingPrecedence(t *testing.T) {
	cfg := mustConfig(t, `{
	  "defaults": {"list": "l1"},
	  "proxies": [{"name":"p","url":"http://1.1.1.1:80"}],
	  "lists": [{"name":"l1","proxies":["p"]},{"name":"l2","proxies":["p"]},
	            {"name":"l3","proxies":["p"]},{"name":"l4","proxies":["p"]}],
	  "domains": [
	    {"pattern": "shop.example.com", "list": "l2"},
	    {"pattern": "*.example.com", "list": "l3"},
	    {"pattern": "*.cdn.example.com", "list": "l4"},
	    {"pattern": "*", "list": "l1"}
	  ]
	}`)
	rs := compileRules(cfg)

	tests := map[string]string{
		"shop.example.com":     "l2", // точное совпадение важнее wildcard
		"img.cdn.example.com":  "l4", // длинный суффикс важнее короткого
		"api.example.com":      "l3",
		"example.com":          "l1", // "*.example.com" не покрывает сам домен
		"SHOP.EXAMPLE.COM":     "l2", // регистр не важен
		"api.example.com.":     "l3", // точка в конце FQDN отбрасывается
		"совершенно.другое.рф": "l1", // catch-all
	}
	for domain, want := range tests {
		r, ok := rs.match(domain)
		if !ok {
			t.Errorf("%s: правило не подобрано", domain)
			continue
		}
		if r.List != want {
			t.Errorf("%s -> лист %s, ожидался %s", domain, r.List, want)
		}
	}
}

func TestRuleInheritsDefaults(t *testing.T) {
	cfg := mustConfig(t, `{
	  "defaults": {"max_conns_per_proxy": 16, "max_parallel_proxies": 3, "mitm": true, "ban_duration": "5m"},
	  "proxies": [{"name":"p","url":"http://1.1.1.1:80"}],
	  "lists": [{"name":"l","proxies":["p"]}],
	  "domains": [
	    {"pattern": "inherit.com", "list": "l"},
	    {"pattern": "own.com", "list": "l", "max_conns_per_proxy": 2, "mitm": false, "ban_duration": "1m"},
	    {"pattern": "unlimited.com", "list": "l", "max_conns_per_proxy": -1}
	  ]
	}`)
	rs := compileRules(cfg)

	inherit, _ := rs.match("inherit.com")
	if inherit.MaxConnsPerProxy != 16 || inherit.MaxParallelProxies != 3 {
		t.Errorf("лимиты не унаследованы: %+v", inherit)
	}
	if !inherit.MITM {
		t.Error("mitm не унаследован из defaults")
	}
	if inherit.BanDuration != 5*time.Minute {
		t.Errorf("ban_duration = %s, ожидалось 5m", inherit.BanDuration)
	}

	own, _ := rs.match("own.com")
	if own.MaxConnsPerProxy != 2 || own.MITM || own.BanDuration != time.Minute {
		t.Errorf("свои значения домена перебиты значениями defaults: %+v", own)
	}

	unlimited, _ := rs.match("unlimited.com")
	if unlimited.MaxConnsPerProxy != 0 {
		t.Errorf("-1 должен означать «без ограничения» (0 внутри), получено %d", unlimited.MaxConnsPerProxy)
	}
}

func TestAcquireRotatesAndReleases(t *testing.T) {
	pool, err := New(mustConfig(t, threeProxies))
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		lease, err := pool.Acquire("example.com")
		if err != nil {
			t.Fatal(err)
		}
		seen[lease.Proxy.Name]++
		lease.Release()
	}
	if len(seen) != 3 {
		t.Errorf("ротация задействовала %d прокси из 3: %v", len(seen), seen)
	}
	for _, p := range pool.Proxies() {
		if p.Active() != 0 {
			t.Errorf("после Release у %s осталось %d активных", p.Name, p.Active())
		}
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	pool, _ := New(mustConfig(t, threeProxies))
	lease, err := pool.Acquire("example.com")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	lease.Release()
	if got := lease.Proxy.Active(); got != 0 {
		t.Errorf("повторный Release увёл счётчик в %d", got)
	}
}

func TestMaxConnsPerProxy(t *testing.T) {
	pool, _ := New(mustConfig(t, `{
	  "proxies": [{"name":"a","url":"http://1.1.1.1:80"}],
	  "lists": [{"name":"one","proxies":["a"]}],
	  "domains": [{"pattern":"example.com","list":"one","max_conns_per_proxy":2}]
	}`))

	first, err := pool.Acquire("example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Acquire("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire("example.com"); !errors.Is(err, ErrNoProxy) {
		t.Errorf("третье соединение должно упереться в лимит, получено %v", err)
	}
	first.Release()
	if third, err := pool.Acquire("example.com"); err != nil {
		t.Errorf("после освобождения слота ожидался успех: %v", err)
	} else {
		third.Release()
	}
	second.Release()
}

func TestMaxParallelProxies(t *testing.T) {
	pool, _ := New(mustConfig(t, `{
	  "proxies": [
	    {"name":"a","url":"http://1.1.1.1:80"},
	    {"name":"b","url":"http://2.2.2.2:80"},
	    {"name":"c","url":"http://3.3.3.3:80"}
	  ],
	  "lists": [{"name":"main","proxies":["a","b","c"]}],
	  "domains": [{"pattern":"example.com","list":"main","max_parallel_proxies":2}]
	}`))

	// Держим соединения открытыми: третий прокси в ротацию попасть не должен.
	held := make([]*Lease, 0, 4)
	names := map[string]bool{}
	for i := 0; i < 4; i++ {
		lease, err := pool.Acquire("example.com")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, lease)
		names[lease.Proxy.Name] = true
	}
	if len(names) != 2 {
		t.Errorf("одновременно задействовано %d прокси, лимит 2: %v", len(names), names)
	}

	for _, l := range held {
		l.Release()
	}
	// Всё освободилось — рабочий набор снова открыт для любого прокси листа.
	fresh := map[string]bool{}
	for i := 0; i < 6; i++ {
		lease, err := pool.Acquire("example.com")
		if err != nil {
			t.Fatal(err)
		}
		fresh[lease.Proxy.Name] = true
		lease.Release()
	}
	if len(fresh) != 3 {
		t.Errorf("после освобождения в ротацию вернулось %d прокси из 3: %v", len(fresh), fresh)
	}
}

func TestNoRuleWithoutDirect(t *testing.T) {
	pool, _ := New(mustConfig(t, threeProxies))
	if _, err := pool.Acquire("другой.домен"); !errors.Is(err, ErrNoRule) {
		t.Errorf("без правила и без allow_direct ожидался ErrNoRule, получено %v", err)
	}
}

func TestAllowDirectFallback(t *testing.T) {
	pool, _ := New(mustConfig(t, `{"defaults": {"allow_direct": true}}`))
	lease, err := pool.Acquire("любой.домен")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if lease.Proxy.Name != "direct" {
		t.Errorf("ожидался direct, получен %s", lease.Proxy.Name)
	}
}

// TestApplyKeepsLiveProxies — при hot-reload прокси с тем же именем и адресом
// должен остаться тем же объектом, иначе потеряются счётчики и рейтинг.
func TestApplyKeepsLiveProxies(t *testing.T) {
	pool, _ := New(mustConfig(t, threeProxies))
	lease, err := pool.Acquire("example.com")
	if err != nil {
		t.Fatal(err)
	}
	before := lease.Proxy

	updated := mustConfig(t, `{
	  "proxies": [
	    {"name": "a", "url": "http://1.1.1.1:8080"},
	    {"name": "b", "url": "http://9.9.9.9:8080"},
	    {"name": "c", "url": "http://3.3.3.3:8080"}
	  ],
	  "lists": [{"name": "main", "proxies": ["a", "b", "c"]}],
	  "domains": [{"pattern": "example.com", "list": "main"}]
	}`)
	if err := pool.Apply(updated); err != nil {
		t.Fatal(err)
	}

	byName := map[string]*Proxy{}
	for _, p := range pool.Proxies() {
		byName[p.Name] = p
	}
	if byName[before.Name] != before {
		t.Errorf("прокси %s пересоздан, живое состояние потеряно", before.Name)
	}
	if byName["b"].Upstream.Addr != "9.9.9.9:8080" {
		t.Errorf("изменившийся адрес не подхвачен: %s", byName["b"].Upstream.Addr)
	}

	lease.Release()
	if before.Active() != 0 {
		t.Errorf("после Release у %s осталось %d активных", before.Name, before.Active())
	}
}
