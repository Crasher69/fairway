// Package config — модель конфигурации: прокси, листы, правила доменов.
// Формат — JSON на диске, перечитывается на лету (см. watch.go).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"mitm/internal/forward"
)

// Config — всё дерево настроек.
type Config struct {
	Defaults Defaults `json:"defaults"`
	Proxies  []Proxy  `json:"proxies"`
	Lists    []List   `json:"lists"`
	Domains  []Domain `json:"domains"`
}

// Defaults — правило для доменов, которые не попали ни под один паттерн.
type Defaults struct {
	// List — лист по умолчанию. Пусто означает «правила нет».
	List string `json:"list"`
	// AllowDirect разрешает ходить напрямую, когда лист не подобран.
	// ВНИМАНИЕ: при этом наружу светится реальный IP машины.
	AllowDirect        bool     `json:"allow_direct"`
	MaxParallelProxies int      `json:"max_parallel_proxies"`
	MaxConnsPerProxy   int      `json:"max_conns_per_proxy"`
	MITM               bool     `json:"mitm"`
	BanDuration        Duration `json:"ban_duration"`
}

// Proxy — один апстрим-прокси.
type Proxy struct {
	Name string   `json:"name"`
	URL  string   `json:"url"` // scheme://user:pass@host:port
	Tags []string `json:"tags,omitempty"`
}

// List — именованный набор прокси.
type List struct {
	Name    string   `json:"name"`
	Proxies []string `json:"proxies"`
}

// Domain — правило для домена: какой лист использовать и как ротировать.
type Domain struct {
	// Pattern — "example.com", "*.example.com" или "*" (все домены).
	Pattern string `json:"pattern"`
	List    string `json:"list"`
	// MaxParallelProxies — сколько РАЗНЫХ прокси листа могут работать
	// на этот домен одновременно. 0 — взять из defaults, -1 — без ограничения.
	MaxParallelProxies int `json:"max_parallel_proxies"`
	// MaxConnsPerProxy — лимит одновременных соединений на один прокси.
	// Не даёт задушить лидера рейтинга. 0 — взять из defaults, -1 — без ограничения.
	MaxConnsPerProxy int `json:"max_conns_per_proxy"`
	// MITM — расшифровывать TLS или пробрасывать туннель как есть.
	// Не задано (null или поля нет) — наследуется из defaults.
	MITM *bool `json:"mitm,omitempty"`
	// BanDuration — на сколько исключать прокси из ротации после бана.
	BanDuration Duration `json:"ban_duration"`
}

// Duration — time.Duration, записанный в JSON строкой: "5m", "1h30m".
type Duration time.Duration

func (d Duration) String() string          { return time.Duration(d).String() }
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("длительность должна быть строкой вида \"5m\": %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("длительность %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Load читает и проверяет конфиг.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse разбирает и проверяет конфиг из памяти.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // опечатка в имени поля не должна молча игнорироваться
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("разбор конфига: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate проверяет ссылочную целостность: имена уникальны, листы и прокси
// существуют, URL разбираются. Конфиг с ошибкой не должен применяться.
func (c *Config) Validate() error {
	proxyNames := make(map[string]bool, len(c.Proxies))
	for i, p := range c.Proxies {
		switch {
		case p.Name == "":
			return fmt.Errorf("proxies[%d]: пустое имя", i)
		case proxyNames[p.Name]:
			return fmt.Errorf("proxies[%d]: имя %q уже занято", i, p.Name)
		}
		if _, err := forward.ParseUpstream(p.URL); err != nil {
			return fmt.Errorf("proxies[%d] (%s): %w", i, p.Name, err)
		}
		proxyNames[p.Name] = true
	}

	listNames := make(map[string]bool, len(c.Lists))
	for i, l := range c.Lists {
		switch {
		case l.Name == "":
			return fmt.Errorf("lists[%d]: пустое имя", i)
		case listNames[l.Name]:
			return fmt.Errorf("lists[%d]: имя %q уже занято", i, l.Name)
		case len(l.Proxies) == 0:
			return fmt.Errorf("lists[%d] (%s): пустой лист", i, l.Name)
		}
		for _, ref := range l.Proxies {
			if !proxyNames[ref] {
				return fmt.Errorf("lists[%d] (%s): нет прокси с именем %q", i, l.Name, ref)
			}
		}
		listNames[l.Name] = true
	}

	patterns := make(map[string]bool, len(c.Domains))
	for i, d := range c.Domains {
		switch {
		case d.Pattern == "":
			return fmt.Errorf("domains[%d]: пустой паттерн", i)
		case patterns[d.Pattern]:
			return fmt.Errorf("domains[%d]: паттерн %q уже описан", i, d.Pattern)
		case d.List == "":
			return fmt.Errorf("domains[%d] (%s): не указан лист", i, d.Pattern)
		case !listNames[d.List]:
			return fmt.Errorf("domains[%d] (%s): нет листа с именем %q", i, d.Pattern, d.List)
		case d.MaxParallelProxies < -1 || d.MaxConnsPerProxy < -1:
			return fmt.Errorf("domains[%d] (%s): лимит меньше -1 бессмыслен (0 — наследовать, -1 — без ограничения)", i, d.Pattern)
		}
		if err := validatePattern(d.Pattern); err != nil {
			return fmt.Errorf("domains[%d]: %w", i, err)
		}
		patterns[d.Pattern] = true
	}

	if c.Defaults.List != "" && !listNames[c.Defaults.List] {
		return fmt.Errorf("defaults: нет листа с именем %q", c.Defaults.List)
	}
	if c.Defaults.MaxParallelProxies < 0 || c.Defaults.MaxConnsPerProxy < 0 {
		return fmt.Errorf("defaults: лимиты не могут быть отрицательными")
	}
	return nil
}

// validatePattern не пускает формы, которые matcher не поддерживает.
func validatePattern(p string) error {
	if p == "*" || !strings.Contains(p, "*") {
		return nil
	}
	if strings.HasPrefix(p, "*.") && !strings.Contains(p[2:], "*") {
		return nil
	}
	return fmt.Errorf("паттерн %q: поддерживаются только \"example.com\", \"*.example.com\" и \"*\"", p)
}

// Example — конфиг, который создаётся при первом запуске.
func Example() *Config {
	return &Config{
		Defaults: Defaults{
			AllowDirect:      true,
			MaxConnsPerProxy: 32,
			BanDuration:      Duration(5 * time.Minute),
		},
		Proxies: []Proxy{},
		Lists:   []List{},
		Domains: []Domain{},
	}
}

// Save записывает конфиг в файл в читаемом виде.
func (c *Config) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
