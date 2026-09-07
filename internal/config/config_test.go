package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const valid = `{
  "defaults": {"list": "ru", "allow_direct": false, "max_conns_per_proxy": 16, "ban_duration": "5m"},
  "proxies": [
    {"name": "p1", "url": "http://user:pass@1.2.3.4:3128"},
    {"name": "p2", "scheme": "socks5", "host": "5.6.7.8", "port": 1080, "country": "RU"}
  ],
  "lists": [{"name": "ru", "proxies": ["p1", "p2"]}],
  "domains": [
    {"pattern": "example.com", "list": "ru", "max_parallel_proxies": 2},
    {"pattern": "*.example.com", "list": "ru", "mitm": true, "ban_duration": "1m"}
  ]
}`

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxies) != 2 || len(cfg.Lists) != 1 || len(cfg.Domains) != 2 {
		t.Fatalf("разобрано не всё: %+v", cfg)
	}
	if cfg.Defaults.BanDuration.Duration() != 5*time.Minute {
		t.Errorf("ban_duration = %s, ожидалось 5m", cfg.Defaults.BanDuration)
	}
	if cfg.Domains[0].MITM != nil {
		t.Error("mitm не задан для example.com — должен остаться nil, чтобы наследоваться")
	}
	if cfg.Domains[1].MITM == nil || !*cfg.Domains[1].MITM {
		t.Error("mitm: true для *.example.com не разобран")
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"неизвестное поле": `{"proxys": []}`,
		"битый JSON":       `{`,
		"дубль прокси": `{"proxies":[{"name":"p","url":"http://1.1.1.1:80"},
		                              {"name":"p","url":"http://2.2.2.2:80"}]}`,
		"пустое имя прокси":   `{"proxies":[{"name":"","url":"http://1.1.1.1:80"}]}`,
		"плохой url":          `{"proxies":[{"name":"p","url":"ftp://1.1.1.1:21"}]}`,
		"лист в никуда":       `{"lists":[{"name":"l","proxies":["нет"]}]}`,
		"пустой лист":         `{"lists":[{"name":"l","proxies":[]}]}`,
		"домен без листа":     `{"domains":[{"pattern":"a.com","list":""}]}`,
		"домен в никуда":      `{"domains":[{"pattern":"a.com","list":"нет"}]}`,
		"defaults в никуда":   `{"defaults":{"list":"нет"}}`,
		"кривой паттерн":      `{"proxies":[{"name":"p","url":"http://1.1.1.1:80"}],"lists":[{"name":"l","proxies":["p"]}],"domains":[{"pattern":"a.*.com","list":"l"}]}`,
		"кривая длительность": `{"defaults":{"ban_duration":"пять минут"}}`,
		"лимит меньше -1":     `{"proxies":[{"name":"p","url":"http://1.1.1.1:80"}],"lists":[{"name":"l","proxies":["p"]}],"domains":[{"pattern":"a.com","list":"l","max_conns_per_proxy":-5}]}`,
	}
	for name, raw := range tests {
		if cfg, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: ожидалась ошибка, получено %+v", name, cfg)
		}
	}
}

func TestUnlimitedIsAllowed(t *testing.T) {
	raw := `{"proxies":[{"name":"p","url":"http://1.1.1.1:80"}],
	         "lists":[{"name":"l","proxies":["p"]}],
	         "domains":[{"pattern":"a.com","list":"l","max_conns_per_proxy":-1}]}`
	if _, err := Parse([]byte(raw)); err != nil {
		t.Errorf("-1 (без ограничения) должен приниматься: %v", err)
	}
}

func TestDurationRoundTrip(t *testing.T) {
	cfg, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"ban_duration":"5m0s"`) {
		t.Errorf("длительность сериализована не строкой: %s", raw)
	}
	again, err := Parse(raw)
	if err != nil {
		t.Fatalf("свой же вывод не разбирается: %v", err)
	}
	if again.Defaults.BanDuration != cfg.Defaults.BanDuration {
		t.Error("длительность не пережила round-trip")
	}
}

func TestSaveLoadExample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Example().Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("сохранённый пример не читается обратно: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "нет.json")); !os.IsNotExist(err) {
		t.Errorf("отсутствие файла должно определяться как IsNotExist, получено %v", err)
	}
}

// TestDefaultsAcceptUnlimited — «без ограничения» должно записываться
// одинаково и в defaults, и в правиле домена.
func TestDefaultsAcceptUnlimited(t *testing.T) {
	raw := `{"defaults": {"max_conns_per_proxy": -1, "max_parallel_proxies": -1}}`
	if _, err := Parse([]byte(raw)); err != nil {
		t.Errorf("-1 в defaults должен приниматься: %v", err)
	}
	if _, err := Parse([]byte(`{"defaults": {"max_conns_per_proxy": -5}}`)); err == nil {
		t.Error("лимит меньше -1 должен отвергаться")
	}
}

// TestSaveOmitsInheritedZeros — ноль в правиле домена значит «взять из
// defaults». Записывать его явным "0s" нельзя: человек прочтёт это как
// «баны выключены» и будет неделю искать, почему прокси не банятся.
func TestSaveOmitsInheritedZeros(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{BanDuration: Duration(2 * time.Minute)},
		Proxies:  []Proxy{{Name: "p", URL: "http://1.1.1.1:80"}},
		Lists:    []List{{Name: "l", Proxies: []string{"p"}}},
		Domains:  []Domain{{Pattern: "a.com", List: "l"}},
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Смотрим только блок domains: в defaults явные нули уместны, это
	// справочный блок, по которому человек и понимает, что вообще бывает.
	text := string(raw)
	domains := text[strings.Index(text, `"domains"`):]
	for _, unwanted := range []string{`"ban_duration"`, `"max_conns_per_proxy"`, `"max_parallel_proxies"`} {
		if strings.Contains(domains, unwanted) {
			t.Errorf("в сохранённом правиле домена появился %s:\n%s", unwanted, domains)
		}
	}
	// И при этом файл по-прежнему читается, а наследование работает.
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Domains[0].BanDuration != 0 || back.Defaults.BanDuration.Duration() != 2*time.Minute {
		t.Errorf("после round-trip: домен %v, defaults %v", back.Domains[0].BanDuration, back.Defaults.BanDuration)
	}
}

// TestProxyURLIsUnpacked — строку целиком можно вставить в url, но в файле
// должен остаться разложенный вид: править по полям в панели удобнее.
func TestProxyURLIsUnpacked(t *testing.T) {
	tests := []struct {
		raw    string
		scheme string
		host   string
		port   int
		login  string
		pass   string
	}{
		{"socks5://bob:secret@1.2.3.4:1080", "socks5", "1.2.3.4", 1080, "bob", "secret"},
		{"http://5.6.7.8:3128", "http", "5.6.7.8", 3128, "", ""},
		{"1.2.3.4:8000", "http", "1.2.3.4", 8000, "", ""},
		{"https://proxy.example.com", "https", "proxy.example.com", 443, "", ""},
	}
	for _, tt := range tests {
		p := Proxy{Name: "p", URL: tt.raw}
		if err := p.Normalize(); err != nil {
			t.Errorf("%s: %v", tt.raw, err)
			continue
		}
		if p.URL != "" {
			t.Errorf("%s: url не очищен", tt.raw)
		}
		if p.Scheme != tt.scheme || p.Host != tt.host || p.Port != tt.port {
			t.Errorf("%s разобран как %s://%s:%d", tt.raw, p.Scheme, p.Host, p.Port)
		}
		if p.Login != tt.login || p.Password != tt.pass {
			t.Errorf("%s: креды %q/%q", tt.raw, p.Login, p.Password)
		}
	}
}

func TestConnectURLRoundTrip(t *testing.T) {
	tests := []Proxy{
		{Scheme: "socks5", Host: "1.2.3.4", Port: 1080, Login: "bob", Password: "secret"},
		{Scheme: "http", Host: "5.6.7.8", Port: 3128},
		{Scheme: "direct"},
	}
	for _, p := range tests {
		back := Proxy{Name: "p", URL: p.ConnectURL()}
		if err := back.Normalize(); err != nil {
			t.Errorf("%+v -> %q: %v", p, p.ConnectURL(), err)
			continue
		}
		if back.Scheme != p.Scheme || back.Host != p.Host || back.Port != p.Port ||
			back.Login != p.Login || back.Password != p.Password {
			t.Errorf("%+v не пережил round-trip: %+v", p, back)
		}
	}
}

func TestProxyValidation(t *testing.T) {
	tests := map[string]string{
		"без адреса":    `{"proxies":[{"name":"p","port":8080}]}`,
		"без порта":     `{"proxies":[{"name":"p","host":"1.2.3.4"}]}`,
		"порт за краем": `{"proxies":[{"name":"p","host":"1.2.3.4","port":70000}]}`,
		"чужая схема":   `{"proxies":[{"name":"p","scheme":"ftp","host":"1.2.3.4","port":21}]}`,
	}
	for name, raw := range tests {
		if cfg, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: ожидалась ошибка, получено %+v", name, cfg.Proxies)
		}
	}
	// Схему можно не указывать — подставится http.
	cfg, err := Parse([]byte(`{"proxies":[{"name":"p","host":"1.2.3.4","port":8080}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[0].Scheme != "http" {
		t.Errorf("схема по умолчанию = %q, ожидалась http", cfg.Proxies[0].Scheme)
	}
}
