package config

import (
	"strings"
	"testing"
)

func TestParseProxyLineFormats(t *testing.T) {
	tests := []struct {
		line   string
		scheme string
		want   Proxy
	}{
		{"1.2.3.4:1080", "http", Proxy{Scheme: "http", Host: "1.2.3.4", Port: 1080}},
		{"1.2.3.4:1080", "socks5", Proxy{Scheme: "socks5", Host: "1.2.3.4", Port: 1080}},
		// Самый ходовой формат прайсов.
		{"1.2.3.4:1080:bob:secret", "socks5",
			Proxy{Scheme: "socks5", Host: "1.2.3.4", Port: 1080, Login: "bob", Password: "secret"}},
		{"bob:secret@1.2.3.4:1080", "http",
			Proxy{Scheme: "http", Host: "1.2.3.4", Port: 1080, Login: "bob", Password: "secret"}},
		// Схема в строке важнее схемы по умолчанию.
		{"socks5://bob:secret@1.2.3.4:1080", "http",
			Proxy{Scheme: "socks5", Host: "1.2.3.4", Port: 1080, Login: "bob", Password: "secret"}},
		{"https://proxy.example.com:8443", "http",
			Proxy{Scheme: "https", Host: "proxy.example.com", Port: 8443}},
		{"  1.2.3.4:1080  ", "http", Proxy{Scheme: "http", Host: "1.2.3.4", Port: 1080}},
	}
	for _, tt := range tests {
		got, err := ParseProxyLine(tt.line, tt.scheme)
		if err != nil {
			t.Errorf("%q: %v", tt.line, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%q разобрано как %+v, ожидалось %+v", tt.line, got, tt.want)
		}
	}
}

func TestParseProxyLineErrors(t *testing.T) {
	for _, line := range []string{
		"",
		"просто мусор",
		"1.2.3.4",
		"1.2.3.4:порт",
		"1.2.3.4:70000",
		":1080",
		"1.2.3.4:1080:bob",
		"bob:secret@1.2.3.4:1080:bob:secret",
	} {
		if got, err := ParseProxyLine(line, "http"); err == nil {
			t.Errorf("%q: ожидалась ошибка, разобрано как %+v", line, got)
		}
	}
}

func TestImportProxies(t *testing.T) {
	cfg := &Config{}
	text := `
# комментарии и пустые строки пропускаются

1.1.1.1:1080:bob:secret
2.2.2.2:1080
socks5://3.3.3.3:9050
мусор
1.1.1.1:1080
`
	result := cfg.ImportProxies(text, "socks5", "ru", "RU", "куплены оптом")

	if result.AddedN != 3 {
		t.Errorf("добавлено %d, ожидалось 3: %+v", result.AddedN, result.Added)
	}
	if result.FailedN != 1 || !strings.Contains(result.Failed[0].Text, "мусор") {
		t.Errorf("ошибок %d: %+v", result.FailedN, result.Failed)
	}
	// Повтор адреса пропускается, а не заменяет запись: повторная вставка
	// того же списка не должна ничего ломать.
	if result.SkippedN != 1 {
		t.Errorf("пропущено %d, ожидался один дубликат: %+v", result.SkippedN, result.Skipped)
	}
	// Номер строки нужен, чтобы человек нашёл проблему в своём списке.
	if result.Failed[0].Line != 7 {
		t.Errorf("номер битой строки = %d, ожидался 7", result.Failed[0].Line)
	}

	if len(cfg.Proxies) != 3 {
		t.Fatalf("в конфиге %d прокси", len(cfg.Proxies))
	}
	first := cfg.Proxies[0]
	if first.Name != "ru-1" || first.Country != "RU" || first.Comment != "куплены оптом" {
		t.Errorf("первый прокси: %+v", first)
	}
	if first.Login != "bob" || first.Password != "secret" {
		t.Errorf("креды не разобраны: %+v", first)
	}
	// Схема из строки не перетирается схемой по умолчанию.
	if cfg.Proxies[2].Scheme != "socks5" || cfg.Proxies[2].Host != "3.3.3.3" {
		t.Errorf("третий прокси: %+v", cfg.Proxies[2])
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("импортированный конфиг не проходит проверку: %v", err)
	}
}

// TestImportKeepsExistingNames — повторный импорт не должен наступать
// на уже занятые имена.
func TestImportKeepsExistingNames(t *testing.T) {
	cfg := &Config{Proxies: []Proxy{{Name: "ru-1", Scheme: "http", Host: "9.9.9.9", Port: 80}}}
	result := cfg.ImportProxies("1.1.1.1:1080\n2.2.2.2:1080", "http", "ru", "", "")

	if result.AddedN != 2 {
		t.Fatalf("добавлено %d", result.AddedN)
	}
	names := map[string]int{}
	for _, p := range cfg.Proxies {
		names[p.Name]++
	}
	for name, count := range names {
		if count > 1 {
			t.Errorf("имя %q досталось %d прокси", name, count)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("конфиг сломан: %v", err)
	}
}
