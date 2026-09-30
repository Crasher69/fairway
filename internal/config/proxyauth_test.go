package config

import (
	"strings"
	"testing"
)

func TestProxyAuthOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyAuth.Enabled {
		t.Error("без поля proxy_auth вход на прокси должен быть выключен")
	}
	if !cfg.ProxyAuth.Allows("", "") {
		t.Error("выключенная проверка обязана пускать всех")
	}
	if Example().ProxyAuth.Enabled {
		t.Error("стартовый конфиг должен оставлять прокси открытым")
	}
}

func TestProxyAuthAllows(t *testing.T) {
	auth := ProxyAuth{Enabled: true, Users: []ProxyUser{
		{Login: "alice", Password: "secret"},
		{Login: "bob", Password: "p:a:ss"},
	}}
	tests := []struct {
		login, password string
		want            bool
	}{
		{"alice", "secret", true},
		{"bob", "p:a:ss", true},
		{"alice", "p:a:ss", false},
		{"alice", "", false},
		{"", "", false},
		{"carol", "secret", false},
	}
	for _, tt := range tests {
		if got := auth.Allows(tt.login, tt.password); got != tt.want {
			t.Errorf("Allows(%q, %q) = %v, ожидалось %v", tt.login, tt.password, got, tt.want)
		}
	}
}

func TestProxyAuthValidate(t *testing.T) {
	bad := map[string]ProxyAuth{
		"no users":        {Enabled: true},
		"empty login":     {Users: []ProxyUser{{Login: "", Password: "x"}}},
		"colon in login":  {Users: []ProxyUser{{Login: "a:b", Password: "x"}}},
		"empty password":  {Users: []ProxyUser{{Login: "a"}}},
		"duplicate login": {Users: []ProxyUser{{Login: "a", Password: "x"}, {Login: "a", Password: "y"}}},
	}
	for name, auth := range bad {
		cfg := Example()
		cfg.ProxyAuth = auth
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: конфиг должен был не пройти проверку", name)
		}
	}
	// Выключенный вход с пользователями — нормально: их заводят заранее
	// и включают проверку потом.
	cfg := Example()
	cfg.ProxyAuth = ProxyAuth{Users: []ProxyUser{{Login: "a", Password: "x"}}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("выключенный вход с пользователями отвергнут: %v", err)
	}
}

func TestProxyAuthFromFile(t *testing.T) {
	raw := strings.Replace(valid, `"defaults"`,
		`"proxy_auth": {"enabled": true, "users": [{"login": "u", "password": "p"}]}, "defaults"`, 1)
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ProxyAuth.Enabled || !cfg.ProxyAuth.Allows("u", "p") {
		t.Errorf("proxy_auth из файла прочитан неверно: %+v", cfg.ProxyAuth)
	}
}
