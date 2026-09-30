package plugin

import (
	"net/http"
	"testing"

	"fairway/internal/config"
)

func TestLoopback(t *testing.T) {
	for in, want := range map[string]string{
		":7770":          "127.0.0.1:7770",
		"0.0.0.0:7770":   "127.0.0.1:7770",
		"[::]:7770":      "[::1]:7770",
		"10.0.0.5:7770":  "10.0.0.5:7770",
		"localhost:7770": "localhost:7770",
	} {
		if got := loopback(in); got != want {
			t.Errorf("loopback(%q) = %q, want %q", in, got, want)
		}
	}
}

// Вход на прокси берётся из конфига на каждый запрос.
func TestSelfClientAuth(t *testing.T) {
	auth := config.ProxyAuth{}
	client := SelfClient(":7770", func() config.ProxyAuth { return auth }, nil)
	proxy := client.Transport.(*http.Transport).Proxy
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)

	u, err := proxy(req)
	if err != nil || u.String() != "http://127.0.0.1:7770" {
		t.Fatalf("без входа: %v %v", u, err)
	}
	auth = config.ProxyAuth{Enabled: true, Users: []config.ProxyUser{{Login: "bot", Password: "s3cret"}}}
	u, err = proxy(req)
	if err != nil || u.String() != "http://bot:s3cret@127.0.0.1:7770" {
		t.Fatalf("со входом: %v %v", u, err)
	}
}
