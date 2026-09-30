package forward

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProxyCredentials(t *testing.T) {
	tests := []struct {
		header          string
		login, password string
		ok              bool
	}{
		{"Basic dXNlcjpwOmFzcw==", "user", "p:ass", true}, // user:p:ass
		{"basic dXNlcjpwYXNz", "user", "pass", true},
		{"", "", "", false},
		{"Bearer abc", "", "", false},
		{"Basic !!!", "", "", false},
		{"Basic dXNlcg==", "", "", false}, // "user" без двоеточия
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "http://example.com/", nil)
		if tt.header != "" {
			r.Header.Set("Proxy-Authorization", tt.header)
		}
		login, password, ok := ProxyCredentials(r)
		if login != tt.login || password != tt.password || ok != tt.ok {
			t.Errorf("%q: получили (%q, %q, %v)", tt.header, login, password, ok)
		}
	}
}

// TestAuthorizeGatesRequests: без верного Proxy-Authorization прокси
// отвечает 407 и никуда не ходит, с верным — работает как обычно, и
// заголовок до цели не доходит.
func TestAuthorizeGatesRequests(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization дошёл до цели")
		}
		io.WriteString(w, "ok")
	}))
	defer target.Close()

	direct, err := ParseUpstream("direct")
	if err != nil {
		t.Fatal(err)
	}
	picked := 0
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string, []string) (*Route, error) {
			picked++
			return &Route{Upstream: direct, Name: direct.Name}, nil
		},
		Authorize: func(login, password string, ok bool) bool {
			return ok && login == "user" && password == "pass"
		},
	})
	defer proxySrv.Close()

	get := func(user *url.Userinfo) *http.Response {
		t.Helper()
		proxyURL, _ := url.Parse(proxySrv.URL)
		proxyURL.User = user
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	for _, user := range []*url.Userinfo{nil, url.UserPassword("user", "wrong")} {
		resp := get(user)
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("%v: статус %d, ожидался 407", user, resp.StatusCode)
		}
		if resp.Header.Get("Proxy-Authenticate") == "" {
			t.Errorf("%v: в ответе 407 нет Proxy-Authenticate", user)
		}
	}
	if picked != 0 {
		t.Errorf("без авторизации прокси выбрал маршрут %d раз", picked)
	}

	if resp := get(url.UserPassword("user", "pass")); resp.StatusCode != http.StatusOK {
		t.Errorf("с верным паролем статус %d, ожидался 200", resp.StatusCode)
	}
}

// TestAuthorizeGatesConnect — то же для CONNECT: туннель без пароля не
// открывается.
func TestAuthorizeGatesConnect(t *testing.T) {
	proxySrv := httptest.NewServer(&Server{
		Pick: func(string, []string) (*Route, error) {
			t.Error("без авторизации маршрут выбираться не должен")
			return nil, io.EOF
		},
		Authorize: func(string, string, bool) bool { return false },
	})
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodConnect, proxySrv.URL, nil)
	req.Host = "example.com:443"
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT: статус %d, ожидался 407", resp.StatusCode)
	}
}
