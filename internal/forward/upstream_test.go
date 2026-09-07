package forward

import "testing"

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		raw        string
		wantScheme string
		wantAddr   string
		wantUser   string
		wantAuth   bool
	}{
		{"direct", "direct", "", "", false},
		{"", "direct", "", "", false},
		{"1.2.3.4:8000", "http", "1.2.3.4:8000", "", false},
		{"http://1.2.3.4", "http", "1.2.3.4:80", "", false},
		{"https://proxy.example.com", "https", "proxy.example.com:443", "", false},
		{"socks5://1.2.3.4", "socks5", "1.2.3.4:1080", "", false},
		{"socks5h://1.2.3.4:9050", "socks5", "1.2.3.4:9050", "", false},
		{"http://bob:secret@1.2.3.4:3128", "http", "1.2.3.4:3128", "bob", true},
	}
	for _, tt := range tests {
		up, err := ParseUpstream(tt.raw)
		if err != nil {
			t.Errorf("ParseUpstream(%q): %v", tt.raw, err)
			continue
		}
		if up.Scheme != tt.wantScheme || up.Addr != tt.wantAddr || up.User != tt.wantUser {
			t.Errorf("ParseUpstream(%q) = %+v, ожидалось scheme=%q addr=%q user=%q",
				tt.raw, up, tt.wantScheme, tt.wantAddr, tt.wantUser)
		}
		if got := up.ProxyAuthorization() != ""; got != tt.wantAuth {
			t.Errorf("ParseUpstream(%q): наличие Proxy-Authorization = %v, ожидалось %v", tt.raw, got, tt.wantAuth)
		}
	}
}

func TestParseUpstreamErrors(t *testing.T) {
	for _, raw := range []string{"ftp://1.2.3.4:21", "http://", "socks4://1.2.3.4"} {
		if up, err := ParseUpstream(raw); err == nil {
			t.Errorf("ParseUpstream(%q) = %+v, ожидалась ошибка", raw, up)
		}
	}
}

func TestUpstreamName(t *testing.T) {
	// Имя уходит в логи и метрики — пароль в нём не должен появляться.
	up, err := ParseUpstream("http://bob:secret@1.2.3.4:3128")
	if err != nil {
		t.Fatal(err)
	}
	if up.Name != "http://1.2.3.4:3128" {
		t.Errorf("Name = %q, креды не должны попадать в имя", up.Name)
	}
}
