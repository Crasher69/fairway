package plugin

import (
	"testing"

	"fairway/internal/config"
)

func TestManifestValidate(t *testing.T) {
	for _, tc := range []struct {
		m  Manifest
		ok bool
	}{
		{Manifest{Name: "ok", Version: "1", Kind: KindBase}, true},
		{Manifest{Name: "Bad Name", Version: "1", Kind: KindBase}, false},
		{Manifest{Name: "ok", Kind: KindBase}, false},
		{Manifest{Name: "ok", Version: "1", Kind: "hook"}, false},
		{Manifest{Name: "ok", Version: "1", Kind: "other"}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindHook, Permissions: []Permission{Requests},
			Hooks: &Hooks{Domains: []string{"*", "*.a.com", "b.com"}, Request: true}}, true},
		// Без права requests, без доменов, без request/response, с плохой маской.
		{Manifest{Name: "ok", Version: "1", Kind: KindHook,
			Hooks: &Hooks{Domains: []string{"*"}, Request: true}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindHook, Permissions: []Permission{Requests},
			Hooks: &Hooks{Request: true}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindHook, Permissions: []Permission{Requests},
			Hooks: &Hooks{Domains: []string{"*"}}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindHook, Permissions: []Permission{Requests},
			Hooks: &Hooks{Domains: []string{"a*.com"}, Request: true}}, false},
		// Обработка запросов — только у вида hook.
		{Manifest{Name: "ok", Version: "1", Kind: KindBase, Permissions: []Permission{Requests}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindBase,
			Hooks: &Hooks{Domains: []string{"*"}, Request: true}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindBase, Permissions: []Permission{"root"}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindBase, HTTPHosts: []string{"a.com"}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindBase, Permissions: []Permission{HTTPFetch},
			HTTPHosts: []string{"https://a.com"}}, false},
		{Manifest{Name: "ok", Version: "1", Kind: KindBase, Permissions: []Permission{HTTPFetch},
			HTTPHosts: []string{"a.com", "*.b.com"}}, true},
	} {
		if err := tc.m.validate(); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc.m, err)
		}
	}
}

func TestManifestAllowsHost(t *testing.T) {
	m := Manifest{HTTPHosts: []string{"api.example.com", "*.proxy.net"}}
	for host, want := range map[string]bool{
		"api.example.com":      true,
		"API.Example.com.":     true,
		"example.com":          false,
		"evil-api.example.com": false,
		"a.proxy.net":          true,
		"a.b.proxy.net":        true,
		"proxy.net":            false,
		"xproxy.net":           false,
	} {
		if got := m.AllowsHost(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}

func TestManifestMissing(t *testing.T) {
	m := Manifest{Permissions: []Permission{ConfigRead, HTTPFetch}}
	if got := m.Missing([]string{"http.fetch", "events"}); len(got) != 1 || got[0] != ConfigRead {
		t.Fatalf("%v", got)
	}
}

func TestConfigEditSameAs(t *testing.T) {
	view := configView{Proxies: []config.Proxy{{ID: "1", Name: "a", Host: "1.1.1.1", Port: 80}}}
	same := []config.Proxy{{ID: "1", Name: "a", Host: "1.1.1.1", Port: 80}}
	other := []config.Proxy{{ID: "1", Name: "b", Host: "1.1.1.1", Port: 80}}
	if !(configEdit{}).sameAs(view) || !(configEdit{Proxies: &same}).sameAs(view) {
		t.Fatal("правка без изменений принята за изменение")
	}
	if (configEdit{Proxies: &other}).sameAs(view) {
		t.Fatal("изменение не замечено")
	}
}
