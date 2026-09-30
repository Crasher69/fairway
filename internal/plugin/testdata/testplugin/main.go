// Плагин для тестов internal/plugin: что делать, говорят настройки.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

type settings struct {
	Greeting  string `json:"greeting"`
	FailInit  bool   `json:"fail_init"`
	Tick      string `json:"tick"`
	FetchURL  string `json:"fetch_url"`
	FetchVia  bool   `json:"fetch_via"`
	AddProxy  string `json:"add_proxy"`
	Forbidden string `json:"forbidden"`
}

var s settings

func init() {
	fairway.Register(fairway.Plugin{
		Init: func(raw json.RawMessage) error {
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &s); err != nil {
					return err
				}
			}
			if s.FailInit {
				return errors.New("init refused")
			}
			fairway.Logf("hello %s", s.Greeting)
			if s.Forbidden != "" {
				// Метод без выданного права: хост должен отказать.
				if _, err := fairway.GetConfig(); err != nil {
					fairway.Logf("config.get: %v", err)
				}
			}
			if s.AddProxy != "" {
				if err := fairway.Subscribe(fairway.EventConfigApplied); err != nil {
					return err
				}
			}
			if s.Tick != "" {
				d, err := time.ParseDuration(s.Tick)
				if err != nil {
					return err
				}
				return fairway.Every(d)
			}
			return nil
		},
		Tick: func() error {
			if s.FetchURL == "" {
				return nil
			}
			resp, err := fairway.Fetch(fairway.Request{URL: s.FetchURL, ViaFairway: s.FetchVia})
			if err != nil {
				fairway.Logf("fetch: %v", err)
				return err
			}
			fairway.Logf("fetch: %d %s", resp.Status, resp.Body)
			return nil
		},
		Call: func(method string, params json.RawMessage) (any, error) {
			switch method {
			case "echo":
				return map[string]any{"echo": params, "greeting": s.Greeting}, nil
			case "fail":
				return nil, errors.New("refused by plugin")
			case "panic":
				panic("boom")
			case "sleep":
				// Уснувший плагин не должен держать остановку.
				time.Sleep(24 * time.Hour)
			}
			return nil, errors.New("unknown method " + method)
		},
		OnRequest: func(req *fairway.HTTPRequest) (*fairway.HTTPResponse, error) {
			u, err := url.Parse(req.URL)
			if err != nil {
				return nil, err
			}
			switch u.Path {
			case "/blocked":
				return &fairway.HTTPResponse{Status: 403, Headers: fairway.Header{"Content-Type": {"text/plain"}},
					Body: []byte("blocked by " + s.Greeting)}, nil
			case "/fail":
				return nil, errors.New("refused by plugin")
			case "/slow":
				time.Sleep(time.Minute)
			case "/crash":
				os.Exit(3)
			case "/host":
				u.Host = "elsewhere.test"
				req.URL = u.String()
				return nil, nil
			case "/rewrite":
				u.Path, u.RawQuery = "/rewritten", "by=plugin"
				req.URL = u.String()
				req.Method = "PUT"
			}
			req.Headers.Set("X-Greeting", s.Greeting)
			req.Headers.Del("X-Secret")
			if req.Headers.Get("Proxy-Authorization") != "" {
				req.Headers.Set("X-Leak", "proxy-authorization")
			}
			if req.BodySkipped {
				req.Headers.Set("X-Body", "skipped")
			} else if len(req.Body) > 0 {
				req.Body = bytes.ToUpper(req.Body)
			}
			return nil, nil
		},
		OnResponse: func(req *fairway.HTTPRequest, resp *fairway.HTTPResponse) error {
			resp.Headers.Set("X-Seen", req.Method+" "+req.URL)
			if resp.Status == 404 {
				resp.Status = 200
			}
			if resp.BodySkipped {
				resp.Headers.Set("X-Body", "skipped")
			} else {
				resp.Body = []byte(strings.ReplaceAll(string(resp.Body), "world", s.Greeting))
			}
			return nil
		},
		Event: func(e fairway.Event) error {
			cfg, err := fairway.GetConfig()
			if err != nil {
				return err
			}
			for _, p := range cfg.Proxies {
				if p.Name == s.AddProxy {
					fairway.Logf("event %s: proxy %s present", e.Type, p.Name)
					return nil
				}
			}
			proxies := append(cfg.Proxies, fairway.Proxy{Name: s.AddProxy, URL: "http://9.9.9.9:8080"})
			_, err = fairway.EditConfig(fairway.ConfigEdit{Proxies: &proxies})
			return err
		},
	})
}

func main() {}
