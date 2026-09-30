// Плагин для тестов internal/plugin: что делать, говорят настройки.
package main

import (
	"encoding/json"
	"errors"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

type settings struct {
	Greeting  string `json:"greeting"`
	FailInit  bool   `json:"fail_init"`
	Tick      string `json:"tick"`
	FetchURL  string `json:"fetch_url"`
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
			resp, err := fairway.Fetch(fairway.Request{URL: s.FetchURL})
			if err != nil {
				fairway.Logf("fetch: %v", err)
				return err
			}
			fairway.Logf("fetch: %d %s", resp.Status, resp.Body)
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
