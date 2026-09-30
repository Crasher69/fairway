// hello — минимальный плагин fairway: здоровается и раз в интервал пишет
// в лог, сколько прокси в конфиге.
//
// Сборка:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
//
// Установка: plugins/hello/manifest.json и plugins/hello/plugin.wasm в
// каталоге плагинов fairway, затем в конфиге:
//
//	"plugins": [{"name": "hello", "enabled": true,
//	             "granted": ["config.read", "schedule"],
//	             "settings": {"interval": "1m"}}]
package main

import (
	"encoding/json"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

type settings struct {
	Interval string `json:"interval"`
}

func init() {
	fairway.Register(fairway.Plugin{
		Init: func(raw json.RawMessage) error {
			s := settings{Interval: "10m"}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &s); err != nil {
					return err
				}
			}
			every, err := time.ParseDuration(s.Interval)
			if err != nil {
				return err
			}
			fairway.Logf("hello, reporting every %s", every)
			return fairway.Every(every)
		},
		Tick: func() error {
			cfg, err := fairway.GetConfig()
			if err != nil {
				return err
			}
			fairway.Logf("proxies: %d, lists: %d", len(cfg.Proxies), len(cfg.Lists))
			return nil
		},
	})
}

// main в режиме reactor не вызывается, но пакет main без него не собрать.
func main() {}
