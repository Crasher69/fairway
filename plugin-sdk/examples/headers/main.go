// Пример плагина вида hook: добавляет заголовок к каждому запросу.
//
// Сборка:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
package main

import (
	"encoding/json"
	"errors"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

var settings = struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}{Name: "X-Via", Value: "fairway"}

func init() {
	fairway.Register(fairway.Plugin{
		// Init вызывается и в экземплярах, которые обрабатывают запросы,
		// так что настройки видны в OnRequest.
		Init: func(raw json.RawMessage) error {
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &settings); err != nil {
					return err
				}
			}
			if settings.Name == "" {
				return errors.New("header name is empty")
			}
			return nil
		},
		OnRequest: func(req *fairway.HTTPRequest) (*fairway.HTTPResponse, error) {
			req.Headers.Set(settings.Name, settings.Value)
			return nil, nil
		},
	})
}

func main() {}
