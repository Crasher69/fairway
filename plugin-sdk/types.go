// Package fairway — SDK для плагинов fairway на Go.
//
// Плагин собирается в WebAssembly (WASI, режим reactor):
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
//
// и кладётся в каталог плагинов fairway вместе с manifest.json:
//
//	plugins/<имя>/manifest.json
//	plugins/<имя>/plugin.wasm
//
// В режиме reactor main не вызывается: плагин регистрируется в init.
//
//	func init() {
//		fairway.Register(fairway.Plugin{
//			Init: func(settings json.RawMessage) error {
//				fairway.Logf("привет")
//				return fairway.Every(10 * time.Minute)
//			},
//			Tick: sync,
//		})
//	}
//
// Протокол обмена с хостом описан в internal/plugin/abi.go репозитория
// fairway; плагин можно писать и не на Go, если соблюсти его.
package fairway

import (
	"encoding/json"
	"time"
)

// Plugin — обработчики плагина. Любой может быть nil.
type Plugin struct {
	// Init вызывается один раз после запуска, с настройками из конфига
	// fairway. Ошибка — плагин не запускается.
	Init func(settings json.RawMessage) error
	// Tick вызывается по таймеру, заданному Every (право "schedule").
	Tick func() error
	// Event получает события, на которые плагин подписался через
	// Subscribe (право "events").
	Event func(Event) error
	// Call отвечает на вызовы со страницы плагина в панели
	// (ui/index.html, см. docs/PLUGINS.md). Результат уходит странице
	// как JSON.
	Call func(method string, params json.RawMessage) (any, error)
}

// Event — событие fairway.
type Event struct {
	Type string          `json:"type"`
	At   time.Time       `json:"at"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Виды событий.
const (
	EventConfigApplied = "config.applied"
	EventProxyBanned   = "proxy.banned"
)

// ProxyBanned — данные события EventProxyBanned.
type ProxyBanned struct {
	Domain string    `json:"domain"`
	Proxy  string    `json:"proxy"` // id прокси
	Reason string    `json:"reason"`
	Until  time.Time `json:"until"`
}

// Config — то, что плагин видит в конфиге (право "config.read").
type Config struct {
	Defaults json.RawMessage   `json:"defaults"`
	Proxies  []Proxy           `json:"proxies"`
	Lists    []List            `json:"lists"`
	Domains  []json.RawMessage `json:"domains"`
}

// Proxy — апстрим-прокси. Новому прокси id можно не задавать — fairway
// выдаст сам.
type Proxy struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Scheme   string `json:"scheme,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Login    string `json:"login,omitempty"`
	Password string `json:"password,omitempty"`
	Country  string `json:"country,omitempty"`
	Comment  string `json:"comment,omitempty"`
	// URL — всё одной строкой: scheme://user:pass@host:port.
	URL string `json:"url,omitempty"`
}

// List — именованный набор прокси (по id).
type List struct {
	Name    string   `json:"name"`
	Proxies []string `json:"proxies"`
}

// ConfigEdit — правка конфига (право "config.write"). Переданный раздел
// заменяется целиком, nil — не трогается.
type ConfigEdit struct {
	Proxies *[]Proxy           `json:"proxies,omitempty"`
	Lists   *[]List            `json:"lists,omitempty"`
	Domains *[]json.RawMessage `json:"domains,omitempty"`
}

// Request — HTTP-запрос для Fetch (право "http.fetch", хост должен быть
// в http_hosts манифеста).
type Request struct {
	Method  string              `json:"method,omitempty"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    []byte              `json:"body,omitempty"`
	// Timeout — 0 означает таймаут хоста по умолчанию (30 с).
	Timeout time.Duration `json:"-"`
}

// Response — ответ на Fetch.
type Response struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}
