# Плагины

Плагин расширяет fairway, не пересобирая его: синхронизирует прокси с API
поставщика, реагирует на баны, правит листы. Плагин — модуль WebAssembly
(WASI, режим reactor), который fairway запускает в рантайме
[wazero](https://wazero.io): чистый Go, без CGO. Один и тот же
`plugin.wasm` работает на Linux, macOS и Windows, на amd64 и arm64.

Плагин работает в песочнице: он не видит ни диска, ни сети, ни памяти
fairway. Всё, что ему можно, — вызовы хоста, и только те, на которые ему
выданы права.

> Сейчас есть плагины вида `base`. Хуки обработки запросов (`hook`) и
> страницы плагинов в панели появятся следующими шагами.

## Установка

Плагин — каталог в каталоге плагинов (`-plugins`, по умолчанию
`<data>/plugins`):

```
data/plugins/hello/manifest.json
data/plugins/hello/plugin.wasm
```

Имя каталога совпадает с `name` в манифесте. Затем плагин включается в
конфиге (правка подхватывается на лету):

```json
"plugins": [
  {
    "name": "hello",
    "enabled": true,
    "granted": ["config.read", "schedule"],
    "settings": {"interval": "1m"}
  }
]
```

Плагин запускается, только если в `granted` есть **все** права из его
манифеста. Новая версия плагина, которая просит больше прав, не получит их
молча: она будет ждать, пока права не выдадут.

Плагин перезапускается, когда меняются его настройки, права или файл
`plugin.wasm` (при следующем применении конфига). Упавший плагин тоже
поднимается при следующем применении конфига.

Скомпилированные модули кешируются в `<data>/plugin-cache`: компиляция
занимает секунды, и без кеша за неё платил бы каждый запуск.

## Манифест

```json
{
  "name": "hello",
  "version": "0.1.0",
  "title": "Hello",
  "description": "Что делает плагин",
  "kind": "base",
  "permissions": ["config.read", "schedule", "http.fetch"],
  "http_hosts": ["api.example.com", "*.example.net"],
  "settings_schema": {"type": "object", "properties": {}}
}
```

- `name` — строчные латинские буквы, цифры, `-`, `_`.
- `http_hosts` — куда плагину можно ходить через `http.fetch`. `*.example.net`
  разрешает поддомены, но не сам `example.net`. Редиректы на другие хосты
  тоже запрещены.
- `settings_schema` — JSON Schema настроек; по ней панель будет рисовать
  форму.

## Права

| Право | Что даёт |
|---|---|
| `config.read` | читать прокси, листы, домены и умолчания. Пароль панели, вход на прокси и настройки плагинов не отдаются никогда |
| `config.write` | заменять разделы `proxies`, `lists`, `domains`. Правка проходит ту же проверку, что правка из панели: битый конфиг не сохранится |
| `events` | получать события: `config.applied`, `proxy.banned` |
| `schedule` | вызываться по таймеру, не чаще раза в 10 секунд |
| `http.fetch` | HTTP-запросы на хосты из `http_hosts`, ответ до 16 МиБ |

## Ограничения

- Память модуля — до 128 МиБ.
- `init` — до 30 секунд, вызов по таймеру — до 5 минут, событие — до 30
  секунд. Дольше — плагин прерывается и считается упавшим.
- Вызовы плагина идут строго по одному.
- Ошибка, которую вернул обработчик плагина, не останавливает его: она
  пишется в лог и в статус плагина.

## Плагин на Go

SDK: модуль `github.com/Crasher69/fairway/plugin-sdk` в этом репозитории,
пример — [`plugin-sdk/examples/hello`](../plugin-sdk/examples/hello).

```go
package main

import (
	"encoding/json"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

func init() {
	fairway.Register(fairway.Plugin{
		Init: func(settings json.RawMessage) error {
			return fairway.Every(10 * time.Minute)
		},
		Tick: func() error {
			resp, err := fairway.Fetch(fairway.Request{URL: "https://api.example.com/proxies"})
			if err != nil {
				return err
			}
			fairway.Logf("got %d bytes", len(resp.Body))
			return nil
		},
	})
}

func main() {}
```

Сборка (Go 1.24+):

```
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
```

В режиме reactor `main` не вызывается — плагин регистрируется в `init`.

## Плагин на другом языке

Подойдёт любой язык, который собирается в WASI-reactor (Rust, Zig,
TinyGo, AssemblyScript). Протокол — JSON через линейную память; он описан
в [`internal/plugin/abi.go`](../internal/plugin/abi.go).

Плагин экспортирует `fw_alloc(size) -> ptr` и
`fw_handle(ptr, len) -> (ptr << 32 | len)`. Хост присылает сообщения
`{"type":"init","settings":{...}}`, `{"type":"tick"}`,
`{"type":"event","event":{...}}` и ждёт `{}` или `{"error":"..."}`.

Хост даёт модулю `fairway` функции `call(ptr, len) -> len` и
`result(ptr)`: плагин передаёт `{"method":"...","params":{...}}`,
получает длину ответа, выделяет буфер и забирает в него
`{"result":...}` или `{"error":"..."}`.

| Метод | Параметры | Результат |
|---|---|---|
| `log` | `{"level":"info\|warn\|error","message":"..."}` | — |
| `config.get` | — | `{"defaults","proxies","lists","domains"}` |
| `config.edit` | `{"proxies"?, "lists"?, "domains"?}` | конфиг после правки |
| `events.subscribe` | `{"types":["proxy.banned"]}` | — |
| `schedule.every` | `{"interval":"10m"}` (`"0s"` — выключить) | — |
| `http.fetch` | `{"method","url","headers","body","timeout_ms"}` | `{"status","headers","body"}` |

`body` — base64 (так кодирует байты JSON).
