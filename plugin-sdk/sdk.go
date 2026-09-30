//go:build wasip1

package fairway

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

var plugin Plugin

// Register задаёт обработчики плагина. Вызывается из init.
func Register(p Plugin) { plugin = p }

//go:wasmimport fairway call
func hostCall(ptr, size uint32) uint32

//go:wasmimport fairway result
func hostResult(ptr uint32)

// Буферы живут в глобальных переменных, пока хост их читает: вызовы идут
// строго по одному, так что одного входного и одного выходного хватает.
var inbuf, outbuf []byte

func pointer(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(unsafe.SliceData(b))))
}

//go:wasmexport fw_alloc
func fwAlloc(size uint32) uint32 {
	inbuf = make([]byte, size)
	return pointer(inbuf)
}

type message struct {
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings"`
	Event    *Event          `json:"event"`
}

type reply struct {
	Error string `json:"error,omitempty"`
}

//go:wasmexport fw_handle
func fwHandle(ptr, size uint32) uint64 {
	err := handle(inbuf[:size])
	var r reply
	if err != nil {
		r.Error = err.Error()
	}
	outbuf, _ = json.Marshal(r)
	return uint64(pointer(outbuf))<<32 | uint64(len(outbuf))
}

func handle(data []byte) (err error) {
	// Паника в обработчике — ошибка вызова, а не падение плагина.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var msg message
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}
	switch msg.Type {
	case "init":
		if plugin.Init != nil {
			return plugin.Init(msg.Settings)
		}
	case "tick":
		if plugin.Tick != nil {
			return plugin.Tick()
		}
	case "event":
		if plugin.Event != nil && msg.Event != nil {
			return plugin.Event(*msg.Event)
		}
	}
	return nil
}

// Call вызывает метод хоста. Обычно хватает обёрток ниже.
func Call(method string, params, result any) error {
	req, err := json.Marshal(struct {
		Method string `json:"method"`
		Params any    `json:"params,omitempty"`
	}{method, params})
	if err != nil {
		return err
	}
	n := hostCall(pointer(req), uint32(len(req)))
	resp := make([]byte, n)
	hostResult(pointer(resp))

	var r struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return err
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	if result != nil && len(r.Result) > 0 {
		return json.Unmarshal(r.Result, result)
	}
	return nil
}

func logAt(level, format string, args ...any) {
	_ = Call("log", map[string]string{"level": level, "message": fmt.Sprintf(format, args...)}, nil)
}

// Logf пишет в лог fairway с именем плагина.
func Logf(format string, args ...any) { logAt("info", format, args...) }

// Warnf — предупреждение в лог.
func Warnf(format string, args ...any) { logAt("warn", format, args...) }

// Errorf — ошибка в лог.
func Errorf(format string, args ...any) { logAt("error", format, args...) }

// GetConfig читает конфиг (право "config.read").
func GetConfig() (*Config, error) {
	var c Config
	if err := Call("config.get", nil, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// EditConfig меняет конфиг и возвращает применённую версию (право
// "config.write"). Конфиг проверяется целиком: ошибка — ничего не изменено.
func EditConfig(edit ConfigEdit) (*Config, error) {
	var c Config
	if err := Call("config.edit", edit, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Subscribe подписывает на события указанных видов (право "events").
// Пустой список отменяет подписку.
func Subscribe(types ...string) error {
	return Call("events.subscribe", map[string][]string{"types": types}, nil)
}

// Every задаёт интервал вызова Tick (право "schedule"); 0 — выключить.
// Минимум — 10 секунд.
func Every(d time.Duration) error {
	return Call("schedule.every", map[string]string{"interval": d.String()}, nil)
}

// Fetch выполняет HTTP-запрос (право "http.fetch").
func Fetch(req Request) (*Response, error) {
	params := struct {
		Request
		TimeoutMS int64 `json:"timeout_ms,omitempty"`
	}{req, req.Timeout.Milliseconds()}
	var resp Response
	if err := Call("http.fetch", params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
