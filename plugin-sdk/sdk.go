//go:build wasip1

package fairway

import (
	"bytes"
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
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params"`
	Request  *HTTPRequest    `json:"request"`
	Response *HTTPResponse   `json:"response"`
}

// Правки запроса и ответа для хоста. Тело передаётся, только если
// изменилось: гонять мегабайты туда и обратно впустую незачем.
type requestEdit struct {
	Method  string  `json:"method"`
	URL     string  `json:"url"`
	Headers Header  `json:"headers"`
	Body    *[]byte `json:"body,omitempty"`
}

type responseEdit struct {
	Status  int     `json:"status"`
	Headers Header  `json:"headers"`
	Body    *[]byte `json:"body,omitempty"`
}

type hookReply struct {
	Request  *requestEdit  `json:"request,omitempty"`
	Response *responseEdit `json:"response,omitempty"`
}

// changedBody — указатель на новое тело или nil, если оно не менялось.
func changedBody(before, after []byte, skipped bool) *[]byte {
	if skipped || bytes.Equal(before, after) && (before == nil) == (after == nil) {
		return nil
	}
	if after == nil {
		after = []byte{}
	}
	return &after
}

func handleRequest(req *HTTPRequest) (any, error) {
	if req.Headers == nil {
		req.Headers = Header{}
	}
	before := bytes.Clone(req.Body)
	resp, err := plugin.OnRequest(req)
	if err != nil {
		return nil, err
	}
	if resp != nil {
		body := resp.Body
		if body == nil {
			body = []byte{}
		}
		return hookReply{Response: &responseEdit{Status: resp.Status, Headers: resp.Headers, Body: &body}}, nil
	}
	return hookReply{Request: &requestEdit{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    changedBody(before, req.Body, req.BodySkipped),
	}}, nil
}

func handleResponse(req *HTTPRequest, resp *HTTPResponse) (any, error) {
	if resp.Headers == nil {
		resp.Headers = Header{}
	}
	before := bytes.Clone(resp.Body)
	if err := plugin.OnResponse(req, resp); err != nil {
		return nil, err
	}
	return hookReply{Response: &responseEdit{
		Status:  resp.Status,
		Headers: resp.Headers,
		Body:    changedBody(before, resp.Body, resp.BodySkipped),
	}}, nil
}

type reply struct {
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

//go:wasmexport fw_handle
func fwHandle(ptr, size uint32) uint64 {
	result, err := handle(inbuf[:size])
	r := reply{Result: result}
	if err != nil {
		r = reply{Error: err.Error()}
	}
	var marshalErr error
	if outbuf, marshalErr = json.Marshal(r); marshalErr != nil {
		outbuf, _ = json.Marshal(reply{Error: "result: " + marshalErr.Error()})
	}
	return uint64(pointer(outbuf))<<32 | uint64(len(outbuf))
}

func handle(data []byte) (result any, err error) {
	// Паника в обработчике — ошибка вызова, а не падение плагина.
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	var msg message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	switch msg.Type {
	case "init":
		if plugin.Init != nil {
			return nil, plugin.Init(msg.Settings)
		}
	case "tick":
		if plugin.Tick != nil {
			return nil, plugin.Tick()
		}
	case "event":
		if plugin.Event != nil && msg.Event != nil {
			return nil, plugin.Event(*msg.Event)
		}
	case "call":
		if plugin.Call == nil {
			return nil, fmt.Errorf("plugin does not accept calls")
		}
		return plugin.Call(msg.Method, msg.Params)
	case "request":
		if plugin.OnRequest != nil && msg.Request != nil {
			return handleRequest(msg.Request)
		}
	case "response":
		if plugin.OnResponse != nil && msg.Request != nil && msg.Response != nil {
			return handleResponse(msg.Request, msg.Response)
		}
	}
	return nil, nil
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
