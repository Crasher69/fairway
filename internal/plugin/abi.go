// Package plugin запускает плагины fairway: модули WebAssembly (WASI
// preview1, «reactor») в рантайме wazero — чистый Go, без CGO, один и тот же
// plugin.wasm работает на всех ОС и архитектурах.
//
// # ABI
//
// Хост и плагин обмениваются JSON-сообщениями через линейную память
// модуля. Плагин экспортирует:
//
//	_initialize()                      — инициализация рантайма (reactor)
//	fw_alloc(size u32) -> ptr u32      — буфер под входящее сообщение
//	fw_handle(ptr u32, len u32) -> u64 — обработать сообщение; ответ —
//	                                     (ptr << 32 | len) в памяти плагина
//
// Хост даёт модулю "fairway":
//
//	call(ptr u32, len u32) -> len u32  — вызвать метод хоста; ответ хост
//	                                     держит у себя до result
//	result(ptr u32)                    — скопировать ответ последнего call
//	                                     в буфер плагина
//
// Ответ call забирается в два шага, чтобы хосту не приходилось вызывать
// плагин изнутри вызова хоста: повторный вход в модуль умеют не все
// компиляторы в WASM.
//
// Сообщения хоста плагину (fw_handle): {"type":"init","settings":{...}},
// {"type":"tick"}, {"type":"event","event":{...}} и
// {"type":"call","method":"...","params":{...}} — вызов со страницы
// плагина в панели. Ответ плагина — {"error":"..."} или {}, на call —
// ещё и {"result":...}.
//
// Вызовы плагина хосту (call): {"method":"...","params":{...}}, ответ —
// {"result":...} или {"error":"..."}. Методы — в host.go.
//
// Вызовы идут строго по одному: у каждого плагина своя горутина, свой
// экземпляр модуля и свой рантайм.
package plugin

import (
	"encoding/json"

	"fairway/internal/events"
)

// Имена экспортов и импортов ABI.
const (
	hostModule   = "fairway"
	exportAlloc  = "fw_alloc"
	exportHandle = "fw_handle"
	exportInit   = "_initialize"
)

// Виды сообщений хоста плагину.
const (
	messageInit  = "init"
	messageTick  = "tick"
	messageEvent = "event"
	messageCall  = "call"
)

type guestMessage struct {
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings,omitempty"`
	Event    *events.Event   `json:"event,omitempty"`
	Method   string          `json:"method,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type guestReply struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type hostRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type hostReply struct {
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}
