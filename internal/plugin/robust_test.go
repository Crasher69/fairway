package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fairway/internal/config"
)

// Плагин — чужой код. Что бы он ни сделал, fairway должен жить дальше:
// эти тесты — про модули, которые раньше роняли процесс или вешали его.

// wasmModule собирает крошечный модуль WebAssembly руками: так можно
// получить то, чего компилятор Go не выдаст, — модуль без памяти или
// init, который никогда не кончается.
type wasmModule struct {
	types   [][]byte // закодированные сигнатуры
	funcs   []byte   // индекс сигнатуры для каждой функции
	bodies  [][]byte // тела функций (без размера)
	exports [][]byte // закодированные экспорты
	memory  bool
}

func leb(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func section(id byte, items [][]byte) []byte {
	body := leb(len(items))
	for _, it := range items {
		body = append(body, it...)
	}
	return append(append([]byte{id}, leb(len(body))...), body...)
}

func (m *wasmModule) fn(sig []byte, body []byte, export string) {
	m.types = append(m.types, sig)
	m.funcs = append(m.funcs, byte(len(m.types)-1))
	m.bodies = append(m.bodies, body)
	if export != "" {
		name := append(leb(len(export)), export...)
		m.exports = append(m.exports, append(name, 0x00, byte(len(m.funcs)-1)))
	}
}

func (m *wasmModule) bytes() []byte {
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	out = append(out, section(1, m.types)...)
	funcs := make([][]byte, len(m.funcs))
	for i, f := range m.funcs {
		funcs[i] = []byte{f}
	}
	out = append(out, section(3, funcs)...)
	exports := m.exports
	if m.memory {
		out = append(out, section(5, [][]byte{{0x00, 0x01}})...) // одна страница
		exports = append(exports, append(append(leb(len("memory")), "memory"...), 0x02, 0x00))
	}
	out = append(out, section(7, exports)...)
	bodies := make([][]byte, len(m.bodies))
	for i, b := range m.bodies {
		bodies[i] = append(leb(len(b)), b...)
	}
	return append(out, section(10, bodies)...)
}

// abiModule — модуль с fw_alloc и fw_handle, которые ничего не делают.
func abiModule(memory bool) *wasmModule {
	m := &wasmModule{memory: memory}
	m.fn([]byte{0x60, 0x01, 0x7f, 0x01, 0x7f}, []byte{0x00, 0x41, 0x00, 0x0b}, exportAlloc)        // (i32) -> i32: 0
	m.fn([]byte{0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e}, []byte{0x00, 0x42, 0x00, 0x0b}, exportHandle) // (i32, i32) -> i64: 0
	return m
}

func (e *env) installModule(name string, wasm []byte) {
	e.t.Helper()
	e.install(name, manifest(name, nil))
	if err := os.WriteFile(filepath.Join(e.dir, name, ModuleFile), wasm, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// TestModuleWithoutMemoryFailsPlugin — модуль без линейной памяти раньше
// ронял весь fairway на первой же записи сообщения, и при включённом
// плагине — каждый следующий запуск. Теперь это провал одного плагина.
func TestModuleWithoutMemoryFailsPlugin(t *testing.T) {
	e := newEnv(t)
	e.installModule("nomem", abiModule(false).bytes())
	e.setPlugins(config.Plugin{Name: "nomem", Enabled: true})

	st := e.waitState("nomem", StateFailed)
	if !strings.Contains(st.Error, "memory") {
		t.Fatalf("ошибка %q, ожидалась про память", st.Error)
	}
}

// TestEndlessInitIsInterrupted — бесконечный цикл в стартовой функции
// модуля раньше держал плагин в «запускается» и ядро процессора на 100%.
func TestEndlessInitIsInterrupted(t *testing.T) {
	saved := startTimeout
	startTimeout = time.Second
	t.Cleanup(func() { startTimeout = saved })

	m := abiModule(true)
	// () -> (): loop { br 0 }
	m.fn([]byte{0x60, 0x00, 0x00}, []byte{0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b}, exportInit)
	e := newEnv(t)
	e.installModule("spinner", m.bytes())
	e.setPlugins(config.Plugin{Name: "spinner", Enabled: true})

	e.waitState("spinner", StateFailed)
}

// TestSleepingPluginDoesNotHoldStop — плагин уснул внутри вызова на сутки.
// Раньше сон шёл через time.Sleep мимо контекста, и выключение плагина
// (а с ним и остановка fairway) ждало конца сна.
func TestSleepingPluginDoesNotHoldStop(t *testing.T) {
	e := newEnv(t)
	e.install("sleeper", manifest("sleeper", nil))
	e.setPlugins(config.Plugin{Name: "sleeper", Enabled: true})
	e.waitState("sleeper", StateRunning)

	called := make(chan error, 1)
	go func() {
		_, err := e.manager.Call(context.Background(), "sleeper", "sleep", nil)
		called <- err
	}()
	time.Sleep(300 * time.Millisecond) // вызов дошёл до плагина и уснул

	started := time.Now()
	e.setPlugins(config.Plugin{Name: "sleeper", Enabled: false})
	e.waitState("sleeper", StateDisabled)
	if took := time.Since(started); took > 10*time.Second {
		t.Errorf("выключение ждало спящий плагин %s", took)
	}
	select {
	case err := <-called:
		if err == nil {
			t.Error("прерванный вызов вернул успех")
		}
	case <-time.After(10 * time.Second):
		t.Error("вызов так и не вернулся")
	}
}
