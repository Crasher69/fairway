package plugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"fairway/internal/config"
	"fairway/internal/events"
	"fairway/internal/i18n"
)

// Ограничения на один плагин.
const (
	// memoryLimitPages — предел линейной памяти модуля (страница — 64 КиБ).
	memoryLimitPages = 2048 // 128 МиБ
	initTimeout      = 30 * time.Second
	tickTimeout      = 5 * time.Minute
	eventTimeout     = 30 * time.Second
	callTimeout      = 30 * time.Second
)

// startTimeout — сколько может идти стартовая функция модуля (init() в
// Go-плагине). Переменная, а не константа: тест укорачивает её, чтобы не
// ждать полминуты зависшего init.
var startTimeout = initTimeout

// instance — один запущенный плагин. Все вызовы модуля идут из одной
// горутины (run), поэтому поля ниже без замков, кроме status.
type instance struct {
	manifest *Manifest
	entry    config.Plugin
	granted  map[Permission]bool
	host     *Host
	logger   *log.Logger
	journal  *journal

	// hooks — экземпляры для обработки запросов, у плагина вида hook.
	// Поднимаются после init основного экземпляра.
	hooks *hookPool

	// calls — вызовы со страницы плагина в панели. Их выполняет горутина
	// плагина между таймером и событиями: модуль однопоточный.
	calls chan *uiCall

	cache   wazero.CompilationCache
	runtime wazero.Runtime
	module  api.Module

	// pending — ответ последнего вызова хоста, ждёт result.
	pending []byte

	// Что плагин попросил во время последнего вызова (см. dispatch).
	tick         time.Duration
	tickSet      bool
	subscribe    []events.Type
	subscribeSet bool

	// aborted закрывается, когда вызов модуля отменён или плагин
	// остановлен: на нём просыпается сон плагина (см. nanosleep).
	aborted   chan struct{}
	abortOnce sync.Once

	mu     sync.Mutex
	status runtimeStatus
}

// runtimeStatus — то, что меняется у работающего плагина.
type runtimeStatus struct {
	State       State
	Error       string
	LastError   string
	LastErrorAt time.Time
	LastTick    time.Time
}

// uiCall — вызов со страницы плагина и канал для ответа.
type uiCall struct {
	method string
	params json.RawMessage
	reply  chan uiReply
}

type uiReply struct {
	result json.RawMessage
	err    error
}

func newInstance(m *Manifest, entry config.Plugin, host *Host, logger *log.Logger, j *journal) *instance {
	granted := make(map[Permission]bool, len(entry.Granted))
	for _, g := range entry.Granted {
		// Право действует, только если плагин его просил: выданное
		// «на всякий случай» не расширяет того, что объявлено в манифесте.
		if m.Has(Permission(g)) {
			granted[Permission(g)] = true
		}
	}
	return &instance{
		manifest: m,
		entry:    entry,
		granted:  granted,
		host:     host,
		logger:   logger,
		journal:  j,
		calls:    make(chan *uiCall),
		aborted:  make(chan struct{}),
		status:   runtimeStatus{State: StateStarting},
	}
}

// abort будит спящий плагин. Модуль после этого уже закрыт (отмена
// контекста вызова закрывает его в wazero), так что будить можно насовсем.
func (in *instance) abort() {
	in.abortOnce.Do(func() { close(in.aborted) })
}

// nanosleep — сон плагина (time.Sleep в Go-плагине), прерываемый отменой.
// Штатный WithSysNanosleep спит через time.Sleep мимо контекста: отмена
// вызова прерывает только код модуля, и плагин, уснувший на сутки, держал
// бы менеджер плагинов (остановка ждёт конца вызова) или копил бы
// брошенные экземпляры по 128 МиБ.
func (in *instance) nanosleep(ns int64) {
	if ns <= 0 {
		return
	}
	t := time.NewTimer(time.Duration(ns))
	defer t.Stop()
	select {
	case <-t.C:
	case <-in.aborted:
	}
}

func (in *instance) logf(format string, args ...any) {
	pluginLogf(in.logger, in.journal, in.manifest.Name, format, args...)
}

// pluginLogf пишет строку в лог fairway с именем плагина и в его журнал.
func pluginLogf(logger *log.Logger, j *journal, name, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if j != nil {
		j.add(line)
	}
	if logger != nil {
		logger.Printf(i18n.T("plugin %s: ")+"%s", name, line)
	}
}

func (in *instance) snapshot() runtimeStatus {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.status
}

func (in *instance) setState(state State, err error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.status.State = state
	in.status.Error = ""
	if err != nil {
		in.status.Error = err.Error()
	}
}

func (in *instance) noteError(err error) {
	in.logf("%v", err)
	in.mu.Lock()
	defer in.mu.Unlock()
	in.status.LastError = err.Error()
	in.status.LastErrorAt = time.Now()
}

// start компилирует и инстанцирует модуль.
func (in *instance) start(ctx context.Context, dir string) error {
	wasm, err := os.ReadFile(filepath.Join(dir, ModuleFile))
	if err != nil {
		return err
	}
	runtimeConfig := wazero.NewRuntimeConfig()
	if in.cache != nil {
		runtimeConfig = runtimeConfig.WithCompilationCache(in.cache)
	}
	in.runtime = wazero.NewRuntimeWithConfig(ctx, runtimeConfig.
		WithMemoryLimitPages(memoryLimitPages).
		// Отмена контекста прерывает зависший плагин, а не ждёт его вечно.
		WithCloseOnContextDone(true))

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, in.runtime); err != nil {
		return err
	}
	_, err = in.runtime.NewHostModuleBuilder(hostModule).
		NewFunctionBuilder().WithFunc(in.hostCall).Export("call").
		NewFunctionBuilder().WithFunc(in.hostResult).Export("result").
		Instantiate(ctx)
	if err != nil {
		return err
	}

	compiled, err := in.runtime.CompileModule(ctx, wasm)
	if err != nil {
		return i18n.Errorf("compiling %s: %w", ModuleFile, err)
	}
	for _, name := range []string{exportAlloc, exportHandle} {
		if _, ok := compiled.ExportedFunctions()[name]; !ok {
			return i18n.Errorf("%s does not export %s", ModuleFile, name)
		}
	}
	// Сообщения передаются через линейную память модуля. Без неё Memory()
	// вернул бы nil, и первая же запись уронила бы весь fairway — не
	// только плагин, а при включённом плагине и каждый следующий запуск.
	if len(compiled.ExportedMemories()) == 0 {
		return i18n.Errorf("%s does not export memory", ModuleFile)
	}
	// Плагин остановлен — спящий вызов просыпается.
	context.AfterFunc(ctx, in.abort)

	out := &lineWriter{log: func(line string) { in.logf("%s", line) }}
	moduleConfig := wazero.NewModuleConfig().
		WithName(in.manifest.Name).
		WithStartFunctions(exportInit).
		WithStdout(out).
		WithStderr(out).
		// Настоящие часы и случайность: по умолчанию wazero даёт
		// детерминированные, и плагин видел бы 1970 год.
		WithSysWalltime().
		WithSysNanotime().
		WithNanosleep(in.nanosleep).
		WithRandSource(rand.Reader)
	// Стартовая функция модуля (init() в Go-плагине) исполняется здесь, и
	// бесконечный цикл в ней держал бы плагин в «запускается» и ядро
	// процессора на 100%, пока плагин не выключат. wazero следит за
	// контекстом только во время вызова, так что таймаут дальше не мешает.
	initCtx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	defer context.AfterFunc(initCtx, in.abort)()
	in.module, err = in.runtime.InstantiateModule(initCtx, compiled, moduleConfig)
	return err
}

func (in *instance) close(ctx context.Context) {
	if in.runtime != nil {
		in.runtime.Close(ctx)
	}
}

// send передаёт плагину сообщение и ждёт ответа. Ошибка, которую вернул
// сам плагин, — *guestError: модуль жив. Любая другая значит, что модуль
// упал или прерван, и дальше с ним работать нельзя.
func (in *instance) send(ctx context.Context, timeout time.Duration, msg guestMessage) error {
	_, err := in.exchange(ctx, timeout, msg)
	return err
}

// exchange — send, который возвращает ещё и result из ответа плагина.
func (in *instance) exchange(ctx context.Context, timeout time.Duration, msg guestMessage) (result json.RawMessage, err error) {
	// Сбой на нашей стороне обмена — ошибка плагина, а не падение
	// процесса: прокси не должен умирать из-за чужого модуля.
	defer func() {
		if p := recover(); p != nil {
			result, err = nil, i18n.Errorf("plugin crashed: %v", p)
		}
	}()
	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Отмена или таймаут будят спящий плагин; stop — раньше cancel, иначе
	// штатное завершение вызова тоже считалось бы отменой.
	defer context.AfterFunc(ctx, in.abort)()
	mem := in.module.Memory()
	if mem == nil {
		return nil, i18n.Errorf("%s does not export memory", ModuleFile)
	}

	res, err := in.module.ExportedFunction(exportAlloc).Call(ctx, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	ptr := uint32(res[0])
	if !mem.Write(ptr, payload) {
		return nil, i18n.Errorf("%s returned a buffer outside of memory", exportAlloc)
	}
	res, err = in.module.ExportedFunction(exportHandle).Call(ctx, uint64(ptr), uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	outPtr, outLen := uint32(res[0]>>32), uint32(res[0])
	var reply guestReply
	if outLen > 0 {
		out, ok := mem.Read(outPtr, outLen)
		if !ok {
			return nil, i18n.Errorf("%s returned a reply outside of memory", exportHandle)
		}
		if err := json.Unmarshal(out, &reply); err != nil {
			return nil, i18n.Errorf("%s: reply is not JSON: %w", exportHandle, err)
		}
	}
	if reply.Error != "" {
		return nil, &guestError{msg: reply.Error}
	}
	return reply.Result, nil
}

type guestError struct{ msg string }

func (e *guestError) Error() string { return e.msg }

// hostCall — импорт fairway.call.
func (in *instance) hostCall(ctx context.Context, m api.Module, ptr, size uint32) uint32 {
	var reply hostReply
	var req hostRequest
	if data, ok := m.Memory().Read(ptr, size); !ok {
		reply.Error = "request outside of memory"
	} else if err := json.Unmarshal(data, &req); err != nil {
		reply.Error = "request is not JSON: " + err.Error()
	} else if result, err := in.dispatch(ctx, req); err != nil {
		reply.Error = err.Error()
	} else {
		reply.Result = result
	}
	in.pending, _ = json.Marshal(reply)
	return uint32(len(in.pending))
}

// hostResult — импорт fairway.result.
func (in *instance) hostResult(ctx context.Context, m api.Module, ptr uint32) {
	m.Memory().Write(ptr, in.pending)
	in.pending = nil
}

// run — жизнь плагина: запуск, init, дальше таймер и события до отмены
// контекста или падения модуля.
func (in *instance) run(ctx context.Context, dir string) {
	defer in.close(context.Background())

	err := in.start(ctx, dir)
	if err == nil {
		err = in.send(ctx, initTimeout, guestMessage{Type: messageInit, Settings: in.entry.Settings})
	}
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		// Даже ошибка, которую вернул сам плагин: не поднявшийся плагин
		// работать не должен.
		in.fail(err)
		return
	}
	in.setState(StateRunning, nil)
	in.logf("%s", i18n.T("started"))
	if in.hooks != nil {
		in.hooks.start(ctx)
		defer in.hooks.stop()
	}

	var (
		ticker      *time.Ticker
		tickC       <-chan time.Time
		eventsC     <-chan events.Event
		unsubscribe = func() {}
	)
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
		unsubscribe()
	}()
	// apply подхватывает то, что плагин попросил в последнем вызове:
	// таймер и подписку он может менять когда угодно, не только в init.
	apply := func() {
		if in.tickSet {
			in.tickSet = false
			if ticker != nil {
				ticker.Stop()
				ticker, tickC = nil, nil
			}
			if in.tick > 0 {
				ticker = time.NewTicker(in.tick)
				tickC = ticker.C
			}
		}
		if in.subscribeSet {
			in.subscribeSet = false
			unsubscribe()
			eventsC, unsubscribe = nil, func() {}
			if len(in.subscribe) > 0 && in.host.Bus != nil {
				eventsC, unsubscribe = in.host.Bus.Subscribe(in.subscribe...)
			}
		}
	}
	apply()

	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case <-tickC:
			err = in.send(ctx, tickTimeout, guestMessage{Type: messageTick})
			in.mu.Lock()
			in.status.LastTick = time.Now()
			in.mu.Unlock()
		case event, ok := <-eventsC:
			if !ok {
				eventsC = nil
				continue
			}
			err = in.send(ctx, eventTimeout, guestMessage{Type: messageEvent, Event: &event})
		case call := <-in.calls:
			// Контекст плагина, а не запроса панели: закрытая страница не
			// должна прерывать модуль посреди вызова.
			var result json.RawMessage
			result, err = in.exchange(ctx, callTimeout,
				guestMessage{Type: messageCall, Method: call.method, Params: call.params})
			call.reply <- uiReply{result: result, err: err}
			// Отказ плагина — ответ странице, а не ошибка самого плагина.
			var guestErr *guestError
			if errors.As(err, &guestErr) {
				err = nil
			}
		}
		if ctx.Err() != nil {
			return
		}
		var guestErr *guestError
		switch {
		case errors.As(err, &guestErr):
			in.noteError(guestErr)
		case err != nil:
			in.fail(err)
			return
		}
		apply()
	}
}

func (in *instance) fail(err error) {
	in.logf("%s%v", i18n.T("stopped: "), err)
	in.setState(StateFailed, err)
}

// lineWriter отдаёт вывод плагина в лог построчно.
type lineWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	log func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// Неполная строка ждёт продолжения.
			w.buf.Reset()
			w.buf.WriteString(line)
			return len(p), nil
		}
		w.log(line[:len(line)-1])
	}
}
