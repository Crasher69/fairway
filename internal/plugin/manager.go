package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"

	"fairway/internal/config"
	"fairway/internal/i18n"
)

// State — состояние плагина для панели.
type State string

const (
	// StateInvalid — пакет не читается: битый манифест и т.п.
	StateInvalid State = "invalid"
	// StateMissing — плагин есть в конфиге, но не установлен.
	StateMissing State = "missing"
	// StateDisabled — установлен, но не включён.
	StateDisabled State = "disabled"
	// StateNeedsPermissions — включён, но выданы не все права из манифеста.
	StateNeedsPermissions State = "needs_permissions"
	StateStarting         State = "starting"
	StateRunning          State = "running"
	// StateFailed — не запустился или упал; поднимется при следующем
	// применении конфига.
	StateFailed State = "failed"
)

// Status — плагин глазами панели.
type Status struct {
	Name           string          `json:"name"`
	Version        string          `json:"version,omitempty"`
	Title          string          `json:"title,omitempty"`
	Description    string          `json:"description,omitempty"`
	Permissions    []Permission    `json:"permissions,omitempty"`
	HTTPHosts      []string        `json:"http_hosts,omitempty"`
	Missing        []Permission    `json:"missing_permissions,omitempty"`
	SettingsSchema json.RawMessage `json:"settings_schema,omitempty"`
	Kind           Kind            `json:"kind,omitempty"`
	Hooks          *Hooks          `json:"hooks,omitempty"`
	HasUI          bool            `json:"has_ui"`
	Enabled        bool            `json:"enabled"`
	State          State           `json:"state"`
	Error          string          `json:"error,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	LastErrorAt    *time.Time      `json:"last_error_at,omitempty"`
	LastTick       *time.Time      `json:"last_tick,omitempty"`
}

// Manager находит плагины в каталоге и держит запущенными те, что включены
// в конфиге.
type Manager struct {
	Dir    string
	Host   Host
	Logger *log.Logger
	// Cache — кеш скомпилированных модулей. Компиляция plugin.wasm занимает
	// секунды; с кешем на диске перезапуск плагина и самого fairway
	// обходится без неё. NewManager ставит кеш в памяти.
	Cache wazero.CompilationCache

	apply chan *config.Config

	mu       sync.Mutex
	known    map[string]*Status  // последний обход каталога и конфига
	running  map[string]*running // запущенные
	journals map[string]*journal // лог каждого плагина, переживает перезапуск

	// hooks — обработчики запросов запущенных плагинов по порядку имён.
	// Читается на каждом запросе через прокси, поэтому без замка.
	hooks atomic.Pointer[[]*hookPool]
}

type running struct {
	inst     *instance
	cancel   context.CancelFunc
	done     chan struct{}
	entry    config.Plugin
	manifest *Manifest
	module   fileStamp
	hooks    *hookPool
}

// fileStamp — версия plugin.wasm: заменили файл — плагин перезапускается.
type fileStamp struct {
	size    int64
	modTime time.Time
}

func NewManager(dir string, host Host, logger *log.Logger) *Manager {
	return &Manager{
		Dir:      dir,
		Host:     host,
		Logger:   logger,
		Cache:    wazero.NewCompilationCache(),
		apply:    make(chan *config.Config, 1),
		known:    map[string]*Status{},
		running:  map[string]*running{},
		journals: map[string]*journal{},
	}
}

// ErrNotRunning — вызов плагина, который не запущен.
var ErrNotRunning = errors.New("plugin is not running")

// ErrNoUI — у плагина нет своей страницы.
var ErrNoUI = errors.New("plugin has no UI")

// UIFile — страница плагина в пакете: один самодостаточный HTML, стили и
// скрипты внутри. Панель показывает его в изолированном iframe.
const UIFile = "ui/index.html"

// Call передаёт плагину вызов с его страницы в панели и ждёт ответа.
func (m *Manager) Call(ctx context.Context, name, method string, params json.RawMessage) (json.RawMessage, error) {
	m.mu.Lock()
	r, ok := m.running[name]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotRunning
	}
	call := &uiCall{method: method, params: params, reply: make(chan uiReply, 1)}
	select {
	case r.inst.calls <- call:
	case <-r.done:
		return nil, ErrNotRunning
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case reply := <-call.reply:
		return reply.result, reply.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// UI отдаёт страницу плагина.
func (m *Manager) UI(name string) ([]byte, error) {
	m.mu.Lock()
	st, ok := m.known[name]
	m.mu.Unlock()
	if !ok || !st.HasUI {
		return nil, ErrNoUI
	}
	return os.ReadFile(filepath.Join(m.Dir, name, filepath.FromSlash(UIFile)))
}

// Log — последние строки лога плагина, старые первыми.
func (m *Manager) Log(name string) []LogLine {
	m.mu.Lock()
	j := m.journals[name]
	m.mu.Unlock()
	if j == nil {
		return nil
	}
	return j.snapshot()
}

func (m *Manager) journalFor(name string) *journal {
	j := m.journals[name]
	if j == nil {
		j = &journal{}
		m.journals[name] = j
	}
	return j
}

// Apply сообщает о новом конфиге. Не блокируется: конфиг применяется из
// Run. Это важно — Apply вызывается и тогда, когда конфиг поменял сам
// плагин, изнутри своего вызова, и синхронная сверка ждала бы саму себя.
func (m *Manager) Apply(cfg *config.Config) {
	for {
		select {
		case m.apply <- cfg:
			return
		default:
		}
		// В очереди устаревший конфиг — он больше не нужен.
		select {
		case <-m.apply:
		default:
		}
	}
}

// Run сверяет плагины с конфигом до отмены контекста, потом останавливает
// все.
func (m *Manager) Run(ctx context.Context) {
	defer m.stopAll()
	for {
		select {
		case <-ctx.Done():
			return
		case cfg := <-m.apply:
			m.reconcile(ctx, cfg)
		}
	}
}

// Plugins — все известные плагины: установленные и упомянутые в конфиге.
func (m *Manager) Plugins() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.known))
	for name, st := range m.known {
		s := *st
		if r, ok := m.running[name]; ok {
			rs := r.inst.snapshot()
			s.State, s.Error = rs.State, rs.Error
			s.LastError = rs.LastError
			if !rs.LastErrorAt.IsZero() {
				s.LastErrorAt = &rs.LastErrorAt
			}
			if !rs.LastTick.IsZero() {
				s.LastTick = &rs.LastTick
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type discovered struct {
	manifest *Manifest
	module   fileStamp
	err      error
}

// scan обходит каталог плагинов. Каталога может не быть — плагинов нет.
func (m *Manager) scan() map[string]discovered {
	found := map[string]discovered{}
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		if !os.IsNotExist(err) {
			m.logf(i18n.T("plugins directory %s: %v"), m.Dir, err)
		}
		return found
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(m.Dir, e.Name())
		manifest, err := LoadManifest(dir)
		var stamp fileStamp
		if err == nil {
			info, statErr := os.Stat(filepath.Join(dir, ModuleFile))
			if statErr != nil {
				err = statErr
			} else {
				stamp = fileStamp{size: info.Size(), modTime: info.ModTime()}
			}
		}
		found[e.Name()] = discovered{manifest: manifest, module: stamp, err: err}
	}
	return found
}

func (m *Manager) reconcile(ctx context.Context, cfg *config.Config) {
	found := m.scan()
	entries := map[string]config.Plugin{}
	for _, p := range cfg.Plugins {
		entries[p.Name] = p
	}

	known := map[string]*Status{}
	want := map[string]*running{}
	for name, d := range found {
		st := &Status{Name: name, State: StateDisabled}
		entry, inConfig := entries[name]
		st.Enabled = inConfig && entry.Enabled
		if d.err != nil {
			st.State, st.Error = StateInvalid, d.err.Error()
			known[name] = st
			continue
		}
		mf := d.manifest
		st.Version, st.Title, st.Description = mf.Version, mf.Title, mf.Description
		st.Permissions, st.HTTPHosts, st.SettingsSchema = mf.Permissions, mf.HTTPHosts, mf.SettingsSchema
		st.Kind, st.Hooks = mf.Kind, mf.Hooks
		st.Missing = mf.Missing(entry.Granted)
		if info, err := os.Stat(filepath.Join(m.Dir, name, filepath.FromSlash(UIFile))); err == nil && !info.IsDir() {
			st.HasUI = true
		}
		switch {
		case !st.Enabled:
		case len(st.Missing) > 0:
			st.State = StateNeedsPermissions
		default:
			st.State = StateStarting
			want[name] = &running{entry: entry, manifest: mf, module: d.module}
		}
		known[name] = st
	}
	for name, entry := range entries {
		if _, ok := found[name]; !ok {
			known[name] = &Status{Name: name, Enabled: entry.Enabled, State: StateMissing}
		}
	}

	m.mu.Lock()
	var stop []*running
	for name, r := range m.running {
		w, ok := want[name]
		if ok && !r.changed(w) {
			delete(want, name) // уже работает как надо
			continue
		}
		stop = append(stop, r)
		delete(m.running, name)
	}
	m.known = known
	m.mu.Unlock()

	// Останавливаем без замка: остановка ждёт, пока плагин доделает вызов,
	// а тот может читать статусы.
	for _, r := range stop {
		r.stop()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for name, w := range want {
		j := m.journalFor(name)
		dir := filepath.Join(m.Dir, name)
		w.inst = m.newInstance(w, j)
		if w.manifest.Kind == KindHook && w.manifest.Hooks != nil {
			w.hooks = newHookPool(name, *w.manifest.Hooks, dir, w.entry.Settings,
				func() *instance { return m.newInstance(w, j) },
				func(format string, args ...any) { pluginLogf(m.Logger, j, name, format, args...) })
			w.inst.hooks = w.hooks
		}
		runCtx, cancel := context.WithCancel(ctx)
		w.cancel, w.done = cancel, make(chan struct{})
		m.running[name] = w
		go func() {
			defer close(w.done)
			w.inst.run(runCtx, dir)
		}()
	}
	m.publishHooks()
}

func (m *Manager) newInstance(r *running, j *journal) *instance {
	in := newInstance(r.manifest, r.entry, &m.Host, m.Logger, j)
	in.cache = m.Cache
	return in
}

// publishHooks обновляет список обработчиков запросов. Вызывается под m.mu.
func (m *Manager) publishHooks() {
	var pools []*hookPool
	for _, r := range m.running {
		if r.hooks != nil {
			pools = append(pools, r.hooks)
		}
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].name < pools[j].name })
	m.hooks.Store(&pools)
}

// changed — надо ли перезапустить плагин: другие настройки или права,
// обновлённый пакет, или он упал.
func (r *running) changed(w *running) bool {
	return r.inst.snapshot().State == StateFailed ||
		r.manifest.Version != w.manifest.Version ||
		r.module != w.module ||
		!bytes.Equal(r.entry.Settings, w.entry.Settings) ||
		!slices.Equal(r.entry.Granted, w.entry.Granted)
}

func (r *running) stop() {
	r.cancel()
	<-r.done
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.running
	m.running = map[string]*running{}
	m.publishHooks()
	m.mu.Unlock()
	for _, r := range all {
		r.stop()
	}
}

func (m *Manager) logf(format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Printf(format, args...)
	}
}
