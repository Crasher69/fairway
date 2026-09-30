package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
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

	mu      sync.Mutex
	known   map[string]*Status  // последний обход каталога и конфига
	running map[string]*running // запущенные
}

type running struct {
	inst     *instance
	cancel   context.CancelFunc
	done     chan struct{}
	entry    config.Plugin
	manifest *Manifest
	module   fileStamp
}

// fileStamp — версия plugin.wasm: заменили файл — плагин перезапускается.
type fileStamp struct {
	size    int64
	modTime time.Time
}

func NewManager(dir string, host Host, logger *log.Logger) *Manager {
	return &Manager{
		Dir:     dir,
		Host:    host,
		Logger:  logger,
		Cache:   wazero.NewCompilationCache(),
		apply:   make(chan *config.Config, 1),
		known:   map[string]*Status{},
		running: map[string]*running{},
	}
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
		st.Missing = mf.Missing(entry.Granted)
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
		w.inst = newInstance(w.manifest, w.entry, &m.Host, m.Logger)
		w.inst.cache = m.Cache
		runCtx, cancel := context.WithCancel(ctx)
		w.cancel, w.done = cancel, make(chan struct{})
		m.running[name] = w
		dir := filepath.Join(m.Dir, name)
		go func() {
			defer close(w.done)
			w.inst.run(runCtx, dir)
		}()
	}
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
