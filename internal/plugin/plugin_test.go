package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"fairway/internal/config"
	"fairway/internal/events"
)

// testWasm — собранный testdata/testplugin. Сборка идёт один раз на прогон:
// это обычный go build, только под wasip1.
var testWasm string

// testCache — общий кеш компиляции на все тесты: под -race компиляция
// модуля занимает десятки секунд, а модуль у всех тестов один.
var testCache = wazero.NewCompilationCache()

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fairway-plugin-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testWasm = filepath.Join(dir, ModuleFile)
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", testWasm, ".")
	cmd.Dir = filepath.Join("testdata", "testplugin")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building test plugin: %v\n%s", err, out)
		os.Exit(1)
	}
	minTick = 50 * time.Millisecond
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// syncBuffer — лог, который читают из теста, пока в него пишут плагины.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type env struct {
	t       *testing.T
	dir     string // каталог плагинов
	logs    *syncBuffer
	editor  *config.Editor
	manager *Manager
}

// waitLimit — сколько ждать плагин. Первый тест под -race платит за
// компиляцию модуля, поэтому с запасом.
const waitLimit = 3 * time.Minute

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{t: t, dir: filepath.Join(root, "plugins"), logs: &syncBuffer{}}

	cfg := &config.Config{Proxies: []config.Proxy{{Name: "manual", URL: "http://1.1.1.1:80"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[config.Config]
	current.Store(cfg)
	bus := &events.Bus{}

	e.editor = &config.Editor{Path: path, Current: current.Load}
	e.manager = NewManager(e.dir, Host{Config: current.Load, Editor: e.editor, Bus: bus},
		log.New(e.logs, "", 0))
	e.manager.Cache = testCache
	e.editor.Apply = func(c *config.Config) error {
		current.Store(c)
		bus.Publish(events.ConfigApplied, events.ConfigAppliedData{Proxies: len(c.Proxies)})
		e.manager.Apply(c)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.manager.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return e
}

func (e *env) install(name string, manifest string) {
	e.t.Helper()
	dir := filepath.Join(e.dir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifest), 0o644); err != nil {
		e.t.Fatal(err)
	}
	wasm, err := os.ReadFile(testWasm)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ModuleFile), wasm, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func manifest(name string, permissions []Permission, hosts ...string) string {
	m := Manifest{Name: name, Version: "1.0.0", Kind: KindBase, Permissions: permissions, HTTPHosts: hosts}
	data, _ := json.Marshal(m)
	return string(data)
}

// setPlugins меняет раздел plugins так же, как это сделает панель.
func (e *env) setPlugins(plugins ...config.Plugin) {
	e.t.Helper()
	if _, err := e.editor.Edit(func(c *config.Config) error {
		c.Plugins = plugins
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) waitLog(substr string) {
	e.t.Helper()
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if strings.Contains(e.logs.String(), substr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("в логе нет %q:\n%s", substr, e.logs.String())
}

func (e *env) waitState(name string, want State) Status {
	e.t.Helper()
	deadline := time.Now().Add(waitLimit)
	var last Status
	for time.Now().Before(deadline) {
		for _, st := range e.manager.Plugins() {
			if st.Name == name {
				last = st
				if st.State == want {
					return st
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("%s: состояние %q (%s), ожидалось %q\nлог:\n%s", name, last.State, last.Error, want, e.logs.String())
	return last
}

func settings(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

func TestPluginStartsAndStops(t *testing.T) {
	e := newEnv(t)
	e.install("hello", manifest("hello", nil))
	e.setPlugins(config.Plugin{Name: "hello", Enabled: true, Settings: settings(map[string]any{"greeting": "world"})})

	e.waitState("hello", StateRunning)
	e.waitLog("plugin hello: hello world")

	e.setPlugins(config.Plugin{Name: "hello", Enabled: false})
	e.waitState("hello", StateDisabled)
}

func TestPluginNeedsGrantedPermissions(t *testing.T) {
	e := newEnv(t)
	e.install("reader", manifest("reader", []Permission{ConfigRead}))
	e.setPlugins(config.Plugin{Name: "reader", Enabled: true})

	st := e.waitState("reader", StateNeedsPermissions)
	if len(st.Missing) != 1 || st.Missing[0] != ConfigRead {
		t.Fatalf("недостающие права: %v", st.Missing)
	}
	if strings.Contains(e.logs.String(), "plugin reader: hello") {
		t.Fatal("плагин запущен без прав")
	}

	e.setPlugins(config.Plugin{Name: "reader", Enabled: true, Granted: []string{string(ConfigRead)}})
	e.waitState("reader", StateRunning)
}

// Право, которого нет в манифесте, не действует, даже если его выдали.
func TestHostRefusesMethodsWithoutPermission(t *testing.T) {
	e := newEnv(t)
	e.install("sneaky", manifest("sneaky", nil))
	e.setPlugins(config.Plugin{Name: "sneaky", Enabled: true, Granted: []string{string(ConfigRead)},
		Settings: settings(map[string]any{"forbidden": "yes"})})

	e.waitLog("config.get: config.get: permission denied (config.read)")
}

func TestPluginInitErrorFails(t *testing.T) {
	e := newEnv(t)
	e.install("broken", manifest("broken", nil))
	e.setPlugins(config.Plugin{Name: "broken", Enabled: true, Settings: settings(map[string]any{"fail_init": true})})

	st := e.waitState("broken", StateFailed)
	if st.Error != "init refused" {
		t.Fatalf("ошибка %q", st.Error)
	}
}

func TestTickAndFetch(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	}))
	defer origin.Close()

	e := newEnv(t)
	perms := []Permission{Schedule, HTTPFetch}
	e.install("fetcher", manifest("fetcher", perms, "127.0.0.1"))
	e.install("stranger", manifest("stranger", perms, "example.com"))
	granted := []string{string(Schedule), string(HTTPFetch)}
	e.setPlugins(
		config.Plugin{Name: "fetcher", Enabled: true, Granted: granted,
			Settings: settings(map[string]any{"tick": "50ms", "fetch_url": origin.URL})},
		config.Plugin{Name: "stranger", Enabled: true, Granted: granted,
			Settings: settings(map[string]any{"tick": "50ms", "fetch_url": origin.URL})},
	)

	e.waitLog("plugin fetcher: fetch: 200 pong")
	e.waitLog(`plugin stranger: fetch: http.fetch: host "127.0.0.1" is not in http_hosts of the manifest`)
	st := e.waitState("stranger", StateRunning) // ошибка вызова — не падение
	if st.LastError == "" || st.LastTick == nil {
		t.Fatalf("статус %+v", st)
	}
}

func TestScheduleRejectsTooShortInterval(t *testing.T) {
	e := newEnv(t)
	e.install("hasty", manifest("hasty", []Permission{Schedule}))
	e.setPlugins(config.Plugin{Name: "hasty", Enabled: true, Granted: []string{string(Schedule)},
		Settings: settings(map[string]any{"tick": "1ms"})})

	st := e.waitState("hasty", StateFailed)
	if !strings.Contains(st.Error, "shorter than") {
		t.Fatalf("ошибка %q", st.Error)
	}
}

// Плагин получает событие о применённом конфиге и сам дописывает в него
// прокси — через тот же редактор, что и панель.
func TestEventsAndConfigEdit(t *testing.T) {
	e := newEnv(t)
	perms := []Permission{ConfigRead, ConfigWrite, Events}
	e.install("provider", manifest("provider", perms))
	e.setPlugins(config.Plugin{Name: "provider", Enabled: true,
		Granted:  []string{string(ConfigRead), string(ConfigWrite), string(Events)},
		Settings: settings(map[string]any{"add_proxy": "from-plugin"})})
	e.waitState("provider", StateRunning)

	// Любая правка конфига будит плагин.
	if _, err := e.editor.Edit(func(c *config.Config) error {
		c.Language = "en"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.waitLog("event config.applied: proxy from-plugin present")

	onDisk, err := config.Load(e.editor.Path)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range onDisk.Proxies {
		names = append(names, p.Name)
		if p.ID == "" {
			t.Fatalf("прокси %s без id", p.Name)
		}
	}
	if strings.Join(names, ",") != "manual,from-plugin" {
		t.Fatalf("прокси на диске: %v", names)
	}
	if len(onDisk.Plugins) != 1 {
		t.Fatal("правка плагина задела раздел plugins")
	}
}

func TestInvalidAndMissingPlugins(t *testing.T) {
	e := newEnv(t)
	e.install("bad", `{"name":"other","version":"1","kind":"base"}`)
	e.setPlugins(config.Plugin{Name: "ghost", Enabled: true})

	if st := e.waitState("bad", StateInvalid); !strings.Contains(st.Error, "does not match directory") {
		t.Fatalf("ошибка %q", st.Error)
	}
	e.waitState("ghost", StateMissing)
}
