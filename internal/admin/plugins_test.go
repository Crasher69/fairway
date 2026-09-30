package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fairway/internal/config"
	"fairway/internal/plugin"
)

// withPlugins подключает к серверу менеджер плагинов с одним установленным
// плагином "demo". Модуль в нём ненастоящий: запускать его в этих тестах
// незачем, проверяется только то, что панель говорит с менеджером и
// конфигом.
func withPlugins(t *testing.T, e *editable) *plugin.Manager {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plugins")
	demo := filepath.Join(dir, "demo")
	os.MkdirAll(filepath.Join(demo, "ui"), 0o755)
	manifest, _ := json.Marshal(plugin.Manifest{Name: "demo", Version: "1.2.3", Kind: plugin.KindBase,
		Title: "Demo", Permissions: []plugin.Permission{plugin.ConfigRead}})
	os.WriteFile(filepath.Join(demo, plugin.ManifestFile), manifest, 0o644)
	os.WriteFile(filepath.Join(demo, plugin.ModuleFile), []byte("not wasm"), 0o644)
	os.WriteFile(filepath.Join(demo, "ui", "index.html"), []byte("<script>alert(1)</script>"), 0o644)

	manager := plugin.NewManager(dir, plugin.Host{Config: e.read, Editor: e.srv.Editor}, nil)
	apply := e.srv.Editor.Apply
	e.srv.Editor.Apply = func(c *config.Config) error {
		if err := apply(c); err != nil {
			return err
		}
		manager.Apply(c)
		return nil
	}
	e.srv.Plugins = manager
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manager.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	manager.Apply(e.read())
	return manager
}

func getPlugins(t *testing.T, url string) pluginsResponse {
	t.Helper()
	code, body := send(t, "GET", url+"/api/plugins", nil)
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	var resp pluginsResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func waitPlugin(t *testing.T, url string, cond func(pluginView) bool) pluginView {
	t.Helper()
	var last pluginView
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range getPlugins(t, url).Plugins {
			if p.Name == "demo" {
				last = p
				if cond(p) {
					return p
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("плагин не пришёл в нужное состояние: %+v", last)
	return last
}

func TestPluginsListAndSave(t *testing.T) {
	e := newEditable(t)
	withPlugins(t, e)

	p := waitPlugin(t, e.url, func(p pluginView) bool { return p.Version != "" })
	if p.State != plugin.StateDisabled || p.Title != "Demo" || !p.HasUI || len(p.Granted) != 0 {
		t.Fatalf("плагин %+v", p)
	}

	// Включили без прав — ждёт прав.
	code, body := send(t, "PUT", e.url+"/api/plugins/demo", map[string]any{"enabled": true})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	waitPlugin(t, e.url, func(p pluginView) bool { return p.State == plugin.StateNeedsPermissions })

	// Права и настройки сохраняются в конфиг, включённость не теряется.
	code, body = send(t, "PUT", e.url+"/api/plugins/demo", map[string]any{
		"granted": []string{"config.read"}, "settings": map[string]any{"key": "value"}})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	onDisk := e.onDisk(t)
	if len(onDisk.Plugins) != 1 {
		t.Fatalf("в конфиге %+v", onDisk.Plugins)
	}
	entry := onDisk.Plugins[0]
	var settings bytes.Buffer
	json.Compact(&settings, entry.Settings)
	if !entry.Enabled || len(entry.Granted) != 1 || settings.String() != `{"key":"value"}` {
		t.Fatalf("запись %+v, настройки %s", entry, entry.Settings)
	}
	// Модуль ненастоящий — плагин падает при запуске, и панель это видит.
	failed := waitPlugin(t, e.url, func(p pluginView) bool { return p.State == plugin.StateFailed })
	if failed.Error == "" {
		t.Fatal("причина падения не видна")
	}

	// Настройки не объектом конфиг не примет.
	if code, _ := send(t, "PUT", e.url+"/api/plugins/demo", map[string]any{"settings": []int{1}}); code != http.StatusBadRequest {
		t.Fatalf("настройки-массив: статус %d", code)
	}
	// Пустые настройки из файла убираются.
	send(t, "PUT", e.url+"/api/plugins/demo", map[string]any{"settings": map[string]any{}})
	if s := e.onDisk(t).Plugins[0].Settings; s != nil {
		t.Fatalf("пустые настройки остались: %s", s)
	}
}

// Страница плагина отдаётся текстом: как HTML с адреса панели она
// выполнилась бы с правами панели.
func TestPluginUIServedAsText(t *testing.T) {
	e := newEditable(t)
	withPlugins(t, e)
	waitPlugin(t, e.url, func(p pluginView) bool { return p.HasUI })

	resp, err := http.Get(e.url + "/api/plugins/demo/ui")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("заголовки %v", resp.Header)
	}
	if string(body) != "<script>alert(1)</script>" {
		t.Fatalf("тело %q", body)
	}

	if code, _ := send(t, "GET", e.url+"/api/plugins/nobody/ui", nil); code != http.StatusNotFound {
		t.Fatalf("чужая страница: статус %d", code)
	}
}

func TestPluginCallNotRunning(t *testing.T) {
	e := newEditable(t)
	withPlugins(t, e)
	waitPlugin(t, e.url, func(p pluginView) bool { return p.Version != "" })

	code, body := send(t, "POST", e.url+"/api/plugins/demo/call", map[string]any{"method": "x"})
	if code != http.StatusConflict {
		t.Fatalf("статус %d: %s", code, body)
	}
	if code, _ := send(t, "POST", e.url+"/api/plugins/demo/call", map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("без метода: статус %d", code)
	}
	if code, body := send(t, "GET", e.url+"/api/plugins/demo/log", nil); code != http.StatusOK || body != "[]\n" {
		t.Fatalf("лог: %d %q", code, body)
	}
}

// Без менеджера (например, в тестах и старых сборках) панель отвечает
// пустым списком, а не ошибкой.
func TestPluginsWithoutManager(t *testing.T) {
	_, ts := newTestServer(t, "")
	resp := getPlugins(t, ts.URL)
	if len(resp.Plugins) != 0 || resp.Dir != "" {
		t.Fatalf("%+v", resp)
	}
}
