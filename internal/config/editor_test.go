package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fullConfig — конфиг, в котором заполнено всё, что умеет Config.
func fullConfig() *Config {
	mitm := true
	return &Config{
		Language:      "ru",
		AdminPassword: "secret",
		ProxyAuth:     ProxyAuth{Enabled: true, Users: []ProxyUser{{Login: "u", Password: "p"}}},
		Defaults:      Defaults{List: "all", MaxParallelProxies: 2},
		Proxies:       []Proxy{{ID: NewID(), Name: "a", Scheme: "http", Host: "1.1.1.1", Port: 80}},
		Lists:         []List{{Name: "all", Proxies: []string{"a"}}},
		Domains:       []Domain{{Pattern: "*", List: "all", MITM: &mitm}},
	}
}

// Clone обязан переносить всё: забытое поле молча пропадало бы из файла
// при любой правке из панели или плагина.
func TestCloneCopiesEverything(t *testing.T) {
	src := fullConfig()
	// Страховка от нового поля в Config, которое забыли и в fullConfig,
	// и в Clone: здесь пустых полей быть не должно.
	v := reflect.ValueOf(*src)
	for i := range v.NumField() {
		if v.Type().Field(i).IsExported() && v.Field(i).IsZero() {
			t.Fatalf("поле %s не заполнено в fullConfig — добавьте его и проверьте Clone", v.Type().Field(i).Name)
		}
	}

	want, _ := json.Marshal(src)
	got, _ := json.Marshal(src.Clone())
	if string(got) != string(want) {
		t.Fatalf("копия отличается:\n%s\n%s", got, want)
	}
}

func TestCloneIsDeep(t *testing.T) {
	src := fullConfig()
	dst := src.Clone()
	dst.ProxyAuth.Users[0].Login = "changed"
	dst.Proxies[0].Name = "changed"
	dst.Lists[0].Proxies[0] = "changed"
	*dst.Domains[0].MITM = false

	if src.ProxyAuth.Users[0].Login == "changed" || src.Proxies[0].Name == "changed" ||
		src.Lists[0].Proxies[0] == "changed" || !*src.Domains[0].MITM {
		t.Fatal("правка копии задела оригинал")
	}
}

func newTestEditor(t *testing.T) (*Editor, *[]*Config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &Config{Proxies: []Proxy{{Name: "a", URL: "http://1.1.1.1:80"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	current := cfg
	applied := &[]*Config{}
	return &Editor{
		Path:    path,
		Current: func() *Config { return current },
		Apply: func(c *Config) error {
			current = c
			*applied = append(*applied, c)
			return nil
		},
	}, applied
}

func TestEditorEditSavesAndApplies(t *testing.T) {
	e, applied := newTestEditor(t)
	before := e.Current()

	next, err := e.Edit(func(c *Config) error {
		c.Proxies = append(c.Proxies, Proxy{Name: "b", URL: "http://2.2.2.2:80"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(*applied) != 1 || (*applied)[0] != next {
		t.Fatal("новая версия не применена")
	}
	if len(before.Proxies) != 1 {
		t.Fatal("правка задела применённый конфиг")
	}
	onDisk, err := Load(e.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Proxies) != 2 || onDisk.Proxies[1].ID == "" {
		t.Fatalf("на диске %+v", onDisk.Proxies)
	}
}

func TestEditorRejectsInvalidWithoutTouchingFile(t *testing.T) {
	e, applied := newTestEditor(t)
	original, _ := os.ReadFile(e.Path)

	_, err := e.Edit(func(c *Config) error {
		c.Proxies = append(c.Proxies, Proxy{Name: "a", URL: "http://2.2.2.2:80"}) // имя занято
		return nil
	})
	if err == nil {
		t.Fatal("битый конфиг принят")
	}
	stop := errors.New("stop")
	if _, err := e.Edit(func(*Config) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("ошибка правки потерялась: %v", err)
	}
	after, _ := os.ReadFile(e.Path)
	if string(after) != string(original) || len(*applied) != 0 {
		t.Fatal("отклонённая правка тронула файл или пул")
	}
}

func TestEditorWithoutPath(t *testing.T) {
	var e *Editor
	if _, err := e.Edit(func(*Config) error { return nil }); !errors.Is(err, ErrNoEditor) {
		t.Fatalf("nil-редактор: %v", err)
	}
	if _, err := (&Editor{}).Reload(); !errors.Is(err, ErrNoEditor) {
		t.Fatalf("редактор без пути: %v", err)
	}
}

func TestEditorReload(t *testing.T) {
	e, applied := newTestEditor(t)
	if _, err := e.Reload(); err != nil || len(*applied) != 1 {
		t.Fatalf("перечитывание: %v", err)
	}

	os.WriteFile(e.Path, []byte("{битый"), 0o600)
	_, err := e.Reload()
	var reloadErr *ReloadError
	if !errors.As(err, &reloadErr) || reloadErr.Applying {
		t.Fatalf("ожидалась ошибка чтения, получено %v", err)
	}
	if len(*applied) != 1 {
		t.Fatal("битый файл применён")
	}
}
