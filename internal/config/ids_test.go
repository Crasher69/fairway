package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// legacyConfig — конфиг из времён до id: прокси без id, листы по именам.
const legacyConfig = `{
  "proxies": [
    {"name": "a", "url": "http://1.1.1.1:80"},
    {"name": "b", "url": "http://2.2.2.2:80"}
  ],
  "lists": [
    {"name": "both", "proxies": ["a", "b"]},
    {"name": "only-b", "proxies": ["b"]}
  ],
  "domains": [{"pattern": "*", "list": "both"}]
}`

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewIDIsUUIDv4(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if !uuidV4.MatchString(id) {
			t.Fatalf("не UUIDv4: %q", id)
		}
		if seen[id] {
			t.Fatalf("повтор id: %q", id)
		}
		seen[id] = true
	}
}

// memberNames — имена прокси листа через запятую.
func memberNames(t *testing.T, cfg *Config, list string) string {
	t.Helper()
	for _, l := range cfg.Lists {
		if l.Name != list {
			continue
		}
		names := make([]string, 0, len(l.Proxies))
		for _, id := range l.Proxies {
			p, ok := cfg.ProxyByID(id)
			if !ok {
				t.Fatalf("лист %s: ссылка %q не id прокси", list, id)
			}
			names = append(names, p.Name)
		}
		return strings.Join(names, ",")
	}
	t.Fatalf("нет листа %s", list)
	return ""
}

// TestLegacyNameBindingsMigrateToIDs — главное в миграции: привязки,
// заданные именами, не теряются, а переезжают на id.
func TestLegacyNameBindingsMigrateToIDs(t *testing.T) {
	cfg, err := Parse([]byte(legacyConfig))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Migrated() {
		t.Error("конфиг без id не помечен как дополненный")
	}
	for _, p := range cfg.Proxies {
		if !uuidV4.MatchString(p.ID) {
			t.Errorf("прокси %s: id %q", p.Name, p.ID)
		}
	}
	if got := memberNames(t, cfg, "both"); got != "a,b" {
		t.Errorf("лист both: %s", got)
	}
	if got := memberNames(t, cfg, "only-b"); got != "b" {
		t.Errorf("лист only-b: %s", got)
	}
}

// TestMigratedConfigIsStable — сохранённый после миграции конфиг читается
// без изменений: те же id, ничего не дописывается.
func TestMigratedConfigIsStable(t *testing.T) {
	first, err := Parse([]byte(legacyConfig))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Migrated() {
		t.Error("уже переведённый конфиг снова помечен как дополненный")
	}
	for i := range first.Proxies {
		if first.Proxies[i].ID != second.Proxies[i].ID {
			t.Errorf("id прокси %s сменился: %q -> %q", first.Proxies[i].Name, first.Proxies[i].ID, second.Proxies[i].ID)
		}
	}
}

// TestLoadWritesIDsBack — без записи на диск id выдумывались бы заново при
// каждом чтении файла.
func TestLoadWritesIDsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Migrated() {
		t.Error("id не были записаны в файл")
	}
	for i := range first.Proxies {
		if first.Proxies[i].ID != second.Proxies[i].ID {
			t.Errorf("id прокси %s не пережил перечитывание", first.Proxies[i].Name)
		}
	}
	if got := memberNames(t, second, "both"); got != "a,b" {
		t.Errorf("лист both после перечитывания: %s", got)
	}
}

// TestListMixesIDsAndNames — в файле, поправленном руками, лист может
// ссылаться на одни прокси по id, на другие по имени.
func TestListMixesIDsAndNames(t *testing.T) {
	raw := `{
  "proxies": [
    {"id": "11111111-1111-4111-8111-111111111111", "name": "a", "url": "http://1.1.1.1:80"},
    {"name": "b", "url": "http://2.2.2.2:80"}
  ],
  "lists": [{"name": "both", "proxies": ["11111111-1111-4111-8111-111111111111", "b"]}]
}`
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[0].ID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("заданный id заменён: %q", cfg.Proxies[0].ID)
	}
	if got := memberNames(t, cfg, "both"); got != "a,b" {
		t.Errorf("лист both: %s", got)
	}
}

// TestIDWinsOverName — если строка в листе совпадает и с id одного прокси,
// и с именем другого, она означает id: id и есть основная привязка.
func TestIDWinsOverName(t *testing.T) {
	raw := `{
  "proxies": [
    {"id": "b", "name": "a", "url": "http://1.1.1.1:80"},
    {"id": "x", "name": "b", "url": "http://2.2.2.2:80"}
  ],
  "lists": [{"name": "l", "proxies": ["b"]}]
}`
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := memberNames(t, cfg, "l"); got != "a" {
		t.Errorf("лист l: %s, ожидался прокси a (с id b)", got)
	}
}

func TestProxyIDErrors(t *testing.T) {
	cases := map[string]string{
		"повтор id": `{"proxies": [
			{"id": "same", "name": "a", "url": "http://1.1.1.1:80"},
			{"id": "same", "name": "b", "url": "http://2.2.2.2:80"}]}`,
		"ссылка в никуда": `{"proxies": [{"name": "a", "url": "http://1.1.1.1:80"}],
			"lists": [{"name": "l", "proxies": ["нет"]}]}`,
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: конфиг принят", name)
		}
	}
}

func TestImportAssignsIDs(t *testing.T) {
	cfg := Example()
	result := cfg.ImportProxies("1.1.1.1:80\n2.2.2.2:80", "", "", "", "")
	if result.AddedN != 2 {
		t.Fatalf("добавлено %d", result.AddedN)
	}
	for _, p := range result.Added {
		if !uuidV4.MatchString(p.ID) {
			t.Errorf("импортированный %s без id: %q", p.Name, p.ID)
		}
	}
	if cfg.Proxies[0].ID == cfg.Proxies[1].ID {
		t.Error("у импортированных одинаковый id")
	}
}

// TestWatcherIgnoresItsOwnIDWriteBack — запись id обратно в файл делает
// сам сторож, и принимать её за новую правку незачем.
func TestWatcherIgnoresItsOwnIDWriteBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	w := NewWatcher(path, 0)
	if err := os.WriteFile(path, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, ok := w.poll(nil)
	if !ok || !cfg.Migrated() {
		t.Fatalf("новый файл не применён или не дополнен id: ok=%v", ok)
	}
	if _, again := w.poll(nil); again {
		t.Error("своя же запись id принята за новую правку")
	}
}
