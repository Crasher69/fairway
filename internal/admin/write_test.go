package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"fairway/internal/config"
)

// editable — сервер с включённой правкой: конфиг лежит в файле, применение
// повторяет то, что делает main.
type editable struct {
	srv     *Server
	url     string
	path    string
	applied int

	mu      sync.Mutex
	current *config.Config
}

func newEditable(t *testing.T) *editable {
	t.Helper()

	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	e := &editable{path: path, current: cfg}
	srv, ts := newTestServer(t, "")
	e.srv = srv
	e.url = ts.URL

	srv.Config = e.read
	srv.Editor = &Editor{
		Path:    path,
		Current: e.read,
		Apply: func(updated *config.Config) error {
			if err := srv.Pool.Apply(updated); err != nil {
				return err
			}
			e.mu.Lock()
			e.current = updated
			e.applied++
			e.mu.Unlock()
			return nil
		},
	}
	return e
}

func (e *editable) read() *config.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current
}

// onDisk читает конфиг с диска: правка обязана оказаться в файле, иначе
// переживёт только до перезапуска.
func (e *editable) onDisk(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(e.path)
	if err != nil {
		t.Fatalf("конфиг на диске не читается: %v", err)
	}
	return cfg
}

func send(t *testing.T, method, url string, body any) (int, string) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

func TestAddProxy(t *testing.T) {
	e := newEditable(t)

	code, body := send(t, "POST", e.url+"/api/proxies",
		config.Proxy{Name: "новый", Scheme: "socks5", Host: "9.9.9.9", Port: 1080,
			Login: "user", Password: "pass", Country: "RU", Comment: "куплен на месяц"})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}

	disk := e.onDisk(t)
	if len(disk.Proxies) != 3 {
		t.Fatalf("на диске %d прокси, ожидалось 3", len(disk.Proxies))
	}
	saved := disk.Proxies[2]
	if saved.Name != "новый" || saved.Scheme != "socks5" || saved.Host != "9.9.9.9" || saved.Port != 1080 {
		t.Errorf("прокси сохранён неверно: %+v", saved)
	}
	if saved.Login != "user" || saved.Password != "pass" || saved.Country != "RU" {
		t.Errorf("реквизиты и страна не сохранились: %+v", saved)
	}
	if got := saved.ConnectURL(); got != "socks5://user:pass@9.9.9.9:1080" {
		t.Errorf("строка подключения = %q", got)
	}
	if e.applied != 1 {
		t.Errorf("конфиг применён %d раз, ожидался 1", e.applied)
	}
}

func TestAddProxyRejectsDuplicateAndGarbage(t *testing.T) {
	e := newEditable(t)

	if code, _ := send(t, "POST", e.url+"/api/proxies", config.Proxy{Name: "fast", URL: "http://9.9.9.9:80"}); code != http.StatusBadRequest {
		t.Errorf("дубль имени принят со статусом %d", code)
	}
	if code, _ := send(t, "POST", e.url+"/api/proxies", config.Proxy{Name: "кривой", URL: "ftp://1.2.3.4:21"}); code != http.StatusBadRequest {
		t.Errorf("неподдерживаемая схема принята со статусом %d", code)
	}
	// Неизвестное поле — почти всегда опечатка, молча игнорировать нельзя.
	req := map[string]string{"name": "x", "url": "http://1.1.1.1:80", "urll": "опечатка"}
	if code, _ := send(t, "POST", e.url+"/api/proxies", req); code != http.StatusBadRequest {
		t.Errorf("неизвестное поле принято со статусом %d", code)
	}

	if disk := e.onDisk(t); len(disk.Proxies) != 2 {
		t.Errorf("отклонённые правки всё же попали на диск: %d прокси", len(disk.Proxies))
	}
}

// TestDeleteProxyCleansLists — удаляемый прокси надо выкинуть и из листов,
// иначе конфиг перестанет проходить проверку ссылочной целостности.
func TestDeleteProxyCleansLists(t *testing.T) {
	e := newEditable(t)

	code, body := send(t, "DELETE", e.url+"/api/proxies/slow", nil)
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}

	disk := e.onDisk(t)
	if len(disk.Proxies) != 1 || disk.Proxies[0].Name != "fast" {
		t.Errorf("прокси после удаления: %+v", disk.Proxies)
	}
	for _, l := range disk.Lists {
		for _, ref := range l.Proxies {
			if ref == "slow" {
				t.Errorf("лист %s всё ещё ссылается на удалённый прокси", l.Name)
			}
		}
	}
}

func TestDeleteMissingProxy(t *testing.T) {
	e := newEditable(t)
	if code, _ := send(t, "DELETE", e.url+"/api/proxies/нет-такого", nil); code != http.StatusBadRequest {
		t.Errorf("удаление несуществующего прокси вернуло %d", code)
	}
}

func TestSaveDomainCreatesAndUpdates(t *testing.T) {
	e := newEditable(t)

	mitm := true
	code, body := send(t, "PUT", e.url+"/api/domains",
		config.Domain{Pattern: "*.shop.ru", List: "main", MITM: &mitm, MaxConnsPerProxy: 4})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	if disk := e.onDisk(t); len(disk.Domains) != 2 {
		t.Fatalf("правил на диске: %d, ожидалось 2", len(disk.Domains))
	}

	// Повторное сохранение того же паттерна должно заменять, а не плодить.
	code, body = send(t, "PUT", e.url+"/api/domains",
		config.Domain{Pattern: "*.shop.ru", List: "main", MaxConnsPerProxy: 9})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	disk := e.onDisk(t)
	if len(disk.Domains) != 2 {
		t.Fatalf("правил на диске: %d, дубликат не должен появляться", len(disk.Domains))
	}
	for _, d := range disk.Domains {
		if d.Pattern == "*.shop.ru" && d.MaxConnsPerProxy != 9 {
			t.Errorf("правило не обновилось: %+v", d)
		}
	}
}

func TestSaveDomainRejectsUnknownList(t *testing.T) {
	e := newEditable(t)
	code, _ := send(t, "PUT", e.url+"/api/domains", config.Domain{Pattern: "a.ru", List: "нет-такого"})
	if code != http.StatusBadRequest {
		t.Errorf("ссылка на несуществующий лист принята со статусом %d", code)
	}
	if disk := e.onDisk(t); len(disk.Domains) != 1 {
		t.Error("битое правило записалось на диск")
	}
}

func TestSaveListAndDelete(t *testing.T) {
	e := newEditable(t)

	if code, body := send(t, "PUT", e.url+"/api/lists", config.List{Name: "запасной", Proxies: []string{"fast"}}); code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	if disk := e.onDisk(t); len(disk.Lists) != 2 {
		t.Fatalf("листов на диске: %d", len(disk.Lists))
	}

	if code, _ := send(t, "DELETE", e.url+"/api/lists/запасной", nil); code != http.StatusOK {
		t.Fatalf("удаление листа вернуло %d", code)
	}
	if disk := e.onDisk(t); len(disk.Lists) != 1 {
		t.Errorf("листов после удаления: %d", len(disk.Lists))
	}

	// Лист, на который ссылается правило домена, удалять нельзя.
	if code, _ := send(t, "DELETE", e.url+"/api/lists/main", nil); code != http.StatusBadRequest {
		t.Errorf("удаление используемого листа вернуло %d, ожидался отказ", code)
	}
}

func TestSaveDefaults(t *testing.T) {
	e := newEditable(t)
	body := config.Defaults{List: "main", AllowDirect: true, MaxConnsPerProxy: 64}
	if code, resp := send(t, "PUT", e.url+"/api/defaults", body); code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, resp)
	}
	disk := e.onDisk(t)
	if disk.Defaults.List != "main" || !disk.Defaults.AllowDirect || disk.Defaults.MaxConnsPerProxy != 64 {
		t.Errorf("defaults на диске: %+v", disk.Defaults)
	}
}

// TestReloadPicksUpManualEdit — кнопка «перечитать» должна применять правку
// файла сразу, не дожидаясь опроса сторожа.
func TestReloadPicksUpManualEdit(t *testing.T) {
	e := newEditable(t)

	edited := strings.Replace(testConfig, `{"name": "main", "proxies": ["fast", "slow"]}`,
		`{"name": "main", "proxies": ["fast"]}`, 1)
	if err := os.WriteFile(e.path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	code, body := send(t, "POST", e.url+"/api/config/reload", nil)
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	if got := e.read().Lists[0].Proxies; len(got) != 1 || got[0] != "fast" {
		t.Errorf("после перечитывания лист = %v", got)
	}
}

func TestReloadRejectsBrokenFile(t *testing.T) {
	e := newEditable(t)
	before := e.read()
	if err := os.WriteFile(e.path, []byte(`{"proxies": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := send(t, "POST", e.url+"/api/config/reload", nil); code != http.StatusBadRequest {
		t.Errorf("битый файл принят со статусом %d", code)
	}
	if e.read() != before {
		t.Error("в работе оказался битый конфиг")
	}
}

// TestEditsDoNotMutateLiveConfig — правка обязана работать с копией:
// живой конфиг в этот момент читают обработчики запросов.
func TestEditsDoNotMutateLiveConfig(t *testing.T) {
	e := newEditable(t)
	before := e.read()
	proxiesBefore := len(before.Proxies)

	if code, body := send(t, "POST", e.url+"/api/proxies", config.Proxy{Name: "ещё", URL: "http://8.8.8.8:80"}); code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}
	if len(before.Proxies) != proxiesBefore {
		t.Error("правка изменила прежний конфиг на месте")
	}
	if len(e.read().Proxies) != proxiesBefore+1 {
		t.Error("новый конфиг не применён")
	}
}

// TestWriteDisabledWithoutEditor — при -upstream конфиг собран из флагов,
// сохранять его некуда, и панель должна честно об этом сказать.
func TestWriteDisabledWithoutEditor(t *testing.T) {
	_, ts := newTestServer(t, "") // Editor не задан
	code, body := send(t, "POST", ts.URL+"/api/proxies", config.Proxy{Name: "x", URL: "http://1.1.1.1:80"})
	if code != http.StatusNotImplemented {
		t.Errorf("статус %d (%s), ожидался 501", code, strings.TrimSpace(body))
	}
}

func TestWriteRequiresToken(t *testing.T) {
	e := newEditable(t)
	e.srv.Token = "секрет"
	code, _ := send(t, "POST", e.url+"/api/proxies", config.Proxy{Name: "x", URL: "http://1.1.1.1:80"})
	if code != http.StatusUnauthorized {
		t.Errorf("правка без токена прошла со статусом %d", code)
	}
}

func TestUpdateProxy(t *testing.T) {
	e := newEditable(t)

	code, body := send(t, "PUT", e.url+"/api/proxies/slow",
		config.Proxy{Name: "slow", Scheme: "socks5", Host: "7.7.7.7", Port: 1080,
			Login: "u", Password: "p", Country: "NL", Comment: "переехал"})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}

	disk := e.onDisk(t)
	var updated *config.Proxy
	for i := range disk.Proxies {
		if disk.Proxies[i].Name == "slow" {
			updated = &disk.Proxies[i]
		}
	}
	if updated == nil {
		t.Fatal("прокси пропал после правки")
	}
	if updated.Host != "7.7.7.7" || updated.Scheme != "socks5" || updated.Country != "NL" {
		t.Errorf("правка не сохранилась: %+v", updated)
	}
}

// TestRenameProxyFixesLists — переименование без починки ссылок развалило бы
// конфиг: лист остался бы указывать на несуществующее имя.
func TestRenameProxyFixesLists(t *testing.T) {
	e := newEditable(t)

	code, body := send(t, "PUT", e.url+"/api/proxies/slow",
		config.Proxy{Name: "slow-new", Scheme: "http", Host: "2.2.2.2", Port: 8080})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}

	disk := e.onDisk(t)
	names := map[string]bool{}
	for _, p := range disk.Proxies {
		names[p.Name] = true
	}
	if !names["slow-new"] || names["slow"] {
		t.Errorf("прокси после переименования: %v", names)
	}
	for _, l := range disk.Lists {
		for _, ref := range l.Proxies {
			if ref == "slow" {
				t.Errorf("лист %s ссылается на старое имя", l.Name)
			}
		}
	}
}

func TestUpdateProxyRejectsNameClash(t *testing.T) {
	e := newEditable(t)
	code, _ := send(t, "PUT", e.url+"/api/proxies/slow",
		config.Proxy{Name: "fast", Scheme: "http", Host: "2.2.2.2", Port: 8080})
	if code != http.StatusBadRequest {
		t.Errorf("переименование в занятое имя прошло со статусом %d", code)
	}
}

func TestUpdateMissingProxy(t *testing.T) {
	e := newEditable(t)
	code, _ := send(t, "PUT", e.url+"/api/proxies/нет-такого",
		config.Proxy{Name: "x", Scheme: "http", Host: "1.1.1.1", Port: 80})
	if code != http.StatusBadRequest {
		t.Errorf("правка несуществующего прокси вернула %d", code)
	}
}

// TestAddProxyFromPastedURL — строку из прайса поставщика можно вставить
// целиком, сервер разложит её по полям.
func TestAddProxyFromPastedURL(t *testing.T) {
	e := newEditable(t)

	code, body := send(t, "POST", e.url+"/api/proxies",
		map[string]string{"name": "вставленный", "url": "socks5://bob:secret@8.8.8.8:1080"})
	if code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}

	disk := e.onDisk(t)
	saved := disk.Proxies[len(disk.Proxies)-1]
	if saved.Scheme != "socks5" || saved.Host != "8.8.8.8" || saved.Port != 1080 {
		t.Errorf("строка не разложилась: %+v", saved)
	}
	if saved.Login != "bob" || saved.Password != "secret" {
		t.Errorf("креды потеряны: %+v", saved)
	}
	if saved.URL != "" {
		t.Errorf("в файле осталась строка url: %q", saved.URL)
	}
}
