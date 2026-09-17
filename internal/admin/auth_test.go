package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hashed, err := HashPassword("верный пароль")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hashed, "верный пароль") {
		t.Fatalf("пароль виден в хеше: %s", hashed)
	}
	if !passwordMatches(hashed, "верный пароль") {
		t.Error("верный пароль не подошёл к своему хешу")
	}
	if passwordMatches(hashed, "неверный пароль") {
		t.Error("чужой пароль подошёл")
	}
	// Хеш солёный: два вызова дают разные строки, иначе одинаковые пароли
	// узнавались бы по совпадению хешей.
	again, err := HashPassword("верный пароль")
	if err != nil {
		t.Fatal(err)
	}
	if again == hashed {
		t.Error("хеш без соли: два вызова дали одну строку")
	}
}

// TestPlainPasswordInConfigWorks — пароль, вписанный в файл руками, должен
// работать: иначе задать его без запущенной панели было бы нечем.
func TestPlainPasswordInConfigWorks(t *testing.T) {
	if !passwordMatches("открытый", "открытый") {
		t.Error("открытый пароль из файла не сработал")
	}
	if passwordMatches("открытый", "другой") {
		t.Error("чужой пароль подошёл к открытому")
	}
}

// client с cookie-банкой: вход по паролю выдаёт сессию в cookie, и без
// хранения cookie дальнейшие запросы не прошли бы.
func clientWithJar(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func postJSON(t *testing.T, c *http.Client, url string, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func get(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestLoginWithPassword — весь путь: без входа закрыто, форма входа
// доступна, после верного пароля API открывается, после выхода закрывается
// снова.
func TestLoginWithPassword(t *testing.T) {
	e := newEditable(t)
	e.srv.Token = "" // токена нет, остаётся только пароль
	hashed, err := HashPassword("пароль от панели")
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.read()
	cfg.AdminPassword = hashed

	c := clientWithJar(t)
	if code := get(t, c, e.url+"/api/overview"); code != http.StatusUnauthorized {
		t.Fatalf("без входа API отдал %d, ожидался 401", code)
	}
	// Оболочка панели обязана открываться: иначе пароль вводить негде.
	if code := get(t, c, e.url+"/"); code != http.StatusOK {
		t.Fatalf("страница входа отдала %d", code)
	}
	if code := get(t, c, e.url+"/app.js"); code != http.StatusOK {
		t.Fatalf("app.js отдал %d", code)
	}
	if code := get(t, c, e.url+"/api/auth"); code != http.StatusOK {
		t.Fatalf("/api/auth отдал %d", code)
	}

	if code, body := postJSON(t, c, e.url+"/api/login", map[string]string{"password": "не тот"}); code != http.StatusUnauthorized {
		t.Fatalf("неверный пароль принят: %d %s", code, body)
	}
	if code, body := postJSON(t, c, e.url+"/api/login", map[string]string{"password": "пароль от панели"}); code != http.StatusNoContent {
		t.Fatalf("верный пароль отвергнут: %d %s", code, body)
	}
	if code := get(t, c, e.url+"/api/overview"); code != http.StatusOK {
		t.Fatalf("после входа API отдал %d", code)
	}

	if code, _ := postJSON(t, c, e.url+"/api/logout", nil); code != http.StatusNoContent {
		t.Fatal("выход не сработал")
	}
	if code := get(t, c, e.url+"/api/overview"); code != http.StatusUnauthorized {
		t.Fatalf("после выхода API отдал %d, ожидался 401", code)
	}
}

// TestTokenStillWorksWithPasswordSet — пароль не отменяет ссылку с токеном:
// оба пути в панель должны работать одновременно.
func TestTokenStillWorksWithPasswordSet(t *testing.T) {
	e := newEditable(t)
	e.srv.Token = "секрет"
	hashed, err := HashPassword("пароль от панели")
	if err != nil {
		t.Fatal(err)
	}
	e.read().AdminPassword = hashed

	c := clientWithJar(t)
	if code := get(t, c, e.url+"/api/overview?token=секрет"); code != http.StatusOK {
		t.Fatalf("токен перестал пускать: %d", code)
	}
}

// TestSavePasswordStoresHash — панель обязана класть в конфиг хеш, а не сам
// пароль: файл копируют и кладут в бэкапы.
func TestSavePasswordStoresHash(t *testing.T) {
	e := newEditable(t)
	// Токен задан, потому что с этого момента панель закрыта: пароль,
	// поставленный первым же запросом, начинает действовать сразу.
	e.srv.Token = "секрет"
	auth := "?token=секрет"

	if code, body := send(t, "PUT", e.url+"/api/password"+auth, map[string]string{"password": "корот"}); code == http.StatusOK {
		t.Fatalf("пароль короче восьми символов принят: %s", body)
	}
	if code, body := send(t, "PUT", e.url+"/api/password"+auth, map[string]string{"password": "длинный пароль"}); code != http.StatusOK {
		t.Fatalf("статус %d: %s", code, body)
	}

	stored := e.onDisk(t).AdminPassword
	if stored == "" || strings.Contains(stored, "длинный пароль") {
		t.Fatalf("в конфиге не хеш: %q", stored)
	}
	if !passwordMatches(stored, "длинный пароль") {
		t.Error("сохранённый хеш не принимает свой пароль")
	}

	// Хеш не должен уезжать в браузер: панели достаточно знать, задан
	// пароль или нет.
	code, body := send(t, "GET", e.url+"/api/config"+auth, nil)
	if code != http.StatusOK {
		t.Fatalf("конфиг не отдан: %d", code)
	}
	if strings.Contains(body, stored) {
		t.Error("хеш пароля ушёл в панель")
	}
	if !strings.Contains(body, `"password_set": true`) {
		t.Errorf("панель не узнает, что пароль задан: %s", body)
	}

	// И, главное, любая другая правка не должна его терять.
	if code, body := send(t, "PUT", e.url+"/api/language"+auth, map[string]string{"language": "ru"}); code != http.StatusOK {
		t.Fatalf("смена языка: %d %s", code, body)
	}
	if got := e.onDisk(t).AdminPassword; got != stored {
		t.Errorf("правка конфига потеряла пароль: было %q, стало %q", stored, got)
	}

	if code, body := send(t, "PUT", e.url+"/api/password"+auth, map[string]string{"password": ""}); code != http.StatusOK {
		t.Fatalf("снятие пароля: %d %s", code, body)
	}
	if got := e.onDisk(t).AdminPassword; got != "" {
		t.Errorf("пароль не снят: %q", got)
	}
}

// TestLoginThrottled — подбор пароля должен упираться в паузу.
func TestLoginThrottled(t *testing.T) {
	e := newEditable(t)
	e.srv.Token = ""
	hashed, err := HashPassword("пароль от панели")
	if err != nil {
		t.Fatal(err)
	}
	e.read().AdminPassword = hashed

	c := clientWithJar(t)
	var blocked bool
	for i := 0; i < 8; i++ {
		code, _ := postJSON(t, c, e.url+"/api/login", map[string]string{"password": "подбор"})
		if code == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("восемь неверных попыток подряд прошли без паузы")
	}
	// Пауза действует и на верный пароль: иначе её можно было бы обойти,
	// перемежая попытки.
	if code, _ := postJSON(t, c, e.url+"/api/login", map[string]string{"password": "пароль от панели"}); code != http.StatusTooManyRequests {
		t.Errorf("во время паузы вход отдал %d", code)
	}
}
