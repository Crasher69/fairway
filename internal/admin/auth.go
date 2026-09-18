package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"fairway/internal/config"
	"fairway/internal/i18n"
)

// Доступ в панель — двумя путями, и оба нужны:
//
//   - токен в ссылке из лога: открыть панель на своей машине сразу после
//     запуска, ничего не придумывая;
//   - пароль из конфига: панель живёт долго, ссылку с токеном человек
//     теряет, а перезапускать сервис ради неё не хочется.
//
// Пароль в конфиге хранится хешем (PBKDF2-HMAC-SHA256): файл лежит рядом с
// прокси-паролями, его копируют и кладут в бэкапы, и пароль от панели не
// должен читаться из него глазами. Открытый текст тоже понимается — иначе
// нельзя было бы задать пароль, правя файл руками, — но панель всегда
// пишет хеш.
const (
	// pbkdf2Iterations — 600k, как рекомендует OWASP для PBKDF2-SHA256.
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32
	pbkdf2SaltLen    = 16
	pbkdf2Prefix     = "pbkdf2-sha256$"

	// sessionTTL — сколько живёт вход по паролю. Сессии хранятся в памяти,
	// поэтому перезапуск сервиса всё равно требует войти заново.
	sessionTTL = 30 * 24 * time.Hour

	sessionCookie = "fairway_session"
	tokenCookie   = "fairway_token"
)

// HashPassword превращает пароль в строку для конфига.
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return pbkdf2Prefix + strconv.Itoa(pbkdf2Iterations) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

// passwordMatches сверяет введённый пароль с тем, что записано в конфиге.
// Сравнение постоянного времени: иначе по времени ответа подбирается хеш
// побайтно.
func passwordMatches(stored, given string) bool {
	if stored == "" || given == "" {
		return false
	}
	if !strings.HasPrefix(stored, pbkdf2Prefix) {
		// Открытый текст: человек вписал пароль в файл руками.
		return subtle.ConstantTimeCompare([]byte(stored), []byte(given)) == 1
	}
	parts := strings.Split(strings.TrimPrefix(stored, pbkdf2Prefix), "$")
	if len(parts) != 3 {
		return false
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, given, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// sessions — выданные входы по паролю. В памяти и без персистентности:
// перезапуск сервиса завершает сессии, и это правильнее, чем хранить их
// рядом с конфигом.
type sessions struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func (s *sessions) issue() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]time.Time)
	}
	now := time.Now()
	// Протухшие чистим здесь же: отдельный сборщик ради десятка записей
	// не нужен, а расти бесконечно карта не должна.
	for key, until := range s.items {
		if now.After(until) {
			delete(s.items, key)
		}
	}
	s.items[id] = now.Add(sessionTTL)
	return id, nil
}

func (s *sessions) valid(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.items[id]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(s.items, id)
		return false
	}
	return true
}

func (s *sessions) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

// dropAll завершает все сессии. Вызывается при смене пароля: тот, кто знал
// старый, не должен остаться внутри.
func (s *sessions) dropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = nil
}

// throttle тормозит подбор пароля. Панель может стоять не только на
// loopback, а пароль человек выберет короткий.
type throttle struct {
	mu       sync.Mutex
	failures int
	until    time.Time
}

// allow сообщает, можно ли сейчас пробовать, и сколько ждать, если нельзя.
func (t *throttle) allow() (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if wait := time.Until(t.until); wait > 0 {
		return false, wait.Round(time.Second) + time.Second
	}
	return true, 0
}

// fail засчитывает неудачную попытку: первые несколько бесплатны (опечатки
// случаются у всех), дальше пауза удваивается до минуты.
func (t *throttle) fail() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures++
	if t.failures <= 3 {
		return
	}
	pause := time.Duration(1<<min(t.failures-4, 6)) * time.Second
	t.until = time.Now().Add(min(pause, time.Minute))
}

func (t *throttle) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures, t.until = 0, time.Time{}
}

// password — пароль из текущего конфига. Читается на каждый запрос:
// конфиг перечитывается на лету, и смена пароля должна действовать сразу.
func (s *Server) password() string {
	if s.Config == nil {
		return ""
	}
	if cfg := s.Config(); cfg != nil {
		return cfg.AdminPassword
	}
	return ""
}

// AcceptToken принимает токен из query и кладёт его в cookie. Возвращает
// false, если токена в адресе не было или он не тот.
//
// Отдельный метод, потому что вызывается дважды: из проверки доступа и
// перед выдачей самой страницы панели. Страница отдаётся без проверки
// (иначе пароль вводить негде), и если не разобрать токен здесь, то
// переход по ссылке из лога закончится пустым экраном: HTML отдан, cookie
// не поставлена, каждый запрос к API получает 401. Ровно это и случилось
// в 0.2.0.
func (s *Server) acceptToken(w http.ResponseWriter, r *http.Request) bool {
	if s.Token == "" || r.URL.Query().Get("token") != s.Token {
		return false
	}
	// Значение кодируется: в cookie допустим только ASCII, а токен
	// пользователь может задать любой, хоть кириллицей.
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    url.QueryEscape(s.Token),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

// authorized пускает по токену (заголовок, query или cookie) либо по
// сессии, выданной за пароль. Токен из query сохраняется в cookie: по
// ссылке из лога панель открывается одним кликом, а дальше работает без
// него в адресной строке.
func (s *Server) authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Token == "" && s.password() == "" {
			next.ServeHTTP(w, r)
			return
		}
		if s.Token != "" {
			if s.acceptToken(w, r) {
				next.ServeHTTP(w, r)
				return
			}
			if header := r.Header.Get("Authorization"); header == "Bearer "+s.Token {
				next.ServeHTTP(w, r)
				return
			}
			if cookie, err := r.Cookie(tokenCookie); err == nil {
				if value, err := url.QueryUnescape(cookie.Value); err == nil && value == s.Token {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		if s.password() != "" {
			if cookie, err := r.Cookie(sessionCookie); err == nil && s.sessions.valid(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, i18n.T("password required"), http.StatusUnauthorized)
			return
		}
		http.Error(w, i18n.T("token required: ?token=… or header Authorization: Bearer …"), http.StatusUnauthorized)
	})
}

// authMode рассказывает панели, что показывать неавторизованному гостю:
// форму пароля или строку про токен. Единственная ручка без проверки
// доступа — она не раскрывает ничего, кроме факта «пароль настроен».
func (s *Server) authMode(w http.ResponseWriter, r *http.Request) {
	mode := "open"
	switch {
	case s.password() != "":
		mode = "password"
	case s.Token != "":
		mode = "token"
	}
	writeJSON(w, map[string]any{"mode": mode})
}

// login обменивает пароль на сессию.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	stored := s.password()
	if stored == "" {
		http.Error(w, i18n.T("password login is not configured"), http.StatusNotFound)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if ok, wait := s.logins.allow(); !ok {
		http.Error(w, i18n.Sprintf("too many attempts, try again in %s", wait), http.StatusTooManyRequests)
		return
	}
	if !passwordMatches(stored, body.Password) {
		s.logins.fail()
		http.Error(w, i18n.T("wrong password"), http.StatusUnauthorized)
		return
	}
	s.logins.reset()

	id, err := s.sessions.issue()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionTTL),
	})
	w.WriteHeader(http.StatusNoContent)
}

// logout завершает сессию и стирает cookie с токеном: иначе «выйти» не
// выходило бы у того, кто пришёл по ссылке с токеном.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.drop(cookie.Value)
	}
	for _, name := range []string{sessionCookie, tokenCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// savePassword ставит или снимает пароль панели. Пустой — снять.
func (s *Server) savePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	hashed := ""
	if body.Password != "" {
		if len([]rune(body.Password)) < 8 {
			http.Error(w, i18n.T("password must be at least 8 characters long"), http.StatusBadRequest)
			return
		}
		var err error
		if hashed, err = HashPassword(body.Password); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		cfg.AdminPassword = hashed
		return nil
	})
	// Старые сессии завершаются вместе со сменой пароля: тот, кто вошёл по
	// прежнему, дальше идти не должен. Свой вход панель восстановит сама.
	s.sessions.dropAll()
}
