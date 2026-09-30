// Package config — модель конфигурации: прокси, листы, правила доменов.
// Формат — JSON на диске, перечитывается на лету (см. watch.go).
package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"fairway/internal/forward"
	"fairway/internal/i18n"
)

// Config — всё дерево настроек.
type Config struct {
	// Language — язык логов, ошибок и панели: en (по умолчанию) или ru.
	// Хранится в конфиге, а не во флаге, чтобы переключаться из панели
	// и переживать перезапуск.
	Language string `json:"language,omitempty"`
	// AdminPassword — пароль входа в панель, когда ссылки с токеном под
	// рукой нет. Панель записывает сюда хеш PBKDF2; вписанный руками
	// открытый текст тоже работает (см. internal/admin/auth.go).
	AdminPassword string `json:"admin_password,omitempty"`
	// ProxyAuth — вход на сам прокси. По умолчанию выключен: прокси открыт
	// всем, кто достучался до порта.
	ProxyAuth ProxyAuth `json:"proxy_auth"`
	Defaults  Defaults  `json:"defaults"`
	Proxies   []Proxy   `json:"proxies"`
	Lists     []List    `json:"lists"`
	Domains   []Domain  `json:"domains"`
	// Plugins — какие плагины включены, какие права им выданы и их
	// настройки. Сами плагины лежат в каталоге плагинов (см. internal/plugin).
	Plugins []Plugin `json:"plugins,omitempty"`

	// migrated — Validate дописал прокси id или перевёл ссылки листов
	// с имён на id. Load по нему сохраняет файл обратно, чтобы id не
	// выдумывались заново при каждом чтении.
	migrated bool
}

// ProxyAuth — проверка клиентов прокси по заголовку Proxy-Authorization
// (Basic). Нужна, когда порт прокси виден из сети шире, чем круг своих:
// иначе через ваши апстримы ходит любой, кто его нашёл.
//
// Пароли лежат открытым текстом, как и пароли апстримов в этом же файле:
// их сверяют на каждом соединении, и медленный хеш здесь бил бы по
// скорости, а быстрый ничего бы не защитил.
type ProxyAuth struct {
	Enabled bool        `json:"enabled"`
	Users   []ProxyUser `json:"users,omitempty"`
}

// ProxyUser — одна пара логин/пароль для клиентов прокси.
type ProxyUser struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Allows сообщает, пускать ли клиента с такими логином и паролем. При
// выключенной проверке пускает всех. Сверяются все пары до конца и за
// постоянное время: иначе по времени ответа подбирается и логин, и пароль.
func (a ProxyAuth) Allows(login, password string) bool {
	if !a.Enabled {
		return true
	}
	matched := 0
	for _, u := range a.Users {
		loginOK := subtle.ConstantTimeCompare([]byte(u.Login), []byte(login))
		passwordOK := subtle.ConstantTimeCompare([]byte(u.Password), []byte(password))
		matched |= loginOK & passwordOK
	}
	return matched == 1
}

func (a ProxyAuth) validate() error {
	if a.Enabled && len(a.Users) == 0 {
		return i18n.Errorf("proxy_auth: enabled, but there are no users — nobody could use the proxy")
	}
	logins := make(map[string]bool, len(a.Users))
	for i, u := range a.Users {
		switch {
		case u.Login == "":
			return i18n.Errorf("proxy_auth.users[%d]: empty login", i)
		case strings.Contains(u.Login, ":"):
			// Basic склеивает логин и пароль через двоеточие — логин с ним
			// не разобрать обратно.
			return i18n.Errorf("proxy_auth.users[%d] (%s): a login cannot contain \":\"", i, u.Login)
		case u.Password == "":
			return i18n.Errorf("proxy_auth.users[%d] (%s): empty password", i, u.Login)
		case logins[u.Login]:
			return i18n.Errorf("proxy_auth.users[%d]: login %q is already taken", i, u.Login)
		}
		logins[u.Login] = true
	}
	return nil
}

// Plugin — запись о плагине в конфиге. Плагин, которого здесь нет, считается
// выключенным.
type Plugin struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Granted — права, которые админ выдал плагину. Плагин запускается,
	// только если здесь есть всё, что он просит в манифесте: новая версия
	// с новыми правами не получит их молча.
	Granted []string `json:"granted,omitempty"`
	// Settings — настройки плагина как есть: их схему знает только плагин.
	Settings json.RawMessage `json:"settings,omitempty"`
}

func validatePlugins(plugins []Plugin) error {
	names := make(map[string]bool, len(plugins))
	for i, p := range plugins {
		switch {
		case p.Name == "":
			return i18n.Errorf("plugins[%d]: empty name", i)
		case names[p.Name]:
			return i18n.Errorf("plugins[%d]: plugin %q is listed twice", i, p.Name)
		}
		names[p.Name] = true
		if len(p.Settings) > 0 {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(p.Settings, &object); err != nil {
				return i18n.Errorf("plugins[%d] (%s): settings must be a JSON object", i, p.Name)
			}
		}
	}
	return nil
}

// Defaults — правило для доменов, которые не попали ни под один паттерн.
type Defaults struct {
	// List — лист по умолчанию. Пусто означает «правила нет».
	List string `json:"list"`
	// AllowDirect разрешает ходить напрямую, когда лист не подобран.
	// ВНИМАНИЕ: при этом наружу светится реальный IP машины.
	AllowDirect        bool     `json:"allow_direct"`
	MaxParallelProxies int      `json:"max_parallel_proxies"`
	MaxConnsPerProxy   int      `json:"max_conns_per_proxy"`
	MITM               bool     `json:"mitm"`
	BanDuration        Duration `json:"ban_duration"`
}

// Proxy — один апстрим-прокси.
//
// Поля разложены по отдельности: так их удобно править в панели и так же
// прокси обычно и продают — «ip:port:логин:пароль». Строку целиком тоже можно
// вставить в URL: при загрузке она разбирается на поля и из файла исчезает.
type Proxy struct {
	// ID — постоянный идентификатор (UUID), по нему прокси состоит в листах.
	// Имя можно менять как угодно, привязки от этого не страдают. Прокси без
	// id получает его при загрузке конфига.
	ID   string `json:"id"`
	Name string `json:"name"`
	// Scheme — http, https или socks5. Пусто означает http.
	Scheme   string `json:"scheme,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Login    string `json:"login,omitempty"`
	Password string `json:"password,omitempty"`
	// Country и Comment ни на что не влияют, но без них список из полусотни
	// прокси превращается в кашу из адресов.
	Country string `json:"country,omitempty"`
	Comment string `json:"comment,omitempty"`
	// URL — способ задать всё одной строкой: scheme://user:pass@host:port.
	// После разбора поле очищается, в файле остаётся разложенный вид.
	URL string `json:"url,omitempty"`
}

// Normalize разбирает URL в отдельные поля и подставляет умолчания.
func (p *Proxy) Normalize() error {
	if p.URL != "" {
		up, err := forward.ParseUpstream(p.URL)
		if err != nil {
			return err
		}
		if up.Scheme == "direct" {
			p.Scheme, p.Host, p.Port = "direct", "", 0
		} else {
			host, port, err := net.SplitHostPort(up.Addr)
			if err != nil {
				return i18n.Errorf("address %q: %w", up.Addr, err)
			}
			number, err := strconv.Atoi(port)
			if err != nil {
				return i18n.Errorf("port %q: %w", port, err)
			}
			p.Scheme, p.Host, p.Port = up.Scheme, host, number
			p.Login, p.Password = up.User, up.Pass
		}
		p.URL = ""
	}
	if p.Scheme == "" {
		p.Scheme = "http"
	}
	return nil
}

// ConnectURL собирает строку подключения для forward.ParseUpstream.
func (p Proxy) ConnectURL() string {
	if p.Scheme == "direct" {
		return "direct"
	}
	scheme := p.Scheme
	if scheme == "" {
		scheme = "http"
	}
	address := p.Host
	if p.Port > 0 {
		address = net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	}
	if p.Login == "" && p.Password == "" {
		return scheme + "://" + address
	}
	return scheme + "://" + url.UserPassword(p.Login, p.Password).String() + "@" + address
}

// List — именованный набор прокси.
type List struct {
	Name string `json:"name"`
	// Proxies — id прокси. Имена здесь тоже понимаются (так были устроены
	// конфиги до появления id): при загрузке они заменяются на id.
	Proxies []string `json:"proxies"`
}

// NewID выдаёт случайный UUID версии 4.
func NewID() string {
	var b [16]byte
	rand.Read(b[:]) // с Go 1.24 не возвращает ошибку
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ProxyByID ищет прокси по id.
func (c *Config) ProxyByID(id string) (Proxy, bool) {
	for _, p := range c.Proxies {
		if p.ID == id {
			return p, true
		}
	}
	return Proxy{}, false
}

// Migrated сообщает, что при проверке конфиг был дополнен: прокси получили
// id или ссылки листов переведены с имён на id. Такой конфиг стоит
// сохранить, иначе id будут другими при следующем чтении файла.
func (c *Config) Migrated() bool { return c.migrated }

// Domain — правило для домена: какой лист использовать и как ротировать.
type Domain struct {
	// Pattern — "example.com", "*.example.com" или "*" (все домены).
	Pattern string `json:"pattern"`
	List    string `json:"list"`
	// MaxParallelProxies — сколько РАЗНЫХ прокси листа могут работать
	// на этот домен одновременно. 0 — взять из defaults, -1 — без ограничения.
	MaxParallelProxies int `json:"max_parallel_proxies,omitempty"`
	// MaxConnsPerProxy — лимит одновременных соединений на один прокси.
	// Не даёт задушить лидера рейтинга. 0 — взять из defaults, -1 — без ограничения.
	MaxConnsPerProxy int `json:"max_conns_per_proxy,omitempty"`
	// MITM — расшифровывать TLS или пробрасывать туннель как есть.
	// Не задано (null или поля нет) — наследуется из defaults.
	MITM *bool `json:"mitm,omitempty"`
	// BanDuration — на сколько исключать прокси из ротации после бана.
	// Ноль не пишем в файл: он значит «наследовать», а явный "0s" читался бы
	// как «баны выключены».
	BanDuration Duration `json:"ban_duration,omitempty"`
}

// Duration — time.Duration, записанный в JSON строкой: "5m", "1h30m".
type Duration time.Duration

func (d Duration) String() string          { return time.Duration(d).String() }
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return i18n.Errorf("duration must be a string like \"5m\": %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return i18n.Errorf("duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Lang — язык из конфига; пустое поле означает язык по умолчанию.
// Конфиг уже прошёл Validate, поэтому ошибка невозможна.
func (c *Config) Lang() i18n.Lang {
	l, _ := i18n.Parse(c.Language)
	return l
}

// Load читает и проверяет конфиг. Если пришлось выдать прокси id или
// перевести листы с имён на id, файл тут же перезаписывается: иначе при
// каждом чтении id были бы новыми. Не вышло записать (файл только для
// чтения) — не беда, конфиг всё равно рабочий.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if cfg.migrated {
		_ = cfg.Save(path)
	}
	return cfg, nil
}

// Parse разбирает и проверяет конфиг из памяти.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // опечатка в имени поля не должна молча игнорироваться
	if err := dec.Decode(&cfg); err != nil {
		return nil, i18n.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate проверяет ссылочную целостность: имена уникальны, листы и прокси
// существуют, URL разбираются. Конфиг с ошибкой не должен применяться.
func (c *Config) Validate() error {
	if _, err := i18n.Parse(c.Language); err != nil {
		return err
	}
	if err := c.ProxyAuth.validate(); err != nil {
		return err
	}
	if err := validatePlugins(c.Plugins); err != nil {
		return err
	}
	proxyNames := make(map[string]string, len(c.Proxies)) // имя -> id
	proxyIDs := make(map[string]bool, len(c.Proxies))
	for i := range c.Proxies {
		p := &c.Proxies[i]
		switch {
		case p.Name == "":
			return i18n.Errorf("proxies[%d]: empty name", i)
		case proxyNames[p.Name] != "":
			return i18n.Errorf("proxies[%d]: name %q is already taken", i, p.Name)
		}
		if p.ID == "" {
			p.ID = NewID()
			c.migrated = true
		}
		if proxyIDs[p.ID] {
			// Так бывает, когда прокси копируют в файле целиком вместе с id.
			return i18n.Errorf("proxies[%d] (%s): id %q is already taken", i, p.Name, p.ID)
		}
		proxyIDs[p.ID] = true
		// Разбираем здесь, а не при загрузке: так одна форма приходит и из
		// файла, и из панели, и проверяется одинаково.
		if err := p.Normalize(); err != nil {
			return fmt.Errorf("proxies[%d] (%s): %w", i, p.Name, err)
		}
		if p.Scheme != "direct" {
			switch {
			case p.Host == "":
				return i18n.Errorf("proxies[%d] (%s): no address", i, p.Name)
			case p.Port <= 0 || p.Port > 65535:
				return i18n.Errorf("proxies[%d] (%s): port %d out of range", i, p.Name, p.Port)
			}
		}
		if _, err := forward.ParseUpstream(p.ConnectURL()); err != nil {
			return fmt.Errorf("proxies[%d] (%s): %w", i, p.Name, err)
		}
		proxyNames[p.Name] = p.ID
	}

	listNames := make(map[string]bool, len(c.Lists))
	for i, l := range c.Lists {
		switch {
		case l.Name == "":
			return i18n.Errorf("lists[%d]: empty name", i)
		case listNames[l.Name]:
			return i18n.Errorf("lists[%d]: name %q is already taken", i, l.Name)
		case len(l.Proxies) == 0:
			return i18n.Errorf("lists[%d] (%s): empty list", i, l.Name)
		}
		for j, ref := range l.Proxies {
			if proxyIDs[ref] {
				continue
			}
			// Старая привязка по имени: переводим на id, не теряя её.
			id, ok := proxyNames[ref]
			if !ok {
				return i18n.Errorf("lists[%d] (%s): no proxy with id or name %q", i, l.Name, ref)
			}
			c.Lists[i].Proxies[j] = id
			c.migrated = true
		}
		listNames[l.Name] = true
	}

	patterns := make(map[string]bool, len(c.Domains))
	for i, d := range c.Domains {
		switch {
		case d.Pattern == "":
			return i18n.Errorf("domains[%d]: empty pattern", i)
		case patterns[d.Pattern]:
			return i18n.Errorf("domains[%d]: pattern %q is already defined", i, d.Pattern)
		case d.List == "":
			return i18n.Errorf("domains[%d] (%s): no list", i, d.Pattern)
		case !listNames[d.List]:
			return i18n.Errorf("domains[%d] (%s): no list named %q", i, d.Pattern, d.List)
		case d.MaxParallelProxies < -1 || d.MaxConnsPerProxy < -1:
			return i18n.Errorf("domains[%d] (%s): a limit below -1 makes no sense (0 — inherit, -1 — unlimited)", i, d.Pattern)
		}
		if err := validatePattern(d.Pattern); err != nil {
			return fmt.Errorf("domains[%d]: %w", i, err)
		}
		patterns[d.Pattern] = true
	}

	if c.Defaults.List != "" && !listNames[c.Defaults.List] {
		return i18n.Errorf("defaults: no list named %q", c.Defaults.List)
	}
	// -1 в defaults означает то же, что и в правиле домена: без ограничения.
	// Ноль там значит ровно это же, но запрещать -1 было бы неожиданно.
	if c.Defaults.MaxParallelProxies < -1 || c.Defaults.MaxConnsPerProxy < -1 {
		return i18n.Errorf("defaults: a limit below -1 makes no sense (0 and -1 — unlimited)")
	}
	return nil
}

// validatePattern не пускает формы, которые matcher не поддерживает.
func validatePattern(p string) error {
	if p == "*" || !strings.Contains(p, "*") {
		return nil
	}
	if strings.HasPrefix(p, "*.") && !strings.Contains(p[2:], "*") {
		return nil
	}
	return i18n.Errorf("pattern %q: only \"example.com\", \"*.example.com\" and \"*\" are supported", p)
}

// Example — конфиг, который создаётся при первом запуске.
func Example() *Config {
	return &Config{
		Language: string(i18n.Default),
		Defaults: Defaults{
			AllowDirect:      true,
			MaxConnsPerProxy: 32,
			BanDuration:      Duration(5 * time.Minute),
		},
		Proxies: []Proxy{},
		Lists:   []List{},
		Domains: []Domain{},
	}
}

// Save записывает конфиг в файл в читаемом виде.
func (c *Config) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
