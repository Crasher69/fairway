// Package admin — веб-интерфейс и REST API поверх того же процесса.
//
// Слушает отдельный адрес, по умолчанию только 127.0.0.1: панель управления
// прокси не должна торчать в интернет. Доступ закрыт токеном.
package admin

import (
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"time"

	"fairway/internal/config"
	"fairway/internal/i18n"
	"fairway/internal/mitmca"
	"fairway/internal/proxypool"
	"fairway/internal/rating"
	"fairway/internal/stats"
)

// Server отдаёт API и статику админки.
type Server struct {
	Pool     *proxypool.Pool
	Ratings  *rating.Registry
	Recorder *stats.Recorder
	Issuer   *mitmca.Issuer
	CA       *mitmca.CA
	// Config отдаёт актуальный конфиг: он меняется на лету, поэтому функция,
	// а не снимок.
	Config func() *config.Config
	// Editor разрешает правку конфига из панели. nil — панель только читает.
	Editor  *Editor
	Token   string
	Version string
	Started time.Time
	// ProxyAddr — адрес, на котором слушает сам прокси. Панель показывает
	// его в подсказке «как начать»: без него человек, впервые открывший
	// панель, не знает, что прописать в настройках браузера.
	ProxyAddr string
}

// Handler собирает маршруты админки.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/domains", s.domains)
	mux.HandleFunc("GET /api/domains/{domain}", s.domain)
	mux.HandleFunc("GET /api/proxies", s.proxies)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("GET /api/config", s.config)
	mux.HandleFunc("POST /api/config/reload", s.reload)
	mux.HandleFunc("POST /api/proxies", s.addProxy)
	mux.HandleFunc("POST /api/proxies/import", s.importProxies)
	mux.HandleFunc("PUT /api/proxies/{name}", s.updateProxy)
	mux.HandleFunc("DELETE /api/proxies/{name}", s.deleteProxy)
	mux.HandleFunc("POST /api/proxies/bulk", s.bulkProxies)
	mux.HandleFunc("PUT /api/lists", s.saveList)
	mux.HandleFunc("PUT /api/lists/{name}", s.updateList)
	mux.HandleFunc("DELETE /api/lists/{name}", s.deleteList)
	mux.HandleFunc("POST /api/domains/{domain}/unban/{proxy}", s.unban)
	mux.HandleFunc("PUT /api/domains", s.saveDomain)
	mux.HandleFunc("DELETE /api/domains/{pattern}", s.deleteDomain)
	mux.HandleFunc("PUT /api/defaults", s.saveDefaults)
	mux.HandleFunc("PUT /api/language", s.saveLanguage)
	mux.HandleFunc("GET /api/ca", s.caInfo)
	mux.HandleFunc("POST /api/ca/install", s.caInstall)
	mux.HandleFunc("POST /api/ca/uninstall", s.caUninstall)
	mux.HandleFunc("GET /ca", s.downloadCA)
	mux.Handle("GET /", staticHandler())

	// Проба живости стоит перед проверкой токена: Docker и systemd взять его
	// неоткуда, а данных эндпоинт не раскрывает.
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", s.healthz)
	root.Handle("/", s.authorized(mux))
	return root
}

// authorized пускает по токену из заголовка, query или cookie.
// Токен из query сохраняется в cookie: по ссылке из лога панель открывается
// одним кликом, а дальше работает без него в адресной строке.
func (s *Server) authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		if token := r.URL.Query().Get("token"); token == s.Token {
			// Значение кодируется: в cookie допустим только ASCII, а токен
			// пользователь может задать любой, хоть кириллицей.
			http.SetCookie(w, &http.Cookie{
				Name:     "fairway_token",
				Value:    url.QueryEscape(token),
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			next.ServeHTTP(w, r)
			return
		}
		if header := r.Header.Get("Authorization"); header == "Bearer "+s.Token {
			next.ServeHTTP(w, r)
			return
		}
		if cookie, err := r.Cookie("fairway_token"); err == nil {
			if value, err := url.QueryUnescape(cookie.Value); err == nil && value == s.Token {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, i18n.T("token required: ?token=… or header Authorization: Bearer …"), http.StatusUnauthorized)
	})
}

type overviewResponse struct {
	Version    string    `json:"version"`
	Started    time.Time `json:"started"`
	UptimeSec  float64   `json:"uptime_sec"`
	Requests   uint64    `json:"requests"`
	Proxies    int       `json:"proxies"`
	Lists      int       `json:"lists"`
	Domains    int       `json:"domains"`
	CASubject  string    `json:"ca_subject"`
	CAExpires  time.Time `json:"ca_expires"`
	ConfigPath string    `json:"config_path"`
	ProxyAddr  string    `json:"proxy_addr"`
	Editable   bool      `json:"editable"`
	// DefaultList и AllowDirect — для подсказки «как начать»: панель должна
	// понимать, дойдёт ли трафик до прокси без единого правила.
	DefaultList string `json:"default_list"`
	AllowDirect bool   `json:"allow_direct"`
	// Language — действующий язык процесса; панель подстраивается под него.
	Language   string   `json:"language"`
	Languages  []string `json:"languages"`
	CertsCache int      `json:"certs_cached"`
	Watchers   int      `json:"watchers"`
	// Рантайм пригождается в проде: по числу горутин видно утечку соединений,
	// по куче — не пора ли поднимать лимиты.
	Goroutines int     `json:"goroutines"`
	HeapMB     float64 `json:"heap_mb"`
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	resp := overviewResponse{
		Version:     s.Version,
		Started:     s.Started,
		UptimeSec:   time.Since(s.Started).Seconds(),
		Requests:    s.Recorder.Total(),
		Proxies:     len(s.Pool.Proxies()),
		Lists:       len(cfg.Lists),
		Domains:     len(cfg.Domains),
		Watchers:    s.Recorder.Subscribers(),
		ProxyAddr:   s.ProxyAddr,
		DefaultList: cfg.Defaults.List,
		AllowDirect: cfg.Defaults.AllowDirect,
		Language:    string(i18n.Current()),
	}
	for _, l := range i18n.Supported() {
		resp.Languages = append(resp.Languages, string(l))
	}
	if s.Editor != nil {
		resp.ConfigPath = s.Editor.Path
		resp.Editable = s.Editor.Path != ""
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	resp.Goroutines = runtime.NumGoroutine()
	resp.HeapMB = float64(mem.HeapAlloc) / (1024 * 1024)
	if s.CA != nil {
		resp.CASubject = s.CA.Subject()
		resp.CAExpires = s.CA.NotAfter()
	}
	if s.Issuer != nil {
		resp.CertsCache = s.Issuer.CachedCount()
	}
	writeJSON(w, resp)
}

type domainRow struct {
	Domain   string  `json:"domain"`
	Pattern  string  `json:"pattern"`
	List     string  `json:"list"`
	MITM     bool    `json:"mitm"`
	Proxies  int     `json:"proxies"`
	Banned   int     `json:"banned"`
	Requests int64   `json:"requests"`
	Errors   int64   `json:"errors"`
	BestCost float64 `json:"best_cost"`
}

// domains перечисляет домены, по которым реально шёл трафик: правило может
// быть wildcard, а знать надо, какие живые домены под него попали.
func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	rows := make([]domainRow, 0, 32)
	for _, domain := range s.Ratings.Domains() {
		row := domainRow{Domain: domain, BestCost: -1}
		if rule, ok := s.Pool.Rule(domain); ok {
			row.Pattern = rule.Pattern
			row.List = rule.List
			row.MITM = rule.MITM
		}
		snap := s.Ratings.Snapshot(domain)
		row.Proxies = len(snap.Proxies)
		for _, st := range snap.Proxies {
			row.Requests += st.Requests
			row.Errors += st.Errors
			if now.Before(st.BannedUntil) {
				row.Banned++
				continue
			}
			if row.BestCost < 0 || st.Cost < row.BestCost {
				row.BestCost = st.Cost
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Requests > rows[j].Requests })
	writeJSON(w, rows)
}

type proxyState struct {
	Name        string    `json:"name"`
	Upstream    string    `json:"upstream"`
	Active      int64     `json:"active"`
	Samples     int       `json:"samples"`
	Requests    int64     `json:"requests"`
	Errors      int64     `json:"errors"`
	ConnectMS   float64   `json:"connect_ms"`
	TTFBMS      float64   `json:"ttfb_ms"`
	Throughput  float64   `json:"throughput"`
	ErrorRate   float64   `json:"error_rate"`
	Cost        float64   `json:"cost"`
	Share       float64   `json:"share"`
	Banned      bool      `json:"banned"`
	BannedUntil time.Time `json:"banned_until,omitempty"`
	BanReason   string    `json:"ban_reason,omitempty"`
	Status      string    `json:"status"`
}

type domainResponse struct {
	Domain  string       `json:"domain"`
	Rule    ruleView     `json:"rule"`
	Proxies []proxyState `json:"proxies"`
}

type ruleView struct {
	Pattern            string `json:"pattern"`
	List               string `json:"list"`
	MITM               bool   `json:"mitm"`
	MaxParallelProxies int    `json:"max_parallel_proxies"`
	MaxConnsPerProxy   int    `json:"max_conns_per_proxy"`
	BanDuration        string `json:"ban_duration"`
	Known              bool   `json:"known"`
}

// domain — то, ради чего админка и нужна: что творится с прокси конкретного
// домена прямо сейчас.
func (s *Server) domain(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	now := time.Now()

	resp := domainResponse{Domain: domain}
	if rule, ok := s.Pool.Rule(domain); ok {
		resp.Rule = ruleView{
			Pattern:            rule.Pattern,
			List:               rule.List,
			MITM:               rule.MITM,
			MaxParallelProxies: rule.MaxParallelProxies,
			MaxConnsPerProxy:   rule.MaxConnsPerProxy,
			BanDuration:        rule.BanDuration.String(),
			Known:              true,
		}
	}

	active := map[string]int64{}
	upstreams := map[string]string{}
	for _, p := range s.Pool.Proxies() {
		active[p.Name] = p.Active()
		upstreams[p.Name] = p.Upstream.Name
	}

	snap := s.Ratings.Snapshot(domain)
	// Доля трафика повторяет арифметику выбора целиком, вместе с разведкой:
	// без неё лидер на локальном стенде показывал бы 99.99%, хотя каждый
	// десятый запрос уходит случайному прокси. Таблица должна показывать то,
	// что произойдёт, а не идеализированную лотерею.
	epsilon := s.Ratings.EffectiveEpsilon()
	sharpness := s.Ratings.EffectiveSharpness()
	var weightSum float64
	var alive int
	weights := make(map[string]float64, len(snap.Proxies))
	for name, st := range snap.Proxies {
		if now.Before(st.BannedUntil) {
			continue
		}
		alive++
		if st.Cost <= 0 {
			continue
		}
		wgt := math.Pow(1/st.Cost, sharpness)
		weights[name] = wgt
		weightSum += wgt
	}

	for name, st := range snap.Proxies {
		row := proxyState{
			Name:        name,
			Upstream:    upstreams[name],
			Active:      active[name],
			Samples:     st.Samples,
			Requests:    st.Requests,
			Errors:      st.Errors,
			ConnectMS:   st.ConnectMS,
			TTFBMS:      st.TTFBMS,
			Throughput:  st.Throughput,
			ErrorRate:   st.ErrorRate,
			Cost:        st.Cost,
			BannedUntil: st.BannedUntil,
			BanReason:   st.BanReason,
		}
		if now.Before(st.BannedUntil) {
			row.Banned = true
			row.Status = "banned"
		} else if alive > 0 {
			// Разведка раздаёт epsilon поровну, остальное — по весу.
			row.Share = epsilon / float64(alive)
			if weightSum > 0 {
				row.Share += (1 - epsilon) * weights[name] / weightSum
			}
		}
		if !row.Banned {
			row.Status = statusOf(st)
		}
		resp.Proxies = append(resp.Proxies, row)
	}
	sort.Slice(resp.Proxies, func(i, j int) bool {
		a, b := resp.Proxies[i], resp.Proxies[j]
		if a.Banned != b.Banned {
			return !a.Banned
		}
		return a.Cost < b.Cost
	})
	writeJSON(w, resp)
}

// unban снимает бан с прокси для домена — руками, из панели. Бан ставится
// автоматически и сам истечёт, но ждать пять минут, когда точно знаешь,
// что 403 был разовым, незачем.
func (s *Server) unban(w http.ResponseWriter, r *http.Request) {
	domain, proxy := r.PathValue("domain"), r.PathValue("proxy")
	if !s.Ratings.Unban(domain, proxy) {
		http.Error(w, i18n.Sprintf("proxy %s is not banned for %s", proxy, domain), http.StatusNotFound)
		return
	}
	s.domain(w, r)
}

// statusOf переводит цифры в слово, которое видно в таблице без вчитывания.
func statusOf(st rating.Snapshot) string {
	switch {
	case st.Samples == 0:
		return "untested"
	case st.ErrorRate > 0.25:
		return "degraded"
	case st.Samples < 3:
		return "probing"
	default:
		return "ok"
	}
}

func (s *Server) proxies(w http.ResponseWriter, r *http.Request) {
	rows := make([]proxyState, 0, 16)
	for _, p := range s.Pool.Proxies() {
		rows = append(rows, proxyState{
			Name:     p.Name,
			Upstream: p.Upstream.Name,
			Active:   p.Active(),
		})
	}
	writeJSON(w, rows)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	writeJSON(w, s.Recorder.Recent(r.URL.Query().Get("domain"), limit))
}

// stream — поток событий через SSE. Выбран вместо WebSocket намеренно:
// однонаправленный поток, переподключение браузер делает сам, отладить можно
// обычным curl.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, i18n.T("streaming is not supported"), http.StatusInternalServerError)
		return
	}
	domain := r.URL.Query().Get("domain")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	events, unsubscribe := s.Recorder.Subscribe()
	defer unsubscribe()

	// Пинг не даёт прокси и браузеру закрыть простаивающее соединение.
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	encoder := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case event, alive := <-events:
			if !alive {
				return
			}
			if domain != "" && event.Domain != domain {
				continue
			}
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			if err := encoder.Encode(event); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// downloadCA отдаёт корневой сертификат — самый простой способ раскатать его
// на машину, с которой уже открыта панель.
func (s *Server) downloadCA(w http.ResponseWriter, r *http.Request) {
	if s.CA == nil {
		http.Error(w, i18n.T("root certificate is unavailable"), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="fairway-ca.crt"`)
	w.Write(s.CA.CertPEM())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// IsLoopback сообщает, слушает ли админка только локальный интерфейс.
// Используется, чтобы предупредить при запуске.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // пустой хост означает все интерфейсы
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// healthz — проба живости для Docker и systemd. Намеренно без токена:
// пробе неоткуда его взять, а никаких данных эндпоинт не раскрывает.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}
