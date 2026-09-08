// Command fairway — адаптивный прокси-балансировщик с опциональным MITM.
//
// Иконка приложения (rsrc_windows_*.syso рядом) генерируется из
// internal/brand — см. cmd/mkicon.
//
//go:generate go run ../mkicon -root ../..
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"fairway/internal/admin"
	"fairway/internal/config"
	"fairway/internal/forward"
	"fairway/internal/mitmca"
	"fairway/internal/proxypool"
	"fairway/internal/rating"
	"fairway/internal/stats"
)

var version = "dev"

// upstreamList — повторяемый флаг -upstream.
type upstreamList []string

func (l *upstreamList) String() string { return strings.Join(*l, ",") }
func (l *upstreamList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() {
	var upstreams upstreamList
	var (
		proxyAddr      = flag.String("proxy", ":8080", "адрес прокси-сервера")
		adminAddr      = flag.String("admin", "127.0.0.1:8081", "адрес админки (только loopback по умолчанию)")
		configPath     = flag.String("config", "config.json", "файл конфигурации; создаётся, если его нет")
		dataDir        = flag.String("data", "./data", "каталог для CA и снапшотов рейтингов")
		dialTimeout    = flag.Duration("dial-timeout", 15*time.Second, "таймаут подключения к цели через апстрим")
		replayBody     = flag.Int64("replay-body", forward.DefaultReplayBodyLimit, "до какого размера (байт) буферизовать тело запроса в MITM ради повтора; -1 — не буферизовать")
		pollInterval   = flag.Duration("config-poll", config.DefaultPollInterval, "как часто перечитывать конфиг")
		ratingSave     = flag.Duration("ratings-save", 30*time.Second, "как часто сохранять рейтинги на диск")
		exportCA       = flag.String("export-ca", "", "сохранить корневой сертификат в указанный файл и выйти")
		adminTokenFlag = flag.String("admin-token", "", "токен доступа к админке; пустой — сгенерировать случайный")
		historySize    = flag.Int("history", stats.DefaultCapacity, "сколько последних запросов держать для админки")
		verbose        = flag.Bool("v", false, "писать в лог каждый запрос")
	)
	flag.Var(&upstreams, "upstream", "апстрим scheme://user:pass@host:port в обход конфига; можно повторять")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)

	// CA поднимаем первым: -export-ca должен работать и до того, как заведён
	// хоть один прокси, — сертификат раскатывают по машинам заранее.
	ca, err := mitmca.LoadOrCreate(*dataDir)
	if err != nil {
		logger.Fatalf("корневой сертификат: %v", err)
	}
	if *exportCA != "" {
		if err := ca.Export(*exportCA); err != nil {
			logger.Fatalf("экспорт корневого сертификата: %v", err)
		}
		logger.Printf("корневой сертификат сохранён в %s", *exportCA)
		logger.Print("импортируйте его в «Доверенные корневые центры» на машинах сети")
		return
	}
	logger.Printf("корневой CA: %s (до %s)", ca.Subject(), ca.NotAfter().Format("02.01.2006"))

	cfg, err := loadConfig(logger, *configPath, upstreams)
	if err != nil {
		logger.Fatal(err)
	}
	pool, err := proxypool.New(cfg)
	if err != nil {
		logger.Fatal(err)
	}
	currentConfig.Store(cfg)
	describe(logger, cfg, pool)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ratings := rating.NewRegistry()
	ratings.BanDuration = func(domain string) time.Duration {
		if rule, ok := pool.Rule(domain); ok {
			return rule.BanDuration
		}
		return 0
	}
	ratings.OnBan = func(domain, proxy, reason string, until time.Time) {
		logger.Printf("бан: %s для %s (%s) до %s", proxy, domain, reason, until.Format("15:04:05"))
	}
	pool.Select = ratings.Select

	ratingsPath := filepath.Join(*dataDir, "ratings.json")
	if err := ratings.Load(ratingsPath); err != nil {
		logger.Printf("рейтинги не загружены: %v", err)
	}
	go ratings.Autosave(ctx, ratingsPath, *ratingSave,
		func(err error) { logger.Printf("рейтинги не сохранены: %v", err) })

	issuer := mitmca.NewIssuer(ca)
	recorder := stats.New(*historySize)

	srv := &forward.Server{
		Pick:            router(pool),
		Issuer:          issuer,
		DialTimeout:     *dialTimeout,
		ReplayBodyLimit: *replayBody,
		Logger:          logger,
		Observe: func(s forward.Sample) {
			ratings.Observe(s)
			recorder.Observe(s)
			if *verbose {
				logSample(logger, s)
			}
		},
	}

	readConfig := func() *config.Config { return currentConfig.Load().(*config.Config) }
	applyConfig := func(updated *config.Config) error {
		if err := pool.Apply(updated); err != nil {
			return err
		}
		currentConfig.Store(updated)
		describe(logger, updated, pool)
		return nil
	}

	adminSrv := &admin.Server{
		Pool:      pool,
		Ratings:   ratings,
		Recorder:  recorder,
		Issuer:    issuer,
		CA:        ca,
		Config:    readConfig,
		Token:     adminToken(logger, *adminTokenFlag),
		Version:   version,
		Started:   time.Now(),
		ProxyAddr: displayAddr(*proxyAddr),
	}
	// Правка из панели и слежение за файлом имеют смысл только когда конфиг
	// живёт в файле: при -upstream он собран из флагов и сохранять его некуда.
	if len(upstreams) == 0 {
		watcher := config.NewWatcher(*configPath, *pollInterval)
		adminSrv.Editor = &admin.Editor{
			Path:    *configPath,
			Current: readConfig,
			Apply:   applyConfig,
			// Панель сохраняет и применяет сама — сторожу незачем
			// применять ту же версию второй раз.
			Saved: watcher.MarkApplied,
		}
		go watcher.Run(ctx,
			func(updated *config.Config) {
				if err := applyConfig(updated); err != nil {
					logger.Printf("конфиг не применён: %v", err)
					return
				}
				logger.Print("конфиг перечитан")
			},
			func(err error) { logger.Printf("конфиг не перечитан: %v", err) },
		)
	}
	startAdmin(ctx, logger, *adminAddr, adminSrv)

	logger.Printf("fairway %s: прокси на %s, конфиг %s, данные в %s",
		version, *proxyAddr, *configPath, *dataDir)

	httpSrv := &http.Server{
		Addr:              *proxyAddr,
		Handler:           srv,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		logger.Print("останавливаюсь")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatal(err)
	}
}

// router связывает пул с прокси-сервером: на каждый запрос берётся lease,
// который освобождается по завершении обработки.
func router(pool *proxypool.Pool) func(string) (*forward.Route, error) {
	return func(domain string) (*forward.Route, error) {
		lease, err := pool.Acquire(domain)
		if err != nil {
			return nil, err
		}
		return &forward.Route{
			Upstream: lease.Proxy.Upstream,
			Name:     lease.Proxy.Name,
			MITM:     lease.Rule.MITM,
			Release:  lease.Release,
		}, nil
	}
}

func logSample(logger *log.Logger, s forward.Sample) {
	if s.Err != nil {
		logger.Printf("%s через %s: ОШИБКА %v (connect %s)", s.Domain, s.Upstream, s.Err, round(s.Connect))
		return
	}
	captcha := ""
	if s.Challenge != "" {
		captcha = " КАПЧА " + s.Challenge + ","
	}
	logger.Printf("%s через %s: статус %d,%s connect %s, ttfb %s, %d Б, %.0f Б/с, всего %s",
		s.Domain, s.Upstream, s.Status, captcha, round(s.Connect), round(s.TTFB),
		s.Bytes, s.Throughput(), round(s.Duration))
}

// loadConfig берёт конфиг с диска, а при флагах -upstream собирает временный
// конфиг из них: удобно для быстрой проверки, файл при этом не трогается.
func loadConfig(logger *log.Logger, path string, upstreams []string) (*config.Config, error) {
	if len(upstreams) > 0 {
		logger.Printf("заданы -upstream (%d шт.) — конфиг %s игнорируется", len(upstreams), path)
		return configFromFlags(upstreams)
	}
	cfg, err := config.Load(path)
	if err == nil {
		return cfg, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	example := config.Example()
	if err := example.Save(path); err != nil {
		return nil, fmt.Errorf("не удалось создать %s: %w", path, err)
	}
	logger.Printf("конфига не было — создал %s (пока пустой, работаю напрямую)", path)
	return example, nil
}

func configFromFlags(upstreams []string) (*config.Config, error) {
	cfg := config.Example()
	cfg.Defaults.List = "cli"
	list := config.List{Name: "cli"}
	for i, raw := range upstreams {
		name := fmt.Sprintf("cli-%d", i+1)
		cfg.Proxies = append(cfg.Proxies, config.Proxy{Name: name, URL: raw})
		list.Proxies = append(list.Proxies, name)
	}
	cfg.Lists = append(cfg.Lists, list)
	return cfg, cfg.Validate()
}

// describe печатает, с чем сервер реально работает: это первое, что смотришь,
// когда запрос ушёл не через тот прокси, через который ожидал.
func describe(logger *log.Logger, cfg *config.Config, pool *proxypool.Pool) {
	proxies := pool.Proxies()
	logger.Printf("прокси: %d, листов: %d, правил доменов: %d", len(proxies), len(cfg.Lists), len(cfg.Domains))
	for _, p := range proxies {
		logger.Printf("  прокси %s -> %s", p.Name, p.Upstream.Name)
	}
	for _, d := range cfg.Domains {
		logger.Printf("  домен %s -> лист %s", d.Pattern, d.List)
	}
	switch {
	case cfg.Defaults.List != "":
		logger.Printf("  по умолчанию -> лист %s", cfg.Defaults.List)
	case cfg.Defaults.AllowDirect:
		logger.Print("  по умолчанию -> НАПРЯМУЮ: домены без правила пойдут с реального IP")
	default:
		logger.Print("  по умолчанию -> отказ: домены без правила получат 503")
	}
}

func round(d time.Duration) time.Duration { return d.Round(time.Millisecond) }

// currentConfig хранит конфиг, применённый последним: админка должна
// показывать то, что реально работает, а не то, что было при запуске.
var currentConfig atomic.Value

// adminToken возвращает токен доступа, генерируя случайный, если не задан.
// Пустой токен разрешён только явным -admin-token="" и сопровождается
// предупреждением: панель управления прокси без пароля — плохая идея.
func adminToken(logger *log.Logger, given string) string {
	if given != "" {
		return given
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		logger.Fatalf("не удалось сгенерировать токен админки: %v", err)
	}
	return hex.EncodeToString(buf)
}

// startAdmin поднимает панель управления на отдельном порту.
func startAdmin(ctx context.Context, logger *log.Logger, addr string, srv *admin.Server) {
	if !admin.IsLoopback(addr) {
		logger.Printf("ВНИМАНИЕ: админка слушает %s, а не loopback — она будет доступна из сети", addr)
	}
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("админка не поднялась: %v", err)
		}
	}()
	logger.Printf("админка: http://%s/?token=%s", displayAddr(addr), srv.Token)
}

// displayAddr делает адрес кликабельным: ":8081" сам по себе в браузер не
// вставишь, нужен хост.
func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}
