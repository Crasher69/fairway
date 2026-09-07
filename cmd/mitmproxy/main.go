// Command mitmproxy — адаптивный прокси-балансировщик с опциональным MITM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mitm/internal/config"
	"mitm/internal/forward"
	"mitm/internal/proxypool"
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
		proxyAddr    = flag.String("proxy", ":8080", "адрес прокси-сервера")
		adminAddr    = flag.String("admin", "127.0.0.1:8081", "адрес админки (только loopback по умолчанию)")
		configPath   = flag.String("config", "config.json", "файл конфигурации; создаётся, если его нет")
		dataDir      = flag.String("data", "./data", "каталог для CA и снапшотов рейтингов")
		dialTimeout  = flag.Duration("dial-timeout", 15*time.Second, "таймаут подключения к цели через апстрим")
		pollInterval = flag.Duration("config-poll", config.DefaultPollInterval, "как часто перечитывать конфиг")
	)
	flag.Var(&upstreams, "upstream", "апстрим scheme://user:pass@host:port в обход конфига; можно повторять")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)

	cfg, err := loadConfig(logger, *configPath, upstreams)
	if err != nil {
		logger.Fatal(err)
	}
	pool, err := proxypool.New(cfg)
	if err != nil {
		logger.Fatal(err)
	}
	describe(logger, cfg, pool)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(upstreams) == 0 {
		watcher := config.NewWatcher(*configPath, *pollInterval)
		go watcher.Run(ctx,
			func(updated *config.Config) {
				if err := pool.Apply(updated); err != nil {
					logger.Printf("конфиг не применён: %v", err)
					return
				}
				logger.Print("конфиг перечитан")
				describe(logger, updated, pool)
			},
			func(err error) { logger.Printf("конфиг не перечитан: %v", err) },
		)
	}

	srv := &forward.Server{
		Pick:        router(pool),
		DialTimeout: *dialTimeout,
		Logger:      logger,
		Observe:     observer(logger),
	}

	logger.Printf("mitmproxy %s: прокси на %s, конфиг %s, данные в %s (админка на %s появится на этапе 5)",
		version, *proxyAddr, *configPath, *dataDir, *adminAddr)

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

func observer(logger *log.Logger) func(forward.Sample) {
	return func(s forward.Sample) {
		if s.Err != nil {
			logger.Printf("%s через %s: ОШИБКА %v (connect %s)", s.Domain, s.Upstream, s.Err, round(s.Connect))
			return
		}
		logger.Printf("%s через %s: статус %d, connect %s, ttfb %s, %d Б, %.0f Б/с, всего %s",
			s.Domain, s.Upstream, s.Status, round(s.Connect), round(s.TTFB),
			s.Bytes, s.Throughput(), round(s.Duration))
	}
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
