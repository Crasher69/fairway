// Command mitmproxy — адаптивный прокси-балансировщик с опциональным MITM.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"mitm/internal/forward"
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
		proxyAddr   = flag.String("proxy", ":8080", "адрес прокси-сервера")
		adminAddr   = flag.String("admin", "127.0.0.1:8081", "адрес админки (только loopback по умолчанию)")
		dataDir     = flag.String("data", "./data", "каталог для CA, конфига и снапшотов рейтингов")
		dialTimeout = flag.Duration("dial-timeout", 15*time.Second, "таймаут подключения к цели через апстрим")
	)
	flag.Var(&upstreams, "upstream", "апстрим-прокси scheme://user:pass@host:port; можно повторять; direct — без прокси")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)

	if len(upstreams) == 0 {
		upstreams = append(upstreams, "direct")
		logger.Print("апстримы не заданы (-upstream), работаю напрямую")
	}
	pool := make([]*forward.Upstream, 0, len(upstreams))
	for _, raw := range upstreams {
		up, err := forward.ParseUpstream(raw)
		if err != nil {
			logger.Fatal(err)
		}
		pool = append(pool, up)
		logger.Printf("апстрим: %s", up.Name)
	}

	// Заглушка выбора: round-robin. На этапе 3 её заменит рейтинг по (домен, прокси).
	var counter atomic.Uint64
	pick := func(string) *forward.Upstream {
		return pool[int(counter.Add(1)-1)%len(pool)]
	}

	srv := &forward.Server{
		Pick:        pick,
		DialTimeout: *dialTimeout,
		Logger:      logger,
		Observe: func(s forward.Sample) {
			if s.Err != nil {
				logger.Printf("%s через %s: ОШИБКА %v (connect %s)", s.Domain, s.Upstream, s.Err, round(s.Connect))
				return
			}
			logger.Printf("%s через %s: статус %d, connect %s, ttfb %s, %d Б, %.0f Б/с, всего %s",
				s.Domain, s.Upstream, s.Status, round(s.Connect), round(s.TTFB),
				s.Bytes, s.Throughput(), round(s.Duration))
		},
	}

	logger.Printf("mitmproxy %s: прокси на %s, данные в %s (админка на %s появится на этапе 5)",
		version, *proxyAddr, *dataDir, *adminAddr)

	httpSrv := &http.Server{
		Addr:              *proxyAddr,
		Handler:           srv,
		ReadHeaderTimeout: 30 * time.Second,
	}
	logger.Fatal(httpSrv.ListenAndServe())
}

func round(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
