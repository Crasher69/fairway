// Command loadgen — нагрузочный генератор для fairway.
//
// Держит заданное число одновременных соединений через прокси и считает
// пропускную способность и перцентили задержки. Нужен, чтобы отвечать на
// вопрос «сколько туннелей выдержит» цифрами, а не ощущениями.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		proxyAddr   = flag.String("proxy", "127.0.0.1:8080", "address of the proxy under test")
		target      = flag.String("target", "http://127.0.0.1:19000/", "target URL")
		concurrency = flag.Int("c", 100, "how many connections to keep open at once")
		duration    = flag.Duration("d", 15*time.Second, "test duration")
		keepAlive   = flag.Bool("keep-alive", false, "reuse connections")
		insecure    = flag.Bool("insecure", false, "skip target certificate verification (for a MITM stand)")
	)
	flag.Parse()

	proxyURL, err := url.Parse("http://" + *proxyAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	collector := &results{start: time.Now()}
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Транспорт на воркер: иначе пул соединений Go сам ограничит
			// параллелизм, и мы измерим его, а не прокси.
			transport := &http.Transport{
				Proxy:               http.ProxyURL(proxyURL),
				DisableKeepAlives:   !*keepAlive,
				MaxIdleConnsPerHost: 1,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

			for ctx.Err() == nil {
				o := request(ctx, client, *target)
				// Последний запрос каждого воркера обрывается дедлайном теста.
				// Это не отказ прокси, и в статистику отказов он попадать
				// не должен — иначе ошибок всегда ровно столько же, сколько
				// соединений, и настоящие потери в этом шуме не видны.
				if o.err != nil && ctx.Err() != nil {
					return
				}
				collector.record(o)
			}
		}()
	}
	wg.Wait()
	collector.print(*concurrency, *keepAlive)
}

type outcome struct {
	latency time.Duration
	bytes   int64
	err     error
}

func request(ctx context.Context, client *http.Client, target string) outcome {
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return outcome{err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return outcome{latency: time.Since(started), err: err}
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil && resp.StatusCode >= 400 {
		// Без этой проверки отказы прокси выглядели бы рекордной скоростью:
		// 503 отдаётся мгновенно и коротким телом.
		err = fmt.Errorf("status %d", resp.StatusCode)
	}
	return outcome{latency: time.Since(started), bytes: n, err: err}
}

type results struct {
	start time.Time

	mu        sync.Mutex
	latencies []time.Duration

	ok     atomic.Int64
	failed atomic.Int64
	bytes  atomic.Int64

	failures map[string]int
}

func (r *results) record(o outcome) {
	if o.err != nil {
		r.failed.Add(1)
		r.mu.Lock()
		if r.failures == nil {
			r.failures = map[string]int{}
		}
		r.failures[o.err.Error()]++
		r.mu.Unlock()
		return
	}
	r.ok.Add(1)
	r.bytes.Add(o.bytes)

	r.mu.Lock()
	r.latencies = append(r.latencies, o.latency)
	r.mu.Unlock()
}

func (r *results) print(concurrency int, keepAlive bool) {
	elapsed := time.Since(r.start)
	ok := r.ok.Load()
	failed := r.failed.Load()

	r.mu.Lock()
	sort.Slice(r.latencies, func(i, j int) bool { return r.latencies[i] < r.latencies[j] })
	latencies := r.latencies
	r.mu.Unlock()

	mode := "new connection per request"
	if keepAlive {
		mode = "keep-alive"
	}
	fmt.Printf("concurrent connections:  %d (%s)\n", concurrency, mode)
	fmt.Printf("duration:                %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("successful requests:     %d\n", ok)
	fmt.Printf("errors:                  %d\n", failed)

	r.mu.Lock()
	causes := make([]string, 0, len(r.failures))
	for cause := range r.failures {
		causes = append(causes, cause)
	}
	sort.Slice(causes, func(i, j int) bool { return r.failures[causes[i]] > r.failures[causes[j]] })
	for i, cause := range causes {
		if i == 5 {
			break // разновидностей ошибок бывает много, важны частые
		}
		fmt.Printf("    %6d × %s\n", r.failures[cause], cause)
	}
	r.mu.Unlock()

	if ok > 0 {
		fmt.Printf("requests per second:     %.0f\n", float64(ok)/elapsed.Seconds())
		fmt.Printf("throughput:              %.1f MB/s\n",
			float64(r.bytes.Load())/elapsed.Seconds()/(1024*1024))
		fmt.Printf("latency p50/p95/p99:     %s / %s / %s\n",
			percentile(latencies, 0.50).Round(time.Millisecond),
			percentile(latencies, 0.95).Round(time.Millisecond),
			percentile(latencies, 0.99).Round(time.Millisecond))
		fmt.Printf("max:                     %s\n", latencies[len(latencies)-1].Round(time.Millisecond))
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}
