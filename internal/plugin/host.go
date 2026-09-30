package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fairway/internal/config"
	"fairway/internal/events"
	"fairway/internal/i18n"
)

// Host — то, чем fairway делится с плагинами.
type Host struct {
	// Config отдаёт применённый конфиг.
	Config func() *config.Config
	// Editor меняет конфиг. nil — конфиг собран из флагов, менять нечего.
	Editor *config.Editor
	Bus    *events.Bus
	// Client — для http.fetch. nil — клиент по умолчанию с таймаутом.
	Client *http.Client
	// SelfClient — для http.fetch с via_fairway: через прокси самого
	// fairway (см. SelfClient). nil — такие запросы не поддерживаются.
	SelfClient *http.Client
}

// minTick — действующий минимум интервала; тесты его уменьшают.
var minTick = MinTick

// Ограничения хоста: плагин не должен суметь занять память или время
// fairway своими запросами.
const (
	// MinTick — чаще плагин вызываться по таймеру не может.
	MinTick = 10 * time.Second
	// maxFetchBody — предел тела ответа http.fetch.
	maxFetchBody = 16 << 20
	// fetchTimeout — таймаут http.fetch, если плагин не задал свой.
	fetchTimeout = 30 * time.Second
)

var errPermission = errors.New("permission denied")

// configView — то, что плагин видит в конфиге: без пароля панели, входа
// на прокси и настроек плагинов (в них чужие ключи API).
type configView struct {
	Defaults config.Defaults `json:"defaults"`
	Proxies  []config.Proxy  `json:"proxies"`
	Lists    []config.List   `json:"lists"`
	Domains  []config.Domain `json:"domains"`
}

func viewOf(c *config.Config) configView {
	return configView{Defaults: c.Defaults, Proxies: c.Proxies, Lists: c.Lists, Domains: c.Domains}
}

// configEdit — правка конфига плагином. Разделы заменяются целиком; не
// переданный раздел не трогается.
type configEdit struct {
	Proxies *[]config.Proxy  `json:"proxies"`
	Lists   *[]config.List   `json:"lists"`
	Domains *[]config.Domain `json:"domains"`
}

// sameAs сообщает, что правка ничего не меняет.
func (e configEdit) sameAs(v configView) bool {
	same := func(edit, current any) bool {
		a, errA := json.Marshal(edit)
		b, errB := json.Marshal(current)
		return errA == nil && errB == nil && bytes.Equal(a, b)
	}
	return (e.Proxies == nil || same(*e.Proxies, v.Proxies)) &&
		(e.Lists == nil || same(*e.Lists, v.Lists)) &&
		(e.Domains == nil || same(*e.Domains, v.Domains))
}

type logParams struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type subscribeParams struct {
	Types []events.Type `json:"types"`
}

type scheduleParams struct {
	Interval string `json:"interval"`
}

type fetchRequest struct {
	Method    string              `json:"method"`
	URL       string              `json:"url"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Body      []byte              `json:"body,omitempty"`
	TimeoutMS int                 `json:"timeout_ms,omitempty"`
	// ViaFairway — отправить запрос через прокси самого fairway.
	ViaFairway bool `json:"via_fairway,omitempty"`
}

type fetchResponse struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// dispatch выполняет вызов плагина. Выполняется в горутине плагина, поэтому
// поля экземпляра здесь можно менять без замков.
func (in *instance) dispatch(ctx context.Context, req hostRequest) (any, error) {
	decode := func(into any) error {
		if len(req.Params) == 0 {
			return nil
		}
		if err := json.Unmarshal(req.Params, into); err != nil {
			return fmt.Errorf("%s: params: %w", req.Method, err)
		}
		return nil
	}
	need := func(p Permission) error {
		if !in.granted[p] {
			return fmt.Errorf("%s: %w (%s)", req.Method, errPermission, p)
		}
		return nil
	}

	switch req.Method {
	case "log":
		var p logParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		in.logf("%s", strings.TrimSpace(levelPrefix(p.Level)+p.Message))
		return nil, nil

	case "config.get":
		if err := need(ConfigRead); err != nil {
			return nil, err
		}
		return viewOf(in.host.Config()), nil

	case "config.edit":
		if err := need(ConfigWrite); err != nil {
			return nil, err
		}
		var p configEdit
		if err := decode(&p); err != nil {
			return nil, err
		}
		// Правка без изменений не пишется: иначе плагин, который правит
		// конфиг в ответ на config.applied, крутил бы сам себя бесконечно.
		if current := viewOf(in.host.Config()); p.sameAs(current) {
			return current, nil
		}
		cfg, err := in.host.Editor.Edit(func(c *config.Config) error {
			if p.Proxies != nil {
				c.Proxies = *p.Proxies
			}
			if p.Lists != nil {
				c.Lists = *p.Lists
			}
			if p.Domains != nil {
				c.Domains = *p.Domains
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return viewOf(cfg), nil

	case "events.subscribe":
		if err := need(Events); err != nil {
			return nil, err
		}
		var p subscribeParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		in.subscribe = p.Types
		in.subscribeSet = true
		return nil, nil

	case "schedule.every":
		if err := need(Schedule); err != nil {
			return nil, err
		}
		var p scheduleParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		every, err := time.ParseDuration(p.Interval)
		if err != nil {
			return nil, fmt.Errorf("schedule.every: %w", err)
		}
		if every != 0 && every < minTick {
			return nil, i18n.Errorf("schedule.every: interval %s is shorter than %s", every, minTick)
		}
		in.tick = every
		in.tickSet = true
		return nil, nil

	case "http.fetch":
		if err := need(HTTPFetch); err != nil {
			return nil, err
		}
		var p fetchRequest
		if err := decode(&p); err != nil {
			return nil, err
		}
		return in.fetch(ctx, p)
	}
	return nil, fmt.Errorf("unknown method %q", req.Method)
}

func levelPrefix(level string) string {
	switch level {
	case "warn", "error":
		return strings.ToUpper(level) + ": "
	}
	return ""
}

func (in *instance) fetch(ctx context.Context, p fetchRequest) (*fetchResponse, error) {
	timeout := fetchTimeout
	if p.TimeoutMS > 0 {
		timeout = time.Duration(p.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := p.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL, bytes.NewReader(p.Body))
	if err != nil {
		return nil, fmt.Errorf("http.fetch: %w", err)
	}
	if err := in.checkURL(req); err != nil {
		return nil, err
	}
	for k, vv := range p.Headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	base := in.httpClient()
	if p.ViaFairway {
		if in.host.SelfClient == nil {
			return nil, i18n.Errorf("http.fetch: via_fairway is not available")
		}
		base = in.host.SelfClient
	}
	client := *base
	// Редирект — такой же запрос, и на чужой хост он уводить не должен.
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return in.checkURL(next)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBody+1))
	if err != nil {
		return nil, fmt.Errorf("http.fetch: %w", err)
	}
	if len(body) > maxFetchBody {
		return nil, i18n.Errorf("http.fetch: response is larger than %d bytes", maxFetchBody)
	}
	return &fetchResponse{Status: resp.StatusCode, Headers: resp.Header, Body: body}, nil
}

func (in *instance) checkURL(req *http.Request) error {
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return i18n.Errorf("http.fetch: scheme %q is not allowed", req.URL.Scheme)
	}
	if !in.manifest.AllowsHost(req.URL.Hostname()) {
		return i18n.Errorf("http.fetch: host %q is not in http_hosts of the manifest", req.URL.Hostname())
	}
	return nil
}

func (in *instance) httpClient() *http.Client {
	if in.host.Client != nil {
		return in.host.Client
	}
	return http.DefaultClient
}
