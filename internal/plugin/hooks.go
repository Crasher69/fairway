package plugin

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fairway/internal/challenge"
	"fairway/internal/i18n"
)

// Ограничения обработки запросов.
const (
	// MaxHookBody — тело больше этого плагину не отдаётся и идёт потоком
	// как есть.
	MaxHookBody = 8 << 20
	// hookTimeout — сколько запрос может ждать плагин, включая очередь к
	// свободному экземпляру. Не уложился — запрос идёт без его правки.
	hookTimeout = 2 * time.Second
	// hookRestartDelay — пауза перед заменой упавшего экземпляра;
	// hookRetryDelay — перед новой попыткой, если экземпляр не поднялся.
	hookRestartDelay = time.Second
	hookRetryDelay   = 10 * time.Second
)

// hookLogEvery — ошибки обработки запросов пишутся в лог не чаще, иначе
// сломанный плагин на каждом запросе забил бы его целиком. Тесты его
// обнуляют.
var hookLogEvery = 10 * time.Second

// hookWorkers — сколько экземпляров модуля обслуживают запросы одного
// плагина. Каждый вызывается строго по одному, так что это и есть
// параллелизм; память у каждого своя.
var hookWorkers = min(runtime.NumCPU(), 4)

// hookRequest — запрос глазами плагина. URL полный, со схемой и хостом
// (порт — только нестандартный). Тела нет, если плагин не просил тел
// (hooks.body) или оно больше MaxHookBody — тогда body_skipped.
type hookRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Headers     http.Header `json:"headers"`
	Body        []byte      `json:"body,omitempty"`
	BodySkipped bool        `json:"body_skipped,omitempty"`
}

// hookResponse — ответ глазами плагина. Сжатое gzip или deflate тело
// отдаётся уже распакованным, без Content-Encoding.
type hookResponse struct {
	Status      int         `json:"status"`
	Headers     http.Header `json:"headers"`
	Body        []byte      `json:"body,omitempty"`
	BodySkipped bool        `json:"body_skipped,omitempty"`
}

// hookReply — result плагина. На request: request — правка запроса,
// response — ответить клиенту самому, запрос дальше не идёт. На response:
// response — правка ответа. Не заданное не меняется.
type hookReply struct {
	Request  *requestEdit  `json:"request"`
	Response *responseEdit `json:"response"`
}

// requestEdit — правка запроса. Менять можно метод, путь и query URL,
// заголовки (заменяются целиком) и тело, если оно было отдано плагину.
// body отсутствует — тело то же; "" — пустое.
type requestEdit struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Body    *[]byte     `json:"body"`
}

// responseEdit — правка ответа или ответ плагина вместо цели.
type responseEdit struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
	Body    *[]byte     `json:"body"`
}

// hookPool — экземпляры модуля, обслуживающие запросы одного плагина.
type hookPool struct {
	name     string
	hooks    Hooks
	dir      string
	settings []byte
	// spawnInstance создаёт экземпляр (ещё не запущенный).
	spawnInstance func() *instance
	logf          func(format string, args ...any)

	idle  chan *instance
	alive atomic.Int32

	mu      sync.Mutex
	ctx     context.Context
	stopped bool

	errMu      sync.Mutex
	errLogged  time.Time
	errDropped int
}

func newHookPool(name string, hooks Hooks, dir string, settings []byte, spawn func() *instance, logf func(string, ...any)) *hookPool {
	return &hookPool{
		name:          name,
		hooks:         hooks,
		dir:           dir,
		settings:      settings,
		spawnInstance: spawn,
		logf:          logf,
		idle:          make(chan *instance, hookWorkers),
	}
}

// start поднимает экземпляры. Вызывается, когда основной экземпляр
// плагина прошёл init, — до этого запросы идут мимо плагина.
func (p *hookPool) start(ctx context.Context) {
	p.mu.Lock()
	p.ctx = ctx
	p.mu.Unlock()
	for range hookWorkers {
		go p.spawn(0)
	}
}

// spawn запускает один экземпляр после паузы и отдаёт его в работу.
func (p *hookPool) spawn(delay time.Duration) {
	ctx := p.ctx
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
	}
	for {
		w := p.spawnInstance()
		err := w.start(ctx, p.dir)
		if err == nil {
			err = w.send(ctx, initTimeout, guestMessage{Type: messageInit, Settings: p.settings})
		}
		if err == nil {
			p.alive.Add(1)
			p.put(w)
			return
		}
		w.close(context.Background())
		if ctx.Err() != nil {
			return
		}
		p.logf(i18n.T("request handler did not start: %v"), err)
		select {
		case <-time.After(hookRetryDelay):
		case <-ctx.Done():
			return
		}
	}
}

// put возвращает экземпляр в очередь, а после остановки — закрывает.
func (p *hookPool) put(w *instance) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		w.close(context.Background())
		return
	}
	p.idle <- w // ёмкость — hookWorkers, экземпляров не больше
}

// stop закрывает свободные экземпляры; занятые закроются при возврате.
func (p *hookPool) stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	for {
		select {
		case w := <-p.idle:
			w.close(context.Background())
		default:
			return
		}
	}
}

func (p *hookPool) ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.stopped && p.ctx != nil && p.alive.Load() > 0
}

// invoke отдаёт сообщение свободному экземпляру и разбирает правку.
// Ошибка — плагин не ответил или ответил ошибкой; запрос тогда идёт без
// его правки.
func (p *hookPool) invoke(msg guestMessage) (*hookReply, error) {
	if !p.ready() {
		return nil, nil // ещё не поднялся или уже остановлен: пропускаем
	}
	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()
	var w *instance
	select {
	case w = <-p.idle:
	case <-ctx.Done():
		return nil, i18n.Errorf("all request handlers are busy")
	}
	// Контекст плагина, а не только таймаут: при остановке плагина вызов
	// прерывается сразу.
	callCtx, stopCall := context.WithCancel(ctx)
	defer stopCall()
	defer context.AfterFunc(p.ctx, stopCall)()

	// Вызов — в своей горутине: отмена прерывает код модуля, но не вызов
	// хоста изнутри него (плагин может спать в time.Sleep), а запрос ждать
	// дольше таймаута не должен.
	type outcome struct {
		result []byte
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := w.exchange(callCtx, hookTimeout, msg)
		done <- outcome{result, err}
	}()
	var out outcome
	select {
	case out = <-done:
	case <-callCtx.Done():
		// Модуль уже помечен закрытым; выйдет из вызова — закроем рантайм.
		p.retire(w, func() { <-done })
		return nil, i18n.Errorf("no answer in %s", hookTimeout)
	}
	result, err := out.result, out.err
	var guestErr *guestError
	if err != nil && !errors.As(err, &guestErr) {
		// Модуль упал или прерван по таймауту — он больше не годится.
		p.retire(w, nil)
		return nil, err
	}
	p.put(w)
	if err != nil {
		return nil, err
	}
	var reply hookReply
	if len(result) > 0 && string(result) != "null" {
		if err := json.Unmarshal(result, &reply); err != nil {
			return nil, fmt.Errorf("result: %w", err)
		}
	}
	return &reply, nil
}

// retire убирает негодный экземпляр и заказывает замену. wait, если не
// nil, ждёт ещё идущий вызов: рантайм закрывается, когда он вернётся.
func (p *hookPool) retire(w *instance, wait func()) {
	p.alive.Add(-1)
	if p.ctx.Err() == nil {
		go p.spawn(hookRestartDelay)
	}
	if wait == nil {
		w.close(context.Background())
		return
	}
	go func() {
		wait()
		w.close(context.Background())
	}()
}

// noteError пишет ошибку обработки в лог плагина, не чаще hookLogEvery.
func (p *hookPool) noteError(what string, err error) {
	p.errMu.Lock()
	now := time.Now()
	if now.Sub(p.errLogged) < hookLogEvery {
		p.errDropped++
		p.errMu.Unlock()
		return
	}
	dropped := p.errDropped
	p.errLogged, p.errDropped = now, 0
	p.errMu.Unlock()
	if dropped > 0 {
		p.logf(i18n.T("%s: %v (and %d more errors)"), what, err, dropped)
	} else {
		p.logf("%s: %v", what, err)
	}
}

// OnRequest пропускает запрос через плагины, которые его обрабатывают, по
// порядку имён. Ответ не nil — плагин ответил сам, отправлять запрос
// никуда не надо. Ошибки плагинов запрос не останавливают: он идёт без
// правки сломавшегося плагина.
//
// URL запроса должен быть полным (схема и хост).
func (m *Manager) OnRequest(domain string, req *http.Request) *http.Response {
	pools := m.matching(domain, func(h *Hooks) bool { return h.Request })
	respBodies := m.matching(domain, func(h *Hooks) bool { return h.Response && h.Body })
	if len(respBodies) > 0 {
		// Тело ответа отдаётся плагину распакованным, а распаковать можно
		// только gzip и deflate.
		if accept := challenge.AcceptEncoding(req.Header.Values("Accept-Encoding")); accept != "" {
			req.Header.Set("Accept-Encoding", accept)
		}
	}
	if len(pools) == 0 {
		return nil
	}
	// Вход на сам прокси — не дело плагинов: заголовок уходит вместе с
	// остальными hop-by-hop, но видеть его им незачем.
	req.Header.Del("Proxy-Authorization")

	body := requestBody{req: req}
	for _, p := range pools {
		view := viewRequest(req)
		if p.hooks.Body {
			view.Body, view.BodySkipped = body.load()
		}
		reply, err := p.invoke(guestMessage{Type: messageRequest, Request: view})
		if err != nil {
			p.noteError(i18n.T("request hook"), err)
			continue
		}
		if reply == nil {
			continue
		}
		if reply.Response != nil {
			resp, err := reply.Response.build(req)
			if err != nil {
				p.noteError(i18n.T("request hook"), err)
				continue
			}
			return resp
		}
		if reply.Request != nil {
			if err := reply.Request.apply(req, view, &body, p.hooks.Body); err != nil {
				p.noteError(i18n.T("request hook"), err)
			}
		}
	}
	return nil
}

// OnResponse пропускает ответ через плагины, которые его обрабатывают.
// req — запрос в том виде, в каком ушёл к цели.
func (m *Manager) OnResponse(domain string, req *http.Request, resp *http.Response) {
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return // дальше не HTTP
	}
	pools := m.matching(domain, func(h *Hooks) bool { return h.Response })
	if len(pools) == 0 {
		return
	}
	reqView := viewRequest(req)
	body := responseBody{resp: resp, head: req.Method == http.MethodHead}
	for _, p := range pools {
		// Тело — первым: распакованное, оно теряет Content-Encoding, и
		// плагин должен видеть заголовки уже без него.
		var view hookResponse
		if p.hooks.Body {
			view.Body, view.BodySkipped = body.load()
		}
		view.Status, view.Headers = resp.StatusCode, resp.Header.Clone()
		reply, err := p.invoke(guestMessage{Type: messageResponse, Request: reqView, Response: &view})
		if err != nil {
			p.noteError(i18n.T("response hook"), err)
			continue
		}
		if reply != nil && reply.Response != nil {
			if err := reply.Response.apply(resp, &body, p.hooks.Body); err != nil {
				p.noteError(i18n.T("response hook"), err)
			}
		}
	}
	body.finish()
}

// matching — запущенные плагины, которые обрабатывают домен.
func (m *Manager) matching(domain string, want func(*Hooks) bool) []*hookPool {
	all := m.hooks.Load()
	if all == nil {
		return nil
	}
	var out []*hookPool
	for _, p := range *all {
		if want(&p.hooks) && p.hooks.Matches(domain) {
			out = append(out, p)
		}
	}
	return out
}

// viewRequest — запрос для плагина, без тела.
func viewRequest(req *http.Request) *hookRequest {
	headers := req.Header.Clone()
	headers.Del("Proxy-Authorization")
	return &hookRequest{Method: req.Method, URL: displayURL(req.URL), Headers: headers}
}

// displayURL — URL без стандартного порта: плагину проще сравнивать.
func displayURL(u *url.URL) string {
	c := *u
	host, port := c.Hostname(), c.Port()
	if (c.Scheme == "https" && port == "443") || (c.Scheme == "http" && port == "80") {
		c.Host = host
		if strings.Contains(host, ":") {
			c.Host = "[" + host + "]"
		}
	}
	return c.String()
}

// apply вносит правку плагина в запрос. Хост и схему менять нельзя: под
// домен уже выбран маршрут, а в MITM и соединение с целью.
func (e *requestEdit) apply(req *http.Request, view *hookRequest, body *requestBody, bodyAllowed bool) error {
	if e.URL != "" && e.URL != view.URL {
		u, err := url.Parse(e.URL)
		if err != nil {
			return fmt.Errorf("url: %w", err)
		}
		was, _ := url.Parse(view.URL)
		if !strings.EqualFold(u.Scheme, was.Scheme) || !strings.EqualFold(u.Host, was.Host) {
			return i18n.Errorf("a hook may change the path and query, not the host: %s", e.URL)
		}
		req.URL.Path, req.URL.RawPath, req.URL.RawQuery = u.Path, u.RawPath, u.RawQuery
	}
	if e.Method != "" && e.Method != req.Method {
		if !validToken(e.Method) {
			return i18n.Errorf("bad method %q", e.Method)
		}
		req.Method = e.Method
	}
	if e.Headers != nil {
		h := cleanHeaders(e.Headers)
		req.Header = h
	}
	if e.Body != nil && bodyAllowed && body.loaded && !body.skipped {
		body.set(*e.Body)
	}
	return nil
}

// build делает ответ плагина вместо ответа цели.
func (e *responseEdit) build(req *http.Request) (*http.Response, error) {
	status := e.Status
	if status == 0 {
		status = http.StatusOK
	}
	if status < 200 || status > 999 {
		return nil, i18n.Errorf("bad status %d", status)
	}
	var data []byte
	if e.Body != nil {
		data = *e.Body
	}
	header := cleanHeaders(e.Headers)
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Length", strconv.Itoa(len(data)))
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
		Request:       req,
	}, nil
}

// apply вносит правку плагина в ответ.
func (e *responseEdit) apply(resp *http.Response, body *responseBody, bodyAllowed bool) error {
	if e.Status != 0 && e.Status != resp.StatusCode {
		if e.Status < 200 || e.Status > 999 {
			return i18n.Errorf("bad status %d", e.Status)
		}
		resp.StatusCode = e.Status
		resp.Status = fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status))
	}
	if e.Headers != nil {
		length := resp.Header.Values("Content-Length")
		encoding := resp.Header.Values("Content-Encoding")
		resp.Header = cleanHeaders(e.Headers)
		// Длина и сжатие описывают тело, а не пожелания плагина: пока
		// тело идёт как пришло, они остаются прежними.
		if length != nil {
			resp.Header["Content-Length"] = length
		}
		if !body.buffered {
			resp.Header.Del("Content-Encoding")
			if encoding != nil {
				resp.Header["Content-Encoding"] = encoding
			}
		}
	}
	if e.Body != nil && bodyAllowed && body.loaded && !body.skipped {
		body.set(*e.Body)
	}
	return nil
}

// cleanHeaders — заголовки от плагина без тех, что описывают само
// сообщение: их хост выставляет сам.
func cleanHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		out[http.CanonicalHeaderKey(k)] = append([]string(nil), vv...)
	}
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Trailer", "Proxy-Authorization"} {
		out.Del(name)
	}
	return out
}

func validToken(s string) bool {
	for _, r := range s {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(`()<>@,;:\"/[]?={}`, r) {
			return false
		}
	}
	return s != ""
}

// requestBody читает тело запроса для плагинов один раз, лениво.
type requestBody struct {
	req     *http.Request
	loaded  bool
	skipped bool
	data    []byte
}

func (b *requestBody) load() ([]byte, bool) {
	if !b.loaded {
		b.loaded = true
		b.data, b.skipped = b.read()
	}
	if b.skipped {
		return nil, true
	}
	return b.data, false
}

func (b *requestBody) read() ([]byte, bool) {
	req := b.req
	if req.Body == nil || req.Body == http.NoBody {
		return nil, false
	}
	if req.ContentLength > MaxHookBody {
		return nil, true
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, MaxHookBody+1))
	if err != nil || int64(len(data)) > MaxHookBody {
		// Прочитанное уходит вперёд остатка: тело доходит до цели целым.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), req.Body))
		return nil, true
	}
	req.Body.Close()
	b.set(data)
	return data, false
}

func (b *requestBody) set(data []byte) {
	b.data = data
	req := b.req
	req.TransferEncoding = nil
	req.ContentLength = int64(len(data))
	if len(data) == 0 {
		req.Body = http.NoBody
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
}

// responseBody читает тело ответа для плагинов один раз, лениво, и
// распаковывает gzip и deflate.
type responseBody struct {
	resp    *http.Response
	head    bool
	loaded  bool
	skipped bool
	// buffered — тело прочитано в data (и распаковано): на выходе оно
	// подставляется обратно с новой длиной и без сжатия.
	buffered bool
	data     []byte
}

func (b *responseBody) load() ([]byte, bool) {
	if !b.loaded {
		b.loaded = true
		b.data, b.skipped = b.read()
	}
	if b.skipped {
		return nil, true
	}
	return b.data, false
}

func (b *responseBody) read() ([]byte, bool) {
	resp := b.resp
	if b.head || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		// Тела нет, а Content-Length — от GET: трогать нельзя.
		return nil, true
	}
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return nil, true // поток событий не кончается — копить нельзя
	}
	if resp.ContentLength > MaxHookBody {
		return nil, true
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxHookBody+1))
	if err != nil || int64(len(raw)) > MaxHookBody {
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), resp.Body))
		return nil, true
	}
	data, ok := decodeBody(resp.Header.Get("Content-Encoding"), raw)
	if !ok {
		// Не распаковать — отдаём клиенту как пришло, плагину не показываем.
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.TransferEncoding = nil
		resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		return nil, true
	}
	resp.Header.Del("Content-Encoding")
	b.buffered = true
	b.data = data
	return data, false
}

func (b *responseBody) set(data []byte) { b.data = data }

// finish подставляет прочитанное тело обратно в ответ.
func (b *responseBody) finish() {
	if !b.buffered {
		return
	}
	resp := b.resp
	resp.Body = io.NopCloser(bytes.NewReader(b.data))
	resp.ContentLength = int64(len(b.data))
	resp.TransferEncoding = nil
	resp.Uncompressed = false
	resp.Header.Set("Content-Length", strconv.Itoa(len(b.data)))
}

// decodeBody распаковывает тело целиком, не больше MaxHookBody.
func decodeBody(encoding string, raw []byte) ([]byte, bool) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return raw, true
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, false
		}
		r = zr
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(raw))
		}
	default:
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxHookBody+1))
	if err != nil || int64(len(data)) > MaxHookBody {
		return nil, false
	}
	return data, true
}
