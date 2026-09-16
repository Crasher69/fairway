package forward

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"fairway/internal/i18n"
)

// maxAttempts — через сколько разных прокси пробуем провести один запрос,
// прежде чем сдаться. Три: первый, замена и ещё одна на случай, что и
// замена мёртвая. Больше — и клиент ждёт дольше, чем сам готов.
const maxAttempts = 3

// tunnelHeadLimit — сколько байт от клиента туннель держит в памяти, пока
// цель не ответила: ровно столько можно повторить через другой прокси.
// TLS ClientHello — единицы килобайт, HTTP-запрос без тела — тоже.
const tunnelHeadLimit = 64 << 10

// DefaultIdleTimeout — туннель, в котором пять минут ни байта в обе
// стороны, закрывается. Он занимает слот рабочего набора домена и
// соединение у прокси, а браузер такое соединение всё равно переоткроет.
const DefaultIdleTimeout = 5 * time.Minute

// tunnelHead — то, что клиент успел прислать в туннель, пока цель молчит.
// Пока от цели нет ни байта, эти данные можно повторить через другой
// прокси: TLS ClientHello или HTTP-запрос без ответа ни к чему клиента не
// обязывают, у него ещё нет состояния, привязанного к соединению. Ровно
// то же правило, что у повтора в MITM: получив от цели хоть байт, нельзя
// знать, выполнен ли запрос, и повторять его вслепую опасно.
//
// Запись в текущее соединение идёт под замком вместе с подменой
// соединения: иначе кусок, прочитанный до подмены, мог бы уйти и в старое
// соединение, и в новое при повторе.
type tunnelHead struct {
	mu       sync.Mutex
	dst      net.Conn
	buf      []byte
	overflow bool // клиент прислал больше лимита — повтор невозможен
	sealed   bool // цель ответила, запоминать больше нечего
	sent     bool // клиент прислал хоть байт
	activity *atomic.Int64
}

func (h *tunnelHead) write(p []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent = true
	h.activity.Store(time.Now().UnixNano())
	if !h.sealed && !h.overflow {
		if len(h.buf)+len(p) > tunnelHeadLimit {
			h.overflow, h.buf = true, nil
		} else {
			h.buf = append(h.buf, p...)
		}
	}
	_, err := h.dst.Write(p)
	return err
}

// closeWrite — клиент закрыл свою сторону, цель должна увидеть EOF.
func (h *tunnelHead) closeWrite() {
	h.mu.Lock()
	defer h.mu.Unlock()
	closeWrite(h.dst)
}

// seal — цель ответила: буфер больше не нужен, память отдаём.
func (h *tunnelHead) seal() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sealed, h.buf = true, nil
}

// state — прислал ли клиент что-нибудь и можно ли это повторить.
func (h *tunnelHead) state() (sent, replayable bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sent, !h.overflow
}

// switchTo переключает туннель на новое соединение и повторяет в него всё,
// что клиент прислал. Старое соединение к этому моменту уже закрыто.
func (h *tunnelHead) switchTo(dst net.Conn) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dst = dst
	if len(h.buf) == 0 {
		return nil
	}
	_, err := dst.Write(h.buf)
	return err
}

// watchIdle закрывает туннель, если в нём давно нет движения. Одним
// таймером на обе стороны, а не дедлайнами на каждом соединении: при
// дедлайне на чтение от клиента долгая загрузка оборвалась бы через idle
// минут, хотя байты от цели идут без остановки.
func watchIdle(idle time.Duration, activity *atomic.Int64, kill func()) (stop func()) {
	if idle <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTimer(idle)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				since := time.Since(time.Unix(0, activity.Load()))
				if since >= idle {
					kill()
					return
				}
				t.Reset(idle - since)
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// tunnelError переводит «первого байта не было» на язык замера. Таймаут
// и обрыв до ответа — обе ошибки прокси: соединение он принял, а цель
// через него не отвечает.
func tunnelError(err error, wait time.Duration) error {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return i18n.Errorf("no reply from target within %s", wait)
	case errors.Is(err, io.EOF):
		return i18n.Errorf("connection closed before the target answered")
	}
	return err
}
