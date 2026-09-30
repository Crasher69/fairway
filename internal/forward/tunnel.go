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

// transferGap — пауза между порциями от цели, после которой туннель
// считается простаивающим. Внутри одной отдачи порции идут с интервалом
// в круговую задержку (сотни миллисекунд даже у медленного прокси), а
// между запросами браузера по keep-alive — секунды и минуты.
const transferGap = time.Second

// transferMeter считает, сколько времени через туннель реально шли байты
// от цели. Скорость по полному времени жизни туннеля бессмысленна: браузер
// держит его минутами, и 200 КБ за пять минут давали бы 700 байт в секунду
// у любого прокси. Порция после долгой паузы открывает новую отдачу: её
// байты не учитываются, как и время ожидания перед ней, — это время до
// первого байта очередного ответа, а не скорость.
type transferMeter struct {
	last   time.Time
	active time.Duration
	bytes  int64
}

func (m *transferMeter) add(n int) {
	now := time.Now()
	if gap := now.Sub(m.last); gap <= transferGap {
		m.active += gap
		m.bytes += int64(n)
	}
	m.last = now
}

// tunnelHead — то, что клиент успел прислать в туннель, пока цель молчит.
// Пока от цели нет ни байта, эти данные можно повторить через другой
// прокси: TLS ClientHello или HTTP-запрос без ответа ни к чему клиента не
// обязывают, у него ещё нет состояния, привязанного к соединению. Ровно
// то же правило, что у повтора в MITM: получив от цели хоть байт, нельзя
// знать, выполнен ли запрос, и повторять его вслепую опасно.
//
// Под замком — только буфер и выбор соединения, сама запись идёт вне
// его. Замок на время записи держал бы и seal: апстрим, переставший
// читать, вешал бы туннель ещё до запуска таймера простоя. Порядок
// байт при этом сохраняется: кусок, взятый до подмены, лежит в буфере и
// повторится в новое соединение (в старое, уже закрытое, он не дойдёт),
// а куски после подмены уходят в новое только после повтора — switchTo
// пишет его под замком.
type tunnelHead struct {
	mu        sync.Mutex
	dst       net.Conn
	buf       []byte
	overflow  bool // клиент прислал больше лимита — повтор невозможен
	sealed    bool // цель ответила, запоминать больше нечего
	sent      bool // клиент прислал хоть байт
	writeDone bool // клиент закрыл свою сторону
	activity  *atomic.Int64
}

func (h *tunnelHead) write(p []byte) error {
	h.mu.Lock()
	h.sent = true
	h.activity.Store(time.Now().UnixNano())
	if !h.sealed && !h.overflow {
		if len(h.buf)+len(p) > tunnelHeadLimit {
			h.overflow, h.buf = true, nil
		} else {
			h.buf = append(h.buf, p...)
		}
	}
	dst := h.dst
	h.mu.Unlock()
	_, err := dst.Write(p)
	return err
}

// closeWrite — клиент закрыл свою сторону, цель должна увидеть EOF.
// Запоминается: при повторе через другой прокси новое соединение тоже
// должно его увидеть, иначе цель ждала бы продолжения до таймаута.
func (h *tunnelHead) closeWrite() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writeDone = true
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
	if len(h.buf) > 0 {
		if _, err := dst.Write(h.buf); err != nil {
			return err
		}
	}
	if h.writeDone {
		closeWrite(dst)
	}
	return nil
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
		return &replyTimeout{wait: wait}
	case errors.Is(err, io.EOF):
		return i18n.Errorf("connection closed before the target answered")
	}
	return err
}
