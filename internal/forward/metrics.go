package forward

import (
	"io"
	"time"
)

// Sample — замер одного запроса. Это то сырьё, из которого на этапе 3
// вырастет EWMA-рейтинг пары (домен, прокси).
type Sample struct {
	Domain   string        // домен цели, без порта
	Upstream string        // имя апстрима, через который шли
	ProxyID  string        // постоянный id прокси — ключ рейтинга
	Connect  time.Duration // установка соединения с целью через апстрим
	TTFB     time.Duration // от установленного соединения до первого байта ответа
	Duration time.Duration // полное время обработки запроса
	Bytes    int64         // байт получено от апстрима
	// Transfer — сколько времени реально шли байты ответа, TransferBytes —
	// сколько их пришло за это время. Из них и только из них считается
	// скорость. Полное время не годится: в него входят чужие неудачные
	// попытки, отправка тела запроса, а в туннеле ещё и простой keep-alive
	// между запросами, когда браузер держит сокет минутами.
	Transfer      time.Duration
	TransferBytes int64
	Status        int // HTTP-статус; 0 для непрозрачного CONNECT-туннеля
	// Reused означает, что запрос ушёл по уже открытому соединению: время
	// установки в нём не измерялось и в рейтинг попадать не должно.
	Reused bool
	// Challenge — имя антибот-заслона («cloudflare», «datadome», …), если
	// вместо содержимого пришла страница проверки. Видно только в MITM:
	// по туннелю тело не прочитать. Для рейтинга это бан, как 403.
	Challenge string
	Err       error // ошибка соединения или обмена
	// ClientGone — запрос оборвал сам клиент: закрыл вкладку, ушёл со
	// страницы, отменил загрузку. Err при этом заполнен (для журнала), но
	// прокси тут ни при чём, и рейтинг такой замер не учитывает.
	ClientGone bool
}

// clientWriter пишет клиенту и запоминает ошибку записи: по ней отличается
// «клиент ушёл» от «апстрим оборвал ответ» — io.Copy и Response.Write
// отдают обе одной ошибкой.
type clientWriter struct {
	w   io.Writer
	err error
}

func (c *clientWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil && c.err == nil {
		c.err = err
	}
	return n, err
}

// Throughput — скорость отдачи, байт/сек, по времени передачи (Transfer):
// задержка апстрима и простой соединения её не занижают. 0 — не измерена.
func (s Sample) Throughput() float64 {
	if s.Transfer <= 0 || s.TransferBytes == 0 {
		return 0
	}
	return float64(s.TransferBytes) / s.Transfer.Seconds()
}
