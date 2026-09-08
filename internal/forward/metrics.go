package forward

import (
	"net"
	"sync"
	"time"
)

// Sample — замер одного запроса. Это то сырьё, из которого на этапе 3
// вырастет EWMA-рейтинг пары (домен, прокси).
type Sample struct {
	Domain   string        // домен цели, без порта
	Upstream string        // имя апстрима, через который шли
	Connect  time.Duration // установка соединения с целью через апстрим
	TTFB     time.Duration // от установленного соединения до первого байта ответа
	Duration time.Duration // полное время обработки запроса
	Bytes    int64         // байт получено от апстрима
	Status   int           // HTTP-статус; 0 для непрозрачного CONNECT-туннеля
	// Reused означает, что запрос ушёл по уже открытому соединению: время
	// установки в нём не измерялось и в рейтинг попадать не должно.
	Reused bool
	// Challenge — имя антибот-заслона («cloudflare», «datadome», …), если
	// вместо содержимого пришла страница проверки. Видно только в MITM:
	// по туннелю тело не прочитать. Для рейтинга это бан, как 403.
	Challenge string
	Err       error // ошибка соединения или обмена
}

// Throughput — средняя скорость отдачи, байт/сек. Считается от момента
// первого байта, чтобы latency апстрима не занижала скорость.
func (s Sample) Throughput() float64 {
	body := s.Duration - s.Connect - s.TTFB
	if body <= 0 || s.Bytes == 0 {
		return 0
	}
	return float64(s.Bytes) / body.Seconds()
}

// countingConn считает объём принятого от апстрима трафика и запоминает
// момент первого байта — из этих двух чисел получаются TTFB и throughput.
type countingConn struct {
	net.Conn

	mu    sync.Mutex
	first time.Time
	n     int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if c.first.IsZero() {
			c.first = time.Now()
		}
		c.n += int64(n)
		c.mu.Unlock()
	}
	return n, err
}

// stats возвращает момент первого байта и число прочитанных байт.
func (c *countingConn) stats() (time.Time, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.first, c.n
}
