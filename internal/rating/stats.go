package rating

import (
	"math"
	"sync"
	"time"

	"fairway/internal/i18n"
)

// Настройки рейтинга. Вынесены в константы, чтобы их было где крутить,
// когда появится реальная статистика с боевых прокси.
const (
	// defaultAlpha — вес свежего замера в EWMA.
	defaultAlpha = 0.25

	// minSamples — пока замеров меньше, прокси считается непроверенным
	// и получает приоритет в ротации (холодный старт).
	minSamples = 3

	// MinSamples — то же число наружу: панели нужно отличать непроверенный
	// прокси так же, как это делает Select.
	MinSamples = minSamples

	// throughputMinBytes — ответы мельче игнорируются при замере скорости:
	// тело приходит вместе с первым байтом, знаменатель вырождается и
	// скорость скачет от нуля до мегабайт в секунду.
	throughputMinBytes = 32 * 1024

	// refBytes — эталонный размер ответа, на котором сравниваются прокси.
	// Задержка и скорость сводятся к одному числу: сколько секунд заняла бы
	// отдача такого объёма.
	refBytes = 64 * 1024

	// failsBeforeBan — столько подряд ошибок соединения выводят прокси
	// из ротации: дохлый прокси не должен получать запросы каждый раунд.
	failsBeforeBan = 3

	// blocksBeforeBan — столько подряд ответов «доступ запрещён» (403, 429,
	// 451) выводят прокси из ротации для домена. Не с первого раза: 403
	// часто относится к одному адресу (закрытый API, приватный файл на
	// CDN, защита от хотлинка), а не к IP прокси, и один такой ответ банил
	// бы здоровый прокси. Любой другой ответ серию обнуляет.
	blocksBeforeBan = 3

	// slowThroughput — подстраховка, когда скорость ещё не измерена:
	// 256 КБ/с, чтобы неизвестная скорость не выглядела бесконечной.
	slowThroughput = 256 * 1024
)

// Stats — накопленное качество одной пары (домен, прокси).
type Stats struct {
	mu sync.Mutex

	connect    EWMA // мс до установленного соединения с целью
	ttfb       EWMA // мс до первого байта ответа
	throughput EWMA // байт/с на ответах крупнее throughputMinBytes
	errorRate  EWMA // доля неудач, 0..1

	requests int64
	errors   int64
	bans     int64

	consecutiveFails  int
	consecutiveBlocks int
	// strikes — сколько банов подряд без единого успешного ответа между
	// ними. От него растёт срок следующего бана: 5 → 10 → 20 минут…
	strikes int
	// probation — бан кончился, а успешного ответа с тех пор не было.
	// Прокси получает по одному запросу за раз, и ошибка соединения банит
	// его сразу, без серии из трёх: одна проба стоит одного запроса, а не
	// трёх проваленных у клиентов.
	probation   bool
	bannedUntil time.Time
	banReason   string
	lastUsed    time.Time
}

// newStats заводит пустую пару. Время создания записывается в lastUsed:
// запись появляется ещё при выборе прокси, до первого замера, и без метки
// её сразу же снесло бы вытеснение как «давно не использованную».
func newStats(now time.Time) *Stats {
	return &Stats{
		connect:    NewEWMA(defaultAlpha),
		ttfb:       NewEWMA(defaultAlpha),
		throughput: NewEWMA(defaultAlpha),
		errorRate:  NewEWMA(defaultAlpha),
		lastUsed:   now,
	}
}

// observation — то, что рейтинг берёт из замера запроса.
type observation struct {
	connect    time.Duration
	ttfb       time.Duration
	bytes      int64
	throughput float64
	status     int
	challenge  string // имя антибот-заслона, если вместо ответа пришла капча
	failed     bool
	cause      string // короткая причина неудачи (failureCause) — для строки бана
	reused     bool   // соединение переиспользовано: connect не измерялся
	at         time.Time
}

// banTerms — срок бана для домена: начальный и потолок, до которого он
// растёт при банах подряд. Потолок меньше начального — срок не растёт.
type banTerms struct {
	base, max time.Duration
}

// add обновляет статистику и, если нужно, отправляет прокси в бан.
// Возвращает причину бана, если он только что случился.
func (s *Stats) add(o observation, banFor banTerms) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests++
	s.lastUsed = o.at
	// Пока бан действует, доходят ответы запросов, ушедших ещё до него.
	// В серии они не идут: иначе к концу бана серия уже была бы набрана,
	// и первая же неудача после него банила бы снова.
	banned := o.at.Before(s.bannedUntil)

	if o.failed {
		s.errors++
		s.errorRate.Add(1)
		if banned {
			return ""
		}
		// Проба после бана провалилась — прокси по-прежнему мёртв для
		// сайта, и ждать ещё двух неудач незачем.
		if s.probation {
			return s.banLocked(o.at, banFor, i18n.T("failed the check after a ban: ")+o.cause)
		}
		s.consecutiveFails++
		// Соединение не установилось — по нему нельзя судить о скорости,
		// поэтому connect/ttfb не трогаем, чтобы не портить среднее.
		if s.consecutiveFails >= failsBeforeBan {
			return s.banLocked(o.at, banFor, i18n.Sprintf("%d failures in a row: %s", s.consecutiveFails, o.cause))
		}
		return ""
	}

	s.consecutiveFails = 0
	s.errorRate.Add(0)
	// На keep-alive соединении установки не было — ноль сюда добавлять нельзя,
	// иначе среднее времени подключения уедет в пол.
	if !o.reused {
		s.connect.Add(float64(o.connect.Microseconds()) / 1000)
	}
	s.ttfb.Add(float64(o.ttfb.Microseconds()) / 1000)
	if o.bytes >= throughputMinBytes && o.throughput > 0 {
		s.throughput.Add(o.throughput)
	}

	// Страница проверки — тот же бан, что и 403: сайт узнал прокси и не
	// пускает, только вежливо. Статус при этом может быть 200. Детектор
	// срабатывает только на однозначные признаки, поэтому бан сразу.
	if o.challenge != "" {
		return s.banLocked(o.at, banFor, i18n.T("captcha: ")+o.challenge)
	}
	// Прокси не принял наш логин и пароль — ждать повторов незачем.
	if o.status == 407 {
		return s.banLocked(o.at, banFor, i18n.T("407 — proxy rejected authorization"))
	}
	reason := blockReason(o.status)
	if reason == "" {
		s.consecutiveBlocks = 0
		// Успешный ответ вне бана: прокси жив для сайта, прошлые баны
		// больше ничего не значат, и следующий, если случится, снова будет
		// коротким. Ответ, вернувшийся во время бана, этого не доказывает:
		// запрос ушёл ещё до него.
		if !banned {
			s.strikes = 0
			s.probation = false
		}
		return ""
	}
	if banned {
		return ""
	}
	s.consecutiveBlocks++
	if s.consecutiveBlocks < blocksBeforeBan {
		return ""
	}
	return s.banLocked(o.at, banFor, reason)
}

// blockReason отличает «сайт не пускает этот прокси» от «медленно».
// Это разные вещи: медленный прокси остаётся в ротации с низким весом,
// забаненный выключается целиком, но только для этого домена.
func blockReason(status int) string {
	switch status {
	case 403:
		return i18n.T("403 — access denied")
	case 429:
		return i18n.T("429 — too many requests")
	case 451:
		return i18n.T("451 — blocked by legal demand")
	}
	return ""
}

func (s *Stats) banLocked(now time.Time, terms banTerms, reason string) string {
	if terms.base <= 0 {
		return ""
	}
	// Уже забанен — не продлеваем и не сообщаем повторно. Под нагрузкой в
	// полёте остаются десятки запросов, каждый из них падает и пытался бы
	// забанить заново: лог забивался бы, а срок бана уезжал вперёд от ошибок,
	// которые начались ещё до него.
	if now.Before(s.bannedUntil) {
		return ""
	}
	// Прошлые баны забываются, если с конца последнего прошло больше
	// потолка, а успехов с тех пор не было просто потому, что не было и
	// запросов: провалы многочасовой давности о прокси уже ничего не
	// говорят.
	if s.strikes > 0 && now.Sub(s.bannedUntil) >= max(terms.max, terms.base) {
		s.strikes = 0
	}
	s.bannedUntil = now.Add(banLength(terms, s.strikes))
	s.banReason = reason
	s.bans++
	s.strikes++
	s.probation = true
	// Бан начинается с чистого листа: после него прокси снова нужно три
	// неудачи подряд, как и в первый раз, а не одна.
	s.consecutiveFails = 0
	s.consecutiveBlocks = 0
	return reason
}

// unban снимает бан руками. Серия ошибок тоже обнуляется: иначе первая же
// неудача после снятия вернула бы бан обратно, и кнопка выглядела бы
// сломанной. Возвращает false, если бана и не было.
func (s *Stats) unban(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.bannedUntil) {
		return false
	}
	s.bannedUntil = time.Time{}
	s.banReason = ""
	s.consecutiveFails = 0
	s.consecutiveBlocks = 0
	// Человек снял бан, потому что знает, что прокси в порядке: копить
	// прошлые баны и проверять его заново незачем.
	s.strikes = 0
	s.probation = false
	return true
}

// banLength — срок очередного бана: начальный, удвоенный за каждый бан
// подряд до этого, но не больше потолка.
func banLength(terms banTerms, strikes int) time.Duration {
	d := terms.base
	for i := 0; i < strikes && d < terms.max; i++ {
		d *= 2
	}
	if terms.max > terms.base && d > terms.max {
		d = terms.max
	}
	return d
}

// OnProbation сообщает, что прокси вышел из бана и ещё не доказал, что
// жив: ему положен один запрос за раз.
func (s *Stats) OnProbation(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.probation && !now.Before(s.bannedUntil)
}

// idleSince сообщает, когда пару трогали в последний раз.
func (s *Stats) idleSince() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastUsed
}

// Banned сообщает, выключен ли прокси для домена прямо сейчас.
func (s *Stats) Banned(now time.Time) (bool, time.Time, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.bannedUntil) {
		return true, s.bannedUntil, s.banReason
	}
	return false, time.Time{}, ""
}

// Samples — сколько успешных замеров накоплено.
//
// Считается по TTFB, а не по времени подключения: на keep-alive соединении
// установки нет, и по connect прокси навсегда остался бы «непроверенным».
func (s *Stats) Samples() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ttfb.Count()
}

// Cost — ожидаемое время (в секундах) на отдачу эталонного ответа через этот
// прокси. Именно по нему сравниваются прокси: одно число, в котором учтены
// и задержка, и скорость, и доля ошибок. Чем меньше, тем лучше.
func (s *Stats) Cost() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.costLocked()
}

func (s *Stats) costLocked() float64 {
	latency := (s.connect.Value() + s.ttfb.Value()) / 1000 // мс -> с

	speed := s.throughput.Value()
	if s.throughput.Count() == 0 || speed <= 0 {
		speed = slowThroughput
	}
	cost := latency + refBytes/speed

	// Ошибки дороже медленности: неудачный запрос придётся повторять,
	// поэтому цена растёт нелинейно и при errorRate → 1 уходит в потолок.
	errRate := math.Min(math.Max(s.errorRate.Value(), 0), 0.99)
	cost /= (1 - errRate) * (1 - errRate)

	if cost <= 0 || math.IsNaN(cost) || math.IsInf(cost, 0) {
		return math.MaxFloat64
	}
	return cost
}

// Snapshot — копия состояния без блокировок, для админки и сохранения на диск.
type Snapshot struct {
	ConnectMS   float64   `json:"connect_ms"`
	TTFBMS      float64   `json:"ttfb_ms"`
	Throughput  float64   `json:"throughput"`
	ErrorRate   float64   `json:"error_rate"`
	Samples     int       `json:"samples"`
	Requests    int64     `json:"requests"`
	Errors      int64     `json:"errors"`
	Bans        int64     `json:"bans"`
	Cost        float64   `json:"cost"`
	BannedUntil time.Time `json:"banned_until,omitempty"`
	BanReason   string    `json:"ban_reason,omitempty"`
	// Strikes — сколько банов подряд без успеха между ними.
	Strikes int `json:"strikes,omitempty"`
	// Probation — вышел из бана и ждёт пробного запроса.
	Probation bool      `json:"probation,omitempty"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// Snapshot снимает состояние пары (домен, прокси).
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		ConnectMS:   s.connect.Value(),
		TTFBMS:      s.ttfb.Value(),
		Throughput:  s.throughput.Value(),
		ErrorRate:   s.errorRate.Value(),
		Samples:     s.ttfb.Count(),
		Requests:    s.requests,
		Errors:      s.errors,
		Bans:        s.bans,
		Cost:        s.costLocked(),
		BannedUntil: s.bannedUntil,
		BanReason:   s.banReason,
		Strikes:     s.strikes,
		Probation:   s.probation,
		LastUsed:    s.lastUsed,
	}
}

// restore поднимает состояние из снапшота, снятого прошлым запуском.
func (s *Stats) restore(snap Snapshot, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	seed := func(e *EWMA, v float64, count int) {
		if count <= 0 {
			return
		}
		e.value = v
		e.count = count
	}
	seed(&s.connect, snap.ConnectMS, snap.Samples)
	seed(&s.ttfb, snap.TTFBMS, snap.Samples)
	seed(&s.errorRate, snap.ErrorRate, snap.Samples)
	if snap.Throughput > 0 {
		seed(&s.throughput, snap.Throughput, snap.Samples)
	}
	s.requests = snap.Requests
	s.errors = snap.Errors
	s.bans = snap.Bans
	s.lastUsed = snap.LastUsed
	// В старых снапшотах метки нет — считаем запись свежей, иначе весь
	// файл был бы вытеснен при первом же автосохранении.
	if s.lastUsed.IsZero() {
		s.lastUsed = now
	}
	// Срок бана восстанавливается и истёкший: по нему считается, давно ли
	// кончился последний бан, и забываются ли прошлые. Бана он не даёт —
	// Banned сравнивает с текущим временем. Причина нужна только живому.
	s.bannedUntil = snap.BannedUntil
	if now.Before(snap.BannedUntil) {
		s.banReason = snap.BanReason
	}
	s.strikes = snap.Strikes
	s.probation = snap.Probation
}
