package rating

import (
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"fairway/internal/forward"
	"fairway/internal/proxypool"
)

// DefaultEpsilon — доля запросов, уходящих на разведку вместо лучшего прокси.
//
// Без разведки система слепнет: победитель забирает весь трафик, а о том,
// что аутсайдер починился (или что лидер деградировал под нагрузкой), узнать
// становится неоткуда.
const DefaultEpsilon = 0.1

// DefaultSharpness — степень, в которую возводится обратная цена при выборе.
// Двойка даёт лидеру уверенное преимущество, но не выключает остальных:
// прокси вдвое дешевле получает вчетверо больше трафика.
const DefaultSharpness = 2

// DefaultEvictAfter — сколько пара (домен, прокси) живёт без запросов.
// Запись заводится на каждую пару, и при правиле «*» с тысячами доменов
// таблица росла бы бесконечно. За сутки простоя замеры всё равно протухают:
// прокси за это время мог и умереть, и ожить, — так что пусть начинает
// заново, как новый.
const DefaultEvictAfter = 24 * time.Hour

// Registry — рейтинги всех пар (домен, прокси).
type Registry struct {
	// Epsilon — доля разведочных запросов. 0 означает DefaultEpsilon.
	Epsilon float64
	// Sharpness — насколько резко преимущество в цене превращается в долю
	// трафика: вес прокси = (1/цена)^Sharpness. При 1 прокси вдвое дешевле
	// получит лишь вдвое больше запросов, и заметная доля трафика будет уходить
	// аутсайдерам. 0 означает DefaultSharpness.
	Sharpness float64
	// BanDuration отдаёт срок бана для домена (обычно из правила конфига).
	// Если nil или возвращает 0, баны не выставляются.
	BanDuration func(domain string) time.Duration
	// MaxBanDuration отдаёт потолок, до которого растёт срок бана подряд.
	// nil или меньше BanDuration — срок не растёт.
	MaxBanDuration func(domain string) time.Duration
	// OnBan вызывается, когда прокси выключается для домена; proxy — его
	// id. Может быть nil.
	OnBan func(domain, proxy, reason string, until time.Time)
	// EvictAfter — через сколько простоя пара забывается. 0 означает
	// DefaultEvictAfter, отрицательное — не вытеснять вовсе.
	EvictAfter time.Duration
	// Now подменяется в тестах.
	Now func() time.Time
	// Rand подменяется в тестах, чтобы выбор был воспроизводим.
	Rand func() float64

	mu       sync.RWMutex
	byDomain map[string]map[string]*Stats // домен -> id прокси -> статистика
}

// NewRegistry создаёт пустой реестр.
func NewRegistry() *Registry {
	return &Registry{byDomain: make(map[string]map[string]*Stats)}
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Registry) random() float64 {
	if r.Rand != nil {
		return r.Rand()
	}
	return rand.Float64()
}

func (r *Registry) sharpness() float64 {
	if r.Sharpness > 0 {
		return r.Sharpness
	}
	return DefaultSharpness
}

func (r *Registry) epsilon() float64 {
	if r.Epsilon > 0 {
		return r.Epsilon
	}
	return DefaultEpsilon
}

// Stats возвращает статистику пары, создавая её при необходимости.
func (r *Registry) Stats(domain, proxy string) *Stats {
	r.mu.RLock()
	if byProxy, ok := r.byDomain[domain]; ok {
		if s, ok := byProxy[proxy]; ok {
			r.mu.RUnlock()
			return s
		}
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	byProxy, ok := r.byDomain[domain]
	if !ok {
		byProxy = make(map[string]*Stats)
		r.byDomain[domain] = byProxy
	}
	s, ok := byProxy[proxy]
	if !ok {
		s = newStats(r.now())
		byProxy[proxy] = s
	}
	return s
}

// Unban снимает бан с прокси для домена. Возвращает false, если пары нет
// или бана не было — панели есть разница между «снял» и «нечего снимать».
func (r *Registry) Unban(domain, proxy string) bool {
	r.mu.RLock()
	s := r.byDomain[domain][proxy]
	r.mu.RUnlock()
	if s == nil {
		return false
	}
	return s.unban(r.now())
}

// Retain забывает всё, что накоплено по прокси, которых больше нет в
// конфиге; known — id оставшихся прокси. Возвращает число снесённых пар.
//
// Вызывается после применения конфига, а не из обработчика удаления:
// прокси исчезает не только кнопкой в панели, но и правкой файла руками,
// а результат должен быть один. Удалённый прокси иначе остался бы в
// таблице домена с замерами и баном — «я его убрал, а он висит».
//
// Рейтинг держится по id, поэтому переименованный прокси свои замеры
// не теряет.
func (r *Registry) Retain(known []string) int {
	keep := make(map[string]bool, len(known))
	for _, id := range known {
		keep[id] = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for domain, byProxy := range r.byDomain {
		for proxy := range byProxy {
			if !keep[proxy] {
				delete(byProxy, proxy)
				removed++
			}
		}
		if len(byProxy) == 0 {
			delete(r.byDomain, domain)
		}
	}
	return removed
}

// Rekey переводит статистику со старых ключей на новые: ids — старый ключ
// -> id. Нужен один раз, при переходе на id: рейтинги, сохранённые прежними
// версиями, лежат по именам прокси, и без переноса накопленное пропало бы.
// Если по id уже есть статистика, она остаётся, а запись по имени
// выбрасывается: свежие замеры важнее старых. Возвращает число
// перенесённых пар.
func (r *Registry) Rekey(ids map[string]string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	moved := 0
	for _, byProxy := range r.byDomain {
		for old, s := range byProxy {
			id, ok := ids[old]
			if !ok || id == old {
				continue
			}
			delete(byProxy, old)
			if _, taken := byProxy[id]; taken {
				continue
			}
			byProxy[id] = s
			moved++
		}
	}
	return moved
}

// Evict забывает пары, которые не использовались дольше EvictAfter, и
// домены, у которых не осталось ни одной пары. Возвращает число снесённых
// пар. Забаненные не трогаются: бан должен дожить до своего срока.
func (r *Registry) Evict() int {
	ttl := r.EvictAfter
	if ttl == 0 {
		ttl = DefaultEvictAfter
	}
	if ttl < 0 {
		return 0
	}
	now := r.now()
	deadline := now.Add(-ttl)

	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for domain, byProxy := range r.byDomain {
		for proxy, s := range byProxy {
			if banned, _, _ := s.Banned(now); banned {
				continue
			}
			if s.idleSince().Before(deadline) {
				delete(byProxy, proxy)
				removed++
			}
		}
		if len(byProxy) == 0 {
			delete(r.byDomain, domain)
		}
	}
	return removed
}

// Observe скармливает рейтингу замер завершённого запроса.
func (r *Registry) Observe(sample forward.Sample) {
	key := sample.ProxyID
	if key == "" {
		key = sample.Upstream
	}
	if sample.Domain == "" || key == "" {
		return
	}
	// Клиент ушёл сам — о прокси такой замер не говорит ничего: ни
	// скорости (ответ оборван), ни ошибки (оборвали не его).
	if sample.ClientGone {
		return
	}
	now := r.now()
	stats := r.Stats(sample.Domain, key)

	var banFor banTerms
	if r.BanDuration != nil {
		banFor.base = r.BanDuration(sample.Domain)
	}
	if r.MaxBanDuration != nil {
		banFor.max = r.MaxBanDuration(sample.Domain)
	}
	var cause string
	if sample.Err != nil {
		cause = failureCause(sample.Err)
	}

	reason := stats.add(observation{
		connect:    sample.Connect,
		ttfb:       sample.TTFB,
		bytes:      sample.TransferBytes,
		throughput: sample.Throughput(),
		status:     sample.Status,
		challenge:  sample.Challenge,
		failed:     sample.Err != nil,
		cause:      cause,
		reused:     sample.Reused,
		at:         now,
	}, banFor)

	if reason != "" && r.OnBan != nil {
		_, until, _ := stats.Banned(now)
		r.OnBan(sample.Domain, key, reason, until)
	}
}

// Select — стратегия выбора прокси для пула (proxypool.Selector).
//
// Порядок такой:
//  1. забаненные для домена исключаются; если забанены все, берётся тот,
//     чей бан кончится раньше (см. ниже);
//  2. непроверенные (замеров меньше minSamples) и вышедшие из бана, у
//     которых на домене ничего не висит, идут первыми — иначе новый прокси
//     никогда не наберёт статистику и останется невидимым, а ожил ли
//     забаненный, никто не узнает. Вышедший из бана, у которого запрос
//     уже висит, не получает ничего: ему положен один запрос за раз;
//  3. с вероятностью Epsilon — случайный из оставшихся (разведка);
//  4. иначе — взвешенная лотерея с весом (1/цена)^Sharpness. Непроверенные
//     в ней не участвуют: цены у них ещё нет.
//
// Почему в п. 2 важно «ничего не висит». Прокси, который принимает
// соединение и молчит, не даёт ни одного завершённого замера: он остаётся
// «непроверенным» сколько угодно, и без этого условия каждый новый запрос
// уходил бы ему как «дадим шанс новичку». На практике два таких прокси
// забирали 80% трафика домена, не пропустив ни байта. Теперь новичок
// получает один запрос на проверку, а следующий — только когда первый
// завершился (успехом или ошибкой) или его взяла разведка.
//
// Почему при всех забаненных не отказ. Раньше клиент получал 503 до конца
// бана, но баны бывают и не по вине прокси: сайт лежал, и каждая попытка
// списалась на прокси, или сайт отдавал 403 на закрытые адреса. Тогда
// домен оставался мёртвым и после того, как сайт поднялся. Запрос через
// прокси, который скоро выйдет из бана, в худшем случае получит от сайта
// тот же отказ, но настоящий, а в лучшем — пройдёт.
//
// Взвешенный случайный, а не «всегда лучший»: постоянный победитель забрал бы
// весь трафик, упёрся в лимит соединений и деградировал, а его замеры перестали
// бы отражать реальность.
func (r *Registry) Select(domain string, candidates []proxypool.Candidate) *proxypool.Proxy {
	if len(candidates) == 0 {
		return nil
	}
	now := r.now()

	alive := make([]proxypool.Candidate, 0, len(candidates))
	fresh := make([]*proxypool.Proxy, 0, len(candidates))
	var (
		fallback     *proxypool.Proxy
		fallbackFree time.Time
		// busy — вышедший из бана, у которого проба ещё висит. Лучше
		// него, чем забаненный, но только если больше некого.
		busy *proxypool.Proxy
	)
	for _, c := range candidates {
		stats := r.Stats(domain, c.Proxy.ID)
		if banned, until, _ := stats.Banned(now); banned {
			if fallback == nil || until.Before(fallbackFree) {
				fallback, fallbackFree = c.Proxy, until
			}
			continue
		}
		probation := stats.OnProbation(now)
		if probation && c.InFlight > 0 {
			busy = c.Proxy
			continue
		}
		alive = append(alive, c)
		if (probation || stats.Samples() < minSamples) && c.InFlight == 0 {
			fresh = append(fresh, c.Proxy)
		}
	}
	// Живых нет — берём того, кто выйдет из бана раньше всех.
	if len(alive) == 0 {
		if busy != nil {
			return busy
		}
		return fallback
	}
	if len(fresh) > 0 {
		return fresh[r.intn(len(fresh))]
	}
	if r.random() < r.epsilon() {
		return alive[r.intn(len(alive))].Proxy
	}

	weights := make([]float64, len(alive))
	var total float64
	for i, c := range alive {
		stats := r.Stats(domain, c.Proxy.ID)
		if stats.Samples() < minSamples {
			continue // замеров нет — цена не значит ничего, в лотерее не участвует
		}
		cost := stats.Cost()
		if cost <= 0 || math.IsNaN(cost) || math.IsInf(cost, 0) {
			continue // цена не определена — в лотерее не участвует
		}
		weights[i] = math.Pow(1/cost, r.sharpness())
		total += weights[i]
	}
	if total <= 0 {
		return alive[r.intn(len(alive))].Proxy
	}

	point := r.random() * total
	for i, w := range weights {
		point -= w
		if point <= 0 {
			return alive[i].Proxy
		}
	}
	return alive[len(alive)-1].Proxy
}

func (r *Registry) intn(n int) int {
	if n <= 1 {
		return 0
	}
	idx := int(r.random() * float64(n))
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// DomainSnapshot — состояние всех прокси одного домена, для админки.
type DomainSnapshot struct {
	Domain  string              `json:"domain"`
	Proxies map[string]Snapshot `json:"proxies"` // по id прокси
}

// Snapshot отдаёт состояние одного домена.
func (r *Registry) Snapshot(domain string) DomainSnapshot {
	r.mu.RLock()
	byProxy := r.byDomain[domain]
	names := make([]string, 0, len(byProxy))
	stats := make([]*Stats, 0, len(byProxy))
	for name, s := range byProxy {
		names = append(names, name)
		stats = append(stats, s)
	}
	r.mu.RUnlock()

	out := DomainSnapshot{Domain: domain, Proxies: make(map[string]Snapshot, len(names))}
	for i, name := range names {
		out.Proxies[name] = stats[i].Snapshot()
	}
	return out
}

// Domains перечисляет домены, по которым есть статистика.
func (r *Registry) Domains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byDomain))
	for d := range r.byDomain {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// EffectiveEpsilon и EffectiveSharpness отдают параметры, с которыми реально
// работает выбор. Нужны админке: доля трафика в таблице должна совпадать
// с тем, что делает Select, а не с константами по умолчанию.
func (r *Registry) EffectiveEpsilon() float64   { return r.epsilon() }
func (r *Registry) EffectiveSharpness() float64 { return r.sharpness() }
