package rating

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fairway/internal/config"
	"fairway/internal/forward"
	"fairway/internal/proxypool"
)

func TestEWMAFirstValueIsTakenAsIs(t *testing.T) {
	e := NewEWMA(0.5)
	if e.Count() != 0 || e.Value() != 0 {
		t.Fatalf("новое среднее должно быть пустым: %+v", e)
	}
	e.Add(100)
	if e.Value() != 100 {
		t.Errorf("первое значение = %v, ожидалось 100 без разгона от нуля", e.Value())
	}
	e.Add(200)
	if got := e.Value(); math.Abs(got-150) > 1e-9 {
		t.Errorf("после 100 и 200 при alpha=0.5 ожидалось 150, получено %v", got)
	}
	if e.Count() != 2 {
		t.Errorf("Count = %d, ожидалось 2", e.Count())
	}
}

func TestEWMAConvergesAndForgets(t *testing.T) {
	e := NewEWMA(0.3)
	for i := 0; i < 50; i++ {
		e.Add(1000)
	}
	if math.Abs(e.Value()-1000) > 1 {
		t.Fatalf("среднее не сошлось к 1000: %v", e.Value())
	}
	// Условия изменились — среднее обязано уехать за разумное число замеров.
	for i := 0; i < 20; i++ {
		e.Add(100)
	}
	if e.Value() > 200 {
		t.Errorf("старое значение не забылось: %v", e.Value())
	}
}

// fixedRand возвращает заданную последовательность «случайных» чисел,
// чтобы выбор прокси в тестах был воспроизводим.
func fixedRand(values ...float64) func() float64 {
	i := 0
	return func() float64 {
		v := values[i%len(values)]
		i++
		return v
	}
}

func sample(domain, proxy string, connect, ttfb time.Duration, bytes int64, status int, err error) forward.Sample {
	return forward.Sample{
		Domain:   domain,
		Upstream: proxy,
		Connect:  connect,
		TTFB:     ttfb,
		Bytes:    bytes,
		Duration: connect + ttfb + time.Second,
		Status:   status,
		Err:      err,
	}
}

func TestObserveSplitsFastAndSlow(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 10; i++ {
		r.Observe(sample("example.com", "fast", 20*time.Millisecond, 30*time.Millisecond, 100_000, 200, nil))
		r.Observe(sample("example.com", "slow", 400*time.Millisecond, 600*time.Millisecond, 100_000, 200, nil))
	}
	fast := r.Stats("example.com", "fast").Cost()
	slow := r.Stats("example.com", "slow").Cost()
	if !(fast < slow) {
		t.Errorf("быстрый прокси должен быть дешевле: fast=%v slow=%v", fast, slow)
	}
}

func TestErrorsRaiseCost(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 10; i++ {
		r.Observe(sample("example.com", "clean", 50*time.Millisecond, 50*time.Millisecond, 100_000, 200, nil))
		r.Observe(sample("example.com", "flaky", 50*time.Millisecond, 50*time.Millisecond, 100_000, 200, nil))
	}
	// Те же задержки, но половина запросов падает.
	for i := 0; i < 10; i++ {
		r.Observe(sample("example.com", "flaky", 0, 0, 0, 0, errors.New("таймаут")))
		r.Observe(sample("example.com", "flaky", 50*time.Millisecond, 50*time.Millisecond, 100_000, 200, nil))
	}
	clean := r.Stats("example.com", "clean").Cost()
	flaky := r.Stats("example.com", "flaky").Cost()
	if !(flaky > clean) {
		t.Errorf("прокси с ошибками должен быть дороже: clean=%v flaky=%v", clean, flaky)
	}
}

func TestSmallResponsesDoNotPolluteThroughput(t *testing.T) {
	r := NewRegistry()
	// Мелкие ответы: тело приходит вместе с первым байтом, скорость вырождена.
	for i := 0; i < 5; i++ {
		r.Observe(sample("example.com", "p", 10*time.Millisecond, 10*time.Millisecond, 500, 200, nil))
	}
	if snap := r.Stats("example.com", "p").Snapshot(); snap.Throughput != 0 {
		t.Errorf("скорость посчитана по мелким ответам: %v", snap.Throughput)
	}
	r.Observe(sample("example.com", "p", 10*time.Millisecond, 10*time.Millisecond, 200_000, 200, nil))
	if snap := r.Stats("example.com", "p").Snapshot(); snap.Throughput == 0 {
		t.Error("крупный ответ должен был дать замер скорости")
	}
}

func TestBanOnStatus(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 5 * time.Minute }

	var banned []string
	r.OnBan = func(domain, proxy, reason string, until time.Time) {
		banned = append(banned, proxy+" "+reason)
	}

	r.Observe(sample("example.com", "p1", 10*time.Millisecond, 10*time.Millisecond, 1000, 429, nil))
	stats := r.Stats("example.com", "p1")
	isBanned, until, reason := stats.Banned(now)
	if !isBanned {
		t.Fatal("429 должен выключать прокси для домена")
	}
	if until != now.Add(5*time.Minute) {
		t.Errorf("бан до %s, ожидалось %s", until, now.Add(5*time.Minute))
	}
	if reason == "" || len(banned) != 1 {
		t.Errorf("причина бана не сообщена: %q, уведомлений %d", reason, len(banned))
	}

	// Бан действует только на свой домен.
	if isBanned, _, _ := r.Stats("other.com", "p1").Banned(now); isBanned {
		t.Error("бан протёк на другой домен")
	}

	// И истекает.
	if isBanned, _, _ := stats.Banned(now.Add(6 * time.Minute)); isBanned {
		t.Error("бан не истёк через 6 минут")
	}
}

func TestSlowIsNotBanned(t *testing.T) {
	now := time.Now()
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 5 * time.Minute }

	for i := 0; i < 10; i++ {
		r.Observe(sample("example.com", "slow", 3*time.Second, 4*time.Second, 100_000, 200, nil))
	}
	if isBanned, _, _ := r.Stats("example.com", "slow").Banned(now); isBanned {
		t.Error("медленный прокси должен оставаться в ротации, а не банится")
	}
}

func TestBanAfterConsecutiveFailures(t *testing.T) {
	now := time.Now()
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return time.Minute }

	fail := sample("example.com", "dead", 0, 0, 0, 0, errors.New("connection refused"))
	for i := 0; i < failsBeforeBan-1; i++ {
		r.Observe(fail)
	}
	if isBanned, _, _ := r.Stats("example.com", "dead").Banned(now); isBanned {
		t.Fatalf("бан раньше %d ошибок подряд", failsBeforeBan)
	}
	r.Observe(fail)
	if isBanned, _, _ := r.Stats("example.com", "dead").Banned(now); !isBanned {
		t.Errorf("после %d ошибок подряд прокси должен выключаться", failsBeforeBan)
	}
}

func TestSuccessResetsFailureStreak(t *testing.T) {
	now := time.Now()
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return time.Minute }

	fail := sample("example.com", "p", 0, 0, 0, 0, errors.New("таймаут"))
	ok := sample("example.com", "p", 10*time.Millisecond, 10*time.Millisecond, 100_000, 200, nil)
	for i := 0; i < 10; i++ {
		r.Observe(fail)
		r.Observe(fail)
		r.Observe(ok) // успех обнуляет серию
	}
	if isBanned, _, _ := r.Stats("example.com", "p").Banned(now); isBanned {
		t.Error("одиночные ошибки вперемешку с успехами не должны давать бан")
	}
}

// --- выбор прокси ---

func poolWith(t *testing.T, names ...string) *proxypool.Pool {
	t.Helper()
	cfg := &config.Config{
		Lists:   []config.List{{Name: "main"}},
		Domains: []config.Domain{{Pattern: "example.com", List: "main"}},
	}
	for _, n := range names {
		cfg.Proxies = append(cfg.Proxies, config.Proxy{Name: n, URL: "http://" + n + ".test:8080"})
		cfg.Lists[0].Proxies = append(cfg.Lists[0].Proxies, n)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := proxypool.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func candidates(t *testing.T, pool *proxypool.Pool) []*proxypool.Proxy {
	t.Helper()
	return pool.Proxies()
}

func TestSelectPrefersUntestedProxies(t *testing.T) {
	pool := poolWith(t, "known", "new")
	r := NewRegistry()
	r.Rand = fixedRand(0.99) // отключаем разведку, чтобы проверить именно холодный старт

	for i := 0; i < 10; i++ {
		r.Observe(sample("example.com", "known", 10*time.Millisecond, 10*time.Millisecond, 100_000, 200, nil))
	}
	for i := 0; i < 5; i++ {
		if got := r.Select("example.com", candidates(t, pool)); got.Name != "new" {
			t.Fatalf("выбран %s, а непроверенный прокси должен идти первым", got.Name)
		}
		// Замеры для нового прокси, пока их меньше minSamples.
		r.Observe(sample("example.com", "new", 20*time.Millisecond, 20*time.Millisecond, 100_000, 200, nil))
	}
}

func TestSelectFavoursCheaperButKeepsExploring(t *testing.T) {
	pool := poolWith(t, "fast", "slow")
	r := NewRegistry()

	for i := 0; i < 20; i++ {
		r.Observe(sample("example.com", "fast", 10*time.Millisecond, 10*time.Millisecond, 200_000, 200, nil))
		r.Observe(sample("example.com", "slow", 500*time.Millisecond, 500*time.Millisecond, 200_000, 200, nil))
	}

	counts := map[string]int{}
	const runs = 4000
	for i := 0; i < runs; i++ {
		counts[r.Select("example.com", candidates(t, pool)).Name]++
	}
	t.Logf("распределение за %d запросов: %v", runs, counts)
	if counts["fast"] <= counts["slow"] {
		t.Errorf("быстрый должен получать больше трафика: %v", counts)
	}
	// Разведка обязана оставлять аутсайдеру заметную долю: иначе о его
	// починке никто никогда не узнает.
	if counts["slow"] < runs/100 {
		t.Errorf("аутсайдер полностью выключен из ротации: %v", counts)
	}
	if counts["fast"] < runs/2 {
		t.Errorf("лидер получает слишком мало трафика: %v", counts)
	}
}

func TestSelectSkipsBanned(t *testing.T) {
	now := time.Now()
	pool := poolWith(t, "good", "banned")
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 10 * time.Minute }

	for i := 0; i < 5; i++ {
		r.Observe(sample("example.com", "good", 10*time.Millisecond, 10*time.Millisecond, 100_000, 200, nil))
		r.Observe(sample("example.com", "banned", 10*time.Millisecond, 10*time.Millisecond, 100_000, 200, nil))
	}
	r.Observe(sample("example.com", "banned", 10*time.Millisecond, 10*time.Millisecond, 1000, 403, nil))

	for i := 0; i < 50; i++ {
		if got := r.Select("example.com", candidates(t, pool)); got.Name == "banned" {
			t.Fatal("забаненный прокси попал в выбор")
		}
	}
}

func TestSelectReturnsNilWhenAllBanned(t *testing.T) {
	now := time.Now()
	pool := poolWith(t, "p1", "p2")
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 10 * time.Minute }

	for _, name := range []string{"p1", "p2"} {
		r.Observe(sample("example.com", name, 10*time.Millisecond, 10*time.Millisecond, 1000, 403, nil))
	}
	if got := r.Select("example.com", candidates(t, pool)); got != nil {
		t.Errorf("при всех забаненных ожидался nil, получен %s", got.Name)
	}
}

// TestPoolRespectsSelectorRefusal — отказ стратегии не должен подменяться
// round-robin: иначе бан не работал бы вовсе.
func TestPoolRespectsSelectorRefusal(t *testing.T) {
	pool := poolWith(t, "p1", "p2")
	pool.Select = func(string, []*proxypool.Proxy) *proxypool.Proxy { return nil }
	if _, err := pool.Acquire("example.com"); err == nil {
		t.Error("пул выдал прокси, хотя стратегия отказала")
	}
}

func TestBanIsAppliedThroughPool(t *testing.T) {
	now := time.Now()
	pool := poolWith(t, "p1", "p2")
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 10 * time.Minute }
	pool.Select = r.Select

	// Оба прокси получают 403 — домен остаётся без живых прокси.
	for _, name := range []string{"p1", "p2"} {
		r.Observe(sample("example.com", name, 10*time.Millisecond, 10*time.Millisecond, 1000, 403, nil))
	}
	if _, err := pool.Acquire("example.com"); err == nil {
		t.Fatal("ожидался отказ: все прокси домена забанены")
	}

	// После истечения бана домен снова обслуживается.
	r.Now = func() time.Time { return now.Add(11 * time.Minute) }
	lease, err := pool.Acquire("example.com")
	if err != nil {
		t.Fatalf("после истечения бана ожидался успех: %v", err)
	}
	lease.Release()
}

// --- сохранение на диск ---

func TestSaveLoadRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "ratings.json")

	src := NewRegistry()
	src.Now = func() time.Time { return now }
	src.BanDuration = func(string) time.Duration { return 10 * time.Minute }
	for i := 0; i < 10; i++ {
		src.Observe(sample("example.com", "fast", 10*time.Millisecond, 20*time.Millisecond, 200_000, 200, nil))
		src.Observe(sample("example.com", "slow", 300*time.Millisecond, 400*time.Millisecond, 200_000, 200, nil))
	}
	src.Observe(sample("shop.example.com", "fast", 10*time.Millisecond, 10*time.Millisecond, 1000, 429, nil))

	if err := src.Save(path); err != nil {
		t.Fatal(err)
	}

	dst := NewRegistry()
	dst.Now = func() time.Time { return now.Add(time.Minute) }
	if err := dst.Load(path); err != nil {
		t.Fatal(err)
	}

	if got, want := dst.Domains(), []string{"example.com", "shop.example.com"}; len(got) != len(want) {
		t.Fatalf("домены после загрузки: %v", got)
	}
	// Порядок сравнения прокси должен пережить перезапуск.
	if dst.Stats("example.com", "fast").Cost() >= dst.Stats("example.com", "slow").Cost() {
		t.Error("после загрузки быстрый прокси перестал быть дешевле медленного")
	}
	// Незакончившийся бан восстанавливается.
	if isBanned, _, _ := dst.Stats("shop.example.com", "fast").Banned(now.Add(time.Minute)); !isBanned {
		t.Error("действующий бан не восстановлен")
	}
	// Протухший — нет.
	stale := NewRegistry()
	stale.Now = func() time.Time { return now.Add(time.Hour) }
	if err := stale.Load(path); err != nil {
		t.Fatal(err)
	}
	if isBanned, _, _ := stale.Stats("shop.example.com", "fast").Banned(now.Add(time.Hour)); isBanned {
		t.Error("протухший бан восстановлен, хотя за это время всё могло измениться")
	}
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	r := NewRegistry()
	if err := r.Load(filepath.Join(t.TempDir(), "нет.json")); err != nil {
		t.Errorf("первый запуск не должен спотыкаться об отсутствие файла: %v", err)
	}
}

func TestLoadBrokenFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratings.json")
	if err := writeFile(path, "{не json"); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err == nil {
		t.Error("битый файл рейтингов должен возвращать ошибку")
	}
}

// TestBanIsNotExtendedWhileActive — под нагрузкой в полёте остаются десятки
// запросов, и каждый упавший пытался бы забанить заново.
func TestBanIsNotExtendedWhileActive(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 5 * time.Minute }

	var notifications int
	r.OnBan = func(string, string, string, time.Time) { notifications++ }

	fail := sample("example.com", "p", 0, 0, 0, 0, errors.New("connection refused"))
	for i := 0; i < 20; i++ {
		r.Observe(fail)
	}

	stats := r.Stats("example.com", "p")
	_, until, _ := stats.Banned(now)
	if until != now.Add(5*time.Minute) {
		t.Errorf("бан до %s, ожидалось %s — срок уехал от последующих ошибок", until, now.Add(5*time.Minute))
	}
	if notifications != 1 {
		t.Errorf("уведомлений о бане: %d, ожидалось 1", notifications)
	}
	if snap := stats.Snapshot(); snap.Bans != 1 {
		t.Errorf("счётчик банов: %d, ожидался 1", snap.Bans)
	}
}

func TestUnbanClearsBanAndStreak(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 10 * time.Minute }

	if r.Unban("example.com", "p1") {
		t.Error("снятие бана с несуществующей пары должно вернуть false")
	}
	for i := 0; i < failsBeforeBan; i++ {
		r.Observe(sample("example.com", "p1", 0, 0, 0, 0, errors.New("connection refused")))
	}
	if banned, _, _ := r.Stats("example.com", "p1").Banned(now); !banned {
		t.Fatal("после серии ошибок бан не выставлен")
	}
	if !r.Unban("example.com", "p1") {
		t.Fatal("снятие действующего бана должно вернуть true")
	}
	if banned, _, _ := r.Stats("example.com", "p1").Banned(now); banned {
		t.Error("бан не снят")
	}
	if r.Unban("example.com", "p1") {
		t.Error("повторное снятие должно вернуть false: бана уже нет")
	}
	// Серия ошибок обнулена: одна неудача после снятия не возвращает бан.
	r.Observe(sample("example.com", "p1", 0, 0, 0, 0, errors.New("connection refused")))
	if banned, _, _ := r.Stats("example.com", "p1").Banned(now); banned {
		t.Error("одна ошибка после снятия бана вернула его обратно")
	}
}

func TestEvictForgetsIdlePairsButKeepsBans(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	r.BanDuration = func(string) time.Duration { return 48 * time.Hour }

	r.Observe(sample("old.example.com", "p1", 10*time.Millisecond, 20*time.Millisecond, 1000, 200, nil))
	r.Observe(sample("old.example.com", "p2", 10*time.Millisecond, 20*time.Millisecond, 1000, 403, nil))
	// Пара, заведённая выбором без единого замера, тоже считается свежей.
	r.Stats("old.example.com", "p3")

	now = now.Add(25 * time.Hour)
	r.Observe(sample("fresh.example.com", "p1", 10*time.Millisecond, 20*time.Millisecond, 1000, 200, nil))

	if got := r.Evict(); got != 2 {
		t.Fatalf("вытеснено %d пар, ожидалось 2 (p1 и p3 у старого домена)", got)
	}
	snap := r.Snapshot("old.example.com")
	if _, ok := snap.Proxies["p2"]; !ok {
		t.Error("забаненная пара вытеснена, хотя бан ещё действует")
	}
	if _, ok := snap.Proxies["p1"]; ok {
		t.Error("простоявшая сутки пара не вытеснена")
	}
	if got := r.Domains(); len(got) != 2 {
		t.Errorf("домены после вытеснения: %v", got)
	}

	// Домен без единой живой пары исчезает целиком.
	now = now.Add(48 * time.Hour)
	r.Evict()
	if got := r.Domains(); len(got) != 0 {
		t.Errorf("после полного простоя домены должны исчезнуть, осталось: %v", got)
	}

	// Отрицательный срок выключает вытеснение.
	r.EvictAfter = -1
	r.Observe(sample("keep.example.com", "p1", 10*time.Millisecond, 20*time.Millisecond, 1000, 200, nil))
	now = now.Add(1000 * time.Hour)
	if got := r.Evict(); got != 0 {
		t.Errorf("при выключенном вытеснении снесено %d пар", got)
	}
}

func TestLoadWithoutLastUsedIsNotEvictedAtOnce(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "ratings.json")
	// Снапшот прежней версии: без last_used.
	raw := `{"saved_at":"2026-09-08T11:00:00Z","domains":{"example.com":{"p1":{"connect_ms":10,"ttfb_ms":20,"samples":5,"requests":5,"cost":0.3}}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	r.Now = func() time.Time { return now }
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := r.Evict(); got != 0 {
		t.Errorf("запись без метки времени вытеснена сразу после загрузки (%d)", got)
	}
}
