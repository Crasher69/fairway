package forward

// Route — выбранный под запрос маршрут: через какой апстрим идём и что с ним
// делать. Release обязателен к вызову по завершении запроса — на нём держатся
// счётчики параллелизма в пуле.
type Route struct {
	Upstream *Upstream
	// Name — как маршрут подписан в логах и метриках (обычно имя прокси).
	Name string
	// ID — постоянный ключ прокси: по нему копится рейтинг и исключаются
	// уже не сработавшие маршруты. Имя можно поменять, id — нет. Пусто —
	// ключом служит Name.
	ID string
	// MITM — расшифровывать ли TLS. Используется начиная с этапа 4.
	MITM bool
	// Release освобождает ресурсы пула. Может быть nil.
	Release func()
}

// key — ключ маршрута для рейтинга и списка avoid.
func (r *Route) key() string {
	if r.ID != "" {
		return r.ID
	}
	return r.Name
}

// sample — заготовка замера для запроса через этот маршрут.
func (r *Route) sample(domain string) Sample {
	return Sample{Domain: domain, Upstream: r.Name, ProxyID: r.key()}
}

func (r *Route) release() {
	if r != nil && r.Release != nil {
		r.Release()
	}
}
