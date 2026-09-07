package forward

// Route — выбранный под запрос маршрут: через какой апстрим идём и что с ним
// делать. Release обязателен к вызову по завершении запроса — на нём держатся
// счётчики параллелизма в пуле.
type Route struct {
	Upstream *Upstream
	// Name — как маршрут подписан в логах и метриках (обычно имя прокси).
	Name string
	// MITM — расшифровывать ли TLS. Используется начиная с этапа 4.
	MITM bool
	// Release освобождает ресурсы пула. Может быть nil.
	Release func()
}

func (r *Route) release() {
	if r != nil && r.Release != nil {
		r.Release()
	}
}
