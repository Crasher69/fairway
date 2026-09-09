package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"fairway/internal/config"
	"fairway/internal/i18n"
)

// Editor меняет конфиг на диске и применяет его на лету.
//
// Отдельный тип, а не метод сервера, потому что здесь нужна своя дисциплина:
// правки идут по очереди (mutex), каждая проверяется целиком до записи, и
// файл на диске остаётся единственным источником правды — сторож перечитает
// его и применит теми же путями, что и ручную правку.
type Editor struct {
	Path string
	// Current отдаёт конфиг, применённый последним.
	Current func() *config.Config
	// Apply применяет новый конфиг к живому пулу.
	Apply func(*config.Config) error
	// Saved вызывается сразу после записи файла — сторожу конфига, чтобы он
	// не принял нашу же запись за чужую правку и не применил её второй раз.
	// Может быть nil.
	Saved func()

	mu sync.Mutex
}

// ErrNoEditor означает, что запись не настроена (например, конфиг задан
// флагами -upstream и файла нет).
var ErrNoEditor = errors.New("config editing is unavailable")

// edit применяет изменение к копии конфига, проверяет и сохраняет.
func (e *Editor) edit(change func(*config.Config) error) (*config.Config, error) {
	if e == nil || e.Path == "" {
		return nil, ErrNoEditor
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	next := cloneConfig(e.Current())
	if err := change(next); err != nil {
		return nil, err
	}
	// Проверяем до записи: битый конфиг не должен попасть на диск даже
	// на мгновение — его подхватит сторож и начнёт ругаться.
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := next.Save(e.Path); err != nil {
		return nil, err
	}
	if e.Saved != nil {
		e.Saved()
	}
	if err := e.Apply(next); err != nil {
		return nil, err
	}
	return next, nil
}

// cloneConfig делает глубокую копию: менять живой конфиг на месте нельзя,
// его в этот момент читают обработчики запросов.
func cloneConfig(src *config.Config) *config.Config {
	dst := &config.Config{Defaults: src.Defaults, Language: src.Language}
	dst.Proxies = append([]config.Proxy(nil), src.Proxies...)
	dst.Lists = append([]config.List(nil), src.Lists...)
	for i, l := range src.Lists {
		dst.Lists[i].Proxies = append([]string(nil), l.Proxies...)
	}
	dst.Domains = append([]config.Domain(nil), src.Domains...)
	for i, d := range src.Domains {
		if d.MITM != nil {
			mitm := *d.MITM
			dst.Domains[i].MITM = &mitm
		}
	}
	return dst
}

// --- обработчики ---

func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Config())
}

func (s *Server) addProxy(w http.ResponseWriter, r *http.Request) {
	var body config.Proxy
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		for _, existing := range cfg.Proxies {
			if existing.Name == body.Name {
				return i18n.Errorf("proxy %q already exists", body.Name)
			}
		}
		cfg.Proxies = append(cfg.Proxies, body)
		return nil
	})
}

// updateProxy правит существующий прокси, в том числе переименовывает.
// При переименовании ссылки в листах чинятся здесь же — иначе правка имени
// разваливала бы конфиг.
func (s *Server) updateProxy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body config.Proxy
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		index := -1
		for i, existing := range cfg.Proxies {
			if existing.Name == name {
				index = i
				continue
			}
			if existing.Name == body.Name {
				return i18n.Errorf("proxy %q already exists", body.Name)
			}
		}
		if index < 0 {
			return i18n.Errorf("proxy %q not found", name)
		}
		cfg.Proxies[index] = body
		if body.Name != name {
			for i := range cfg.Lists {
				for j, ref := range cfg.Lists[i].Proxies {
					if ref == name {
						cfg.Lists[i].Proxies[j] = body.Name
					}
				}
			}
		}
		return nil
	})
}

func (s *Server) deleteProxy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.applyEdit(w, func(cfg *config.Config) error {
		// Сначала выкидываем из листов: иначе проверка честно упадёт на
		// ссылке в никуда, и пользователь получит невнятную ошибку вместо
		// ожидаемого удаления.
		for i := range cfg.Lists {
			cfg.Lists[i].Proxies = without(cfg.Lists[i].Proxies, name)
		}
		before := len(cfg.Proxies)
		kept := cfg.Proxies[:0]
		for _, p := range cfg.Proxies {
			if p.Name != name {
				kept = append(kept, p)
			}
		}
		cfg.Proxies = kept
		if len(cfg.Proxies) == before {
			return i18n.Errorf("proxy %q not found", name)
		}
		return nil
	})
}

func (s *Server) saveList(w http.ResponseWriter, r *http.Request) {
	var body config.List
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		for i, existing := range cfg.Lists {
			if existing.Name == body.Name {
				cfg.Lists[i] = body
				return nil
			}
		}
		cfg.Lists = append(cfg.Lists, body)
		return nil
	})
}

// updateList правит существующий лист, в том числе переименовывает.
// На имя листа ссылаются правила доменов и лист по умолчанию — при
// переименовании ссылки чинятся здесь же, иначе правка имени разваливала
// бы конфиг и человек видел бы «нет листа с именем …» вместо результата.
func (s *Server) updateList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body config.List
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		index := -1
		for i, existing := range cfg.Lists {
			if existing.Name == name {
				index = i
				continue
			}
			if existing.Name == body.Name {
				return i18n.Errorf("list %q already exists", body.Name)
			}
		}
		if index < 0 {
			return i18n.Errorf("list %q not found", name)
		}
		cfg.Lists[index] = body
		if body.Name != name {
			for i := range cfg.Domains {
				if cfg.Domains[i].List == name {
					cfg.Domains[i].List = body.Name
				}
			}
			if cfg.Defaults.List == name {
				cfg.Defaults.List = body.Name
			}
		}
		return nil
	})
}

// bulkProxies — одно действие над несколькими прокси разом: удалить,
// положить в лист, убрать из листа. Одна правка конфига на всю пачку, а не
// цикл из одиночных запросов: полсотни перезаписей файла — это полсотни
// шансов застать конфиг применённым наполовину.
func (s *Server) bulkProxies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Names  []string `json:"names"`
		Action string   `json:"action"`
		List   string   `json:"list"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Names) == 0 {
		http.Error(w, i18n.T("no proxies selected"), http.StatusBadRequest)
		return
	}
	chosen := make(map[string]bool, len(body.Names))
	for _, n := range body.Names {
		chosen[n] = true
	}

	s.applyEdit(w, func(cfg *config.Config) error {
		known := make(map[string]bool, len(cfg.Proxies))
		for _, p := range cfg.Proxies {
			known[p.Name] = true
		}
		for _, n := range body.Names {
			if !known[n] {
				return i18n.Errorf("proxy %q not found", n)
			}
		}

		switch body.Action {
		case "delete":
			for i := range cfg.Lists {
				cfg.Lists[i].Proxies = withoutAny(cfg.Lists[i].Proxies, chosen)
			}
			kept := cfg.Proxies[:0]
			for _, p := range cfg.Proxies {
				if !chosen[p.Name] {
					kept = append(kept, p)
				}
			}
			cfg.Proxies = kept
			return nil

		case "add_to_list":
			if body.List == "" {
				return i18n.Errorf("no list given")
			}
			for i, list := range cfg.Lists {
				if list.Name != body.List {
					continue
				}
				present := make(map[string]bool, len(list.Proxies))
				for _, ref := range list.Proxies {
					present[ref] = true
				}
				// Порядок отмеченных сохраняем, уже лежащие в листе
				// не дублируем.
				for _, n := range body.Names {
					if !present[n] {
						cfg.Lists[i].Proxies = append(cfg.Lists[i].Proxies, n)
						present[n] = true
					}
				}
				return nil
			}
			cfg.Lists = append(cfg.Lists, config.List{Name: body.List, Proxies: append([]string(nil), body.Names...)})
			return nil

		case "remove_from_list":
			if body.List == "" {
				return i18n.Errorf("no list given")
			}
			for i, list := range cfg.Lists {
				if list.Name == body.List {
					cfg.Lists[i].Proxies = withoutAny(list.Proxies, chosen)
					return nil
				}
			}
			return i18n.Errorf("list %q not found", body.List)

		default:
			return i18n.Errorf("unknown action %q", body.Action)
		}
	})
}

func withoutAny(list []string, drop map[string]bool) []string {
	out := list[:0]
	for _, item := range list {
		if !drop[item] {
			out = append(out, item)
		}
	}
	return out
}

func (s *Server) deleteList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.applyEdit(w, func(cfg *config.Config) error {
		kept := cfg.Lists[:0]
		found := false
		for _, l := range cfg.Lists {
			if l.Name == name {
				found = true
				continue
			}
			kept = append(kept, l)
		}
		cfg.Lists = kept
		if !found {
			return i18n.Errorf("list %q not found", name)
		}
		return nil
	})
}

func (s *Server) saveDomain(w http.ResponseWriter, r *http.Request) {
	var body config.Domain
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		for i, existing := range cfg.Domains {
			if existing.Pattern == body.Pattern {
				cfg.Domains[i] = body
				return nil
			}
		}
		cfg.Domains = append(cfg.Domains, body)
		return nil
	})
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	pattern := r.PathValue("pattern")
	s.applyEdit(w, func(cfg *config.Config) error {
		kept := cfg.Domains[:0]
		found := false
		for _, d := range cfg.Domains {
			if d.Pattern == pattern {
				found = true
				continue
			}
			kept = append(kept, d)
		}
		cfg.Domains = kept
		if !found {
			return i18n.Errorf("rule %q not found", pattern)
		}
		return nil
	})
}

func (s *Server) saveDefaults(w http.ResponseWriter, r *http.Request) {
	var body config.Defaults
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		cfg.Defaults = body
		return nil
	})
}

// saveLanguage переключает язык. Это правка конфига, как и любая другая:
// поле сохраняется в файл, и после применения лог переходит на новый язык.
func (s *Server) saveLanguage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Language string `json:"language"`
	}
	if !decode(w, r, &body) {
		return
	}
	s.applyEdit(w, func(cfg *config.Config) error {
		if _, err := i18n.Parse(body.Language); err != nil {
			return err
		}
		cfg.Language = body.Language
		return nil
	})
}

// reload перечитывает конфиг с диска и применяет его. Нужен, когда файл
// правили руками и ждать опроса сторожа не хочется.
func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if s.Editor == nil || s.Editor.Path == "" {
		http.Error(w, ErrNoEditor.Error(), http.StatusBadRequest)
		return
	}
	cfg, err := config.Load(s.Editor.Path)
	if err != nil {
		http.Error(w, i18n.T("config not reloaded: ")+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Editor.Apply(cfg); err != nil {
		http.Error(w, i18n.T("config not applied: ")+err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, cfg)
}

// applyEdit — общий хвост всех правок: применить, ответить конфигом или
// понятной ошибкой.
func (s *Server) applyEdit(w http.ResponseWriter, change func(*config.Config) error) {
	cfg, err := s.Editor.edit(change)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNoEditor) {
			status = http.StatusNotImplemented
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, cfg)
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		http.Error(w, i18n.T("request body: ")+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func without(list []string, name string) []string {
	out := list[:0]
	for _, item := range list {
		if item != name {
			out = append(out, item)
		}
	}
	return out
}

// importProxies добавляет прокси списком. Отдельная ручка, а не цикл из
// POST /api/proxies: полсотни отдельных запросов — это полсотни перезаписей
// конфига, и на середине список может оказаться применён наполовину.
func (s *Server) importProxies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text    string `json:"text"`
		Scheme  string `json:"scheme"`
		Prefix  string `json:"prefix"`
		Country string `json:"country"`
		Comment string `json:"comment"`
		List    string `json:"list"`
	}
	if !decode(w, r, &body) {
		return
	}

	var result config.ImportResult
	cfg, err := s.Editor.edit(func(cfg *config.Config) error {
		result = cfg.ImportProxies(body.Text, body.Scheme, body.Prefix, body.Country, body.Comment)
		if result.AddedN == 0 {
			// Нечего добавлять — не переписываем файл на ровном месте,
			// но и не считаем это ошибкой: разбор строк уже в result.
			return errNothingImported
		}
		// Сразу положить импортированное в лист — иначе после импорта
		// пришлось бы вручную отмечать полсотни галочек.
		if body.List != "" {
			names := make([]string, 0, len(result.Added))
			for _, p := range result.Added {
				names = append(names, p.Name)
			}
			for i, list := range cfg.Lists {
				if list.Name == body.List {
					cfg.Lists[i].Proxies = append(cfg.Lists[i].Proxies, names...)
					return nil
				}
			}
			cfg.Lists = append(cfg.Lists, config.List{Name: body.List, Proxies: names})
		}
		return nil
	})

	if err != nil && !errors.Is(err, errNothingImported) {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNoEditor) {
			status = http.StatusNotImplemented
		}
		http.Error(w, err.Error(), status)
		return
	}

	writeJSON(w, struct {
		config.ImportResult
		Config *config.Config `json:"config,omitempty"`
	}{ImportResult: result, Config: cfg})
}

// errNothingImported прерывает правку, когда добавлять нечего: сохранять
// и применять конфиг в этом случае незачем.
var errNothingImported = errors.New("no lines parsed")
