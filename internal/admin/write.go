package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"fairway/internal/config"
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

	mu sync.Mutex
}

// ErrNoEditor означает, что запись не настроена (например, конфиг задан
// флагами -upstream и файла нет).
var ErrNoEditor = errors.New("правка конфига недоступна")

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
	if err := e.Apply(next); err != nil {
		return nil, err
	}
	return next, nil
}

// cloneConfig делает глубокую копию: менять живой конфиг на месте нельзя,
// его в этот момент читают обработчики запросов.
func cloneConfig(src *config.Config) *config.Config {
	dst := &config.Config{Defaults: src.Defaults}
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
				return fmt.Errorf("прокси %q уже есть", body.Name)
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
				return fmt.Errorf("прокси %q уже есть", body.Name)
			}
		}
		if index < 0 {
			return fmt.Errorf("прокси %q не найден", name)
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
			return fmt.Errorf("прокси %q не найден", name)
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
			return fmt.Errorf("лист %q не найден", name)
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
			return fmt.Errorf("правило %q не найдено", pattern)
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

// reload перечитывает конфиг с диска и применяет его. Нужен, когда файл
// правили руками и ждать опроса сторожа не хочется.
func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if s.Editor == nil || s.Editor.Path == "" {
		http.Error(w, ErrNoEditor.Error(), http.StatusBadRequest)
		return
	}
	cfg, err := config.Load(s.Editor.Path)
	if err != nil {
		http.Error(w, "конфиг не перечитан: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Editor.Apply(cfg); err != nil {
		http.Error(w, "конфиг не применён: "+err.Error(), http.StatusBadRequest)
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
		http.Error(w, "тело запроса: "+err.Error(), http.StatusBadRequest)
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
