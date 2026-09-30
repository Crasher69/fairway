package config

import (
	"encoding/json"
	"errors"
	"sync"
)

// Editor меняет конфиг на диске и применяет его на лету.
//
// Им пользуются все, кто правит конфиг программно: панель, а дальше и
// плагины. Дисциплина у всех одна: правки идут по очереди (mutex), каждая
// проверяется целиком до записи, и файл на диске остаётся единственным
// источником правды — сторож перечитает его и применит теми же путями, что
// и ручную правку.
type Editor struct {
	Path string
	// Current отдаёт конфиг, применённый последним.
	Current func() *Config
	// Apply применяет новый конфиг к живому пулу.
	Apply func(*Config) error
	// Write, если задан, выполняет запись файла. Это сторож конфига
	// (Watcher.Write): он пишет под своим замком и отмечает запись
	// применённой, чтобы не принять её за чужую правку и не применить
	// второй раз. Может быть nil.
	Write func(save func() error) error

	mu sync.Mutex
}

// ErrNoEditor означает, что запись не настроена (например, конфиг задан
// флагами -upstream и файла нет).
var ErrNoEditor = errors.New("config editing is unavailable")

// Edit применяет изменение к копии конфига, проверяет и сохраняет. Ошибка
// из change прерывает правку: файл не трогается, пул тоже.
func (e *Editor) Edit(change func(*Config) error) (*Config, error) {
	if e == nil || e.Path == "" {
		return nil, ErrNoEditor
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	next := e.Current().Clone()
	if err := change(next); err != nil {
		return nil, err
	}
	// Проверяем до записи: битый конфиг не должен попасть на диск даже
	// на мгновение — его подхватит сторож и начнёт ругаться.
	if err := next.Validate(); err != nil {
		return nil, err
	}
	save := func() error { return next.Save(e.Path) }
	if e.Write != nil {
		if err := e.Write(save); err != nil {
			return nil, err
		}
	} else if err := save(); err != nil {
		return nil, err
	}
	if err := e.Apply(next); err != nil {
		return nil, err
	}
	return next, nil
}

// Reload перечитывает конфиг с диска и применяет его. Нужен, когда файл
// правили руками и ждать опроса сторожа не хочется. Ошибки чтения и
// применения различаются, чтобы вызывающий мог объяснить, что случилось.
func (e *Editor) Reload() (*Config, error) {
	if e == nil || e.Path == "" {
		return nil, ErrNoEditor
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, err := Load(e.Path)
	if err != nil {
		return nil, &ReloadError{Err: err}
	}
	if err := e.Apply(cfg); err != nil {
		return nil, &ReloadError{Err: err, Applying: true}
	}
	return cfg, nil
}

// ReloadError — ошибка Reload: при чтении файла или при применении.
type ReloadError struct {
	Err      error
	Applying bool
}

func (e *ReloadError) Error() string { return e.Err.Error() }
func (e *ReloadError) Unwrap() error { return e.Err }

// Clone делает глубокую копию: менять живой конфиг на месте нельзя, его
// в этот момент читают обработчики запросов.
func (c *Config) Clone() *Config {
	dst := &Config{
		Defaults: c.Defaults,
		Language: c.Language,
		// Пароль панели копируется вместе с остальным: иначе любая правка
		// из панели молча снимала бы его.
		AdminPassword: c.AdminPassword,
		ProxyAuth:     c.ProxyAuth,
	}
	dst.ProxyAuth.Users = append([]ProxyUser(nil), c.ProxyAuth.Users...)
	dst.Proxies = append([]Proxy(nil), c.Proxies...)
	dst.Lists = append([]List(nil), c.Lists...)
	for i, l := range c.Lists {
		dst.Lists[i].Proxies = append([]string(nil), l.Proxies...)
	}
	dst.Domains = append([]Domain(nil), c.Domains...)
	for i, d := range c.Domains {
		if d.MITM != nil {
			mitm := *d.MITM
			dst.Domains[i].MITM = &mitm
		}
	}
	dst.Plugins = append([]Plugin(nil), c.Plugins...)
	for i, p := range c.Plugins {
		dst.Plugins[i].Granted = append([]string(nil), p.Granted...)
		dst.Plugins[i].Settings = append(json.RawMessage(nil), p.Settings...)
	}
	return dst
}
