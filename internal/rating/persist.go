package rating

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"fairway/internal/i18n"
)

// snapshotFile — формат файла с рейтингами на диске.
type snapshotFile struct {
	SavedAt time.Time                      `json:"saved_at"`
	Domains map[string]map[string]Snapshot `json:"domains"`
}

// Save сохраняет рейтинги на диск. Запись атомарная (во временный файл и
// rename), чтобы падение в момент сохранения не оставило обрезанный файл.
func (r *Registry) Save(path string) error {
	file := snapshotFile{SavedAt: r.now(), Domains: map[string]map[string]Snapshot{}}
	for _, domain := range r.Domains() {
		snap := r.Snapshot(domain)
		if len(snap.Proxies) > 0 {
			file.Domains[domain] = snap.Proxies
		}
	}

	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Load поднимает рейтинги из файла. Отсутствие файла — не ошибка: при первом
// запуске статистики просто нет.
func (r *Registry) Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file snapshotFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return i18n.Errorf("parsing ratings %s: %w", path, err)
	}

	now := r.now()
	for domain, byProxy := range file.Domains {
		for proxy, snap := range byProxy {
			r.Stats(domain, proxy).restore(snap, now)
		}
	}
	return nil
}

// Autosave периодически сохраняет рейтинги и делает финальное сохранение
// при отмене контекста — чтобы перезапуск не начинался с чистого листа.
// Перед каждым сохранением вытесняются давно не использованные пары:
// чистить удобнее всего там, где таблица и так обходится целиком.
func (r *Registry) Autosave(ctx context.Context, path string, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	save := func() {
		r.Evict()
		if err := r.Save(path); err != nil && onError != nil {
			onError(err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			save()
			return
		case <-ticker.C:
			save()
		}
	}
}
