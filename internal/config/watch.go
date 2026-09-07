package config

import (
	"context"
	"os"
	"time"
)

// DefaultPollInterval — как часто проверяется файл конфига.
const DefaultPollInterval = 2 * time.Second

// Watcher следит за файлом конфига и применяет изменения на лету.
//
// Начальный штамп снимается в NewWatcher, то есть синхронно в вызывающей
// горутине. Это важно: если снимать его уже внутри Run, правка, сделанная
// сразу после запуска, может быть принята за исходное состояние и молча
// потеряна — при hot-reload такое ловится крайне неприятно.
//
// Слежение сделано опросом mtime+size, а не через inotify/ReadDirectoryChanges:
// без зависимостей, одинаково работает на всех ОС и переживает атомарную
// замену файла (когда редактор пишет во временный файл и делает rename).
type Watcher struct {
	path     string
	interval time.Duration

	last   fileStamp // последняя применённая версия
	failed fileStamp // версия, на которую уже пожаловались
}

// NewWatcher создаёт сторож для файла. Файл может ещё не существовать —
// тогда первая же появившаяся валидная версия будет применена.
func NewWatcher(path string, interval time.Duration) *Watcher {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	w := &Watcher{path: path, interval: interval}
	w.last, _ = stamp(path)
	return w
}

// Run блокируется до отмены контекста, вызывая onChange на каждую валидную
// новую версию конфига. Битая версия не применяется: onError получает ошибку,
// в работе остаётся предыдущая — опечатка в JSON не должна ронять живой прокси.
func (w *Watcher) Run(ctx context.Context, onChange func(*Config), onError func(error)) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := stamp(w.path)
			if err != nil || current == w.last {
				continue
			}
			cfg, err := Load(w.path)
			if err != nil {
				// Файл могли поймать в момент записи, поэтому last не трогаем —
				// следующий тик перечитает. Но об одной и той же битой версии
				// сообщаем один раз, иначе лог забьётся повторами.
				if onError != nil && current != w.failed {
					onError(err)
				}
				w.failed = current
				continue
			}
			w.last = current
			onChange(cfg)
		}
	}
}

// stamp — дешёвая подпись файла: время изменения и размер.
type fileStamp struct {
	mod  time.Time
	size int64
}

func stamp(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{mod: fi.ModTime(), size: fi.Size()}, nil
}
