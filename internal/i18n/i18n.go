// Package i18n — язык сообщений: логов, ошибок, ответов API и панели.
//
// Ключ сообщения — его английский текст. Английский язык по умолчанию и
// каталога не требует: T возвращает ключ как есть. Для других языков
// каталог — обычная карта «английский → перевод». Такой подход (как в
// gettext) держит код читаемым: в вызове видно, что именно пишется, а не
// идентификатор вроде ERR_PROXY_NOT_FOUND.
//
// Формат — как у fmt: ключ может содержать %s, %d, %q, %w; перевод обязан
// содержать те же глаголы в том же порядке.
//
// Язык один на процесс и хранится в конфиге (поле language): панель его
// переключает, и после применения конфига лог тоже переходит на него.
package i18n

import (
	"fmt"
	"sort"
	"sync/atomic"
)

// Lang — код языка: en, ru.
type Lang string

const (
	EN Lang = "en"
	RU Lang = "ru"
)

// Default — язык, пока конфиг не задал другой.
const Default = EN

var catalogs = map[Lang]map[string]string{
	EN: nil, // английский — исходный текст, переводить нечего
	RU: ru,
}

var current atomic.Value

func init() { current.Store(Default) }

// Set переключает язык процесса. Неизвестный код игнорируется: лучше
// остаться на прежнем языке, чем упасть из-за опечатки в конфиге.
func Set(l Lang) {
	if _, ok := catalogs[l]; ok {
		current.Store(l)
	}
}

// Current — действующий язык.
func Current() Lang { return current.Load().(Lang) }

// Supported перечисляет коды языков, для которых есть каталог.
func Supported() []Lang {
	out := make([]Lang, 0, len(catalogs))
	for l := range catalogs {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Parse проверяет код языка из конфига. Пустая строка означает язык
// по умолчанию.
func Parse(s string) (Lang, error) {
	if s == "" {
		return Default, nil
	}
	l := Lang(s)
	if _, ok := catalogs[l]; !ok {
		return "", Errorf("unknown language %q (supported: %v)", s, Supported())
	}
	return l, nil
}

// T переводит строку формата. Нет перевода — возвращает ключ.
func T(msg string) string {
	if c := catalogs[Current()]; c != nil {
		if t, ok := c[msg]; ok {
			return t
		}
	}
	return msg
}

// Sprintf — fmt.Sprintf с переведённым форматом.
func Sprintf(msg string, args ...any) string {
	return fmt.Sprintf(T(msg), args...)
}

// Errorf — fmt.Errorf с переведённым форматом; %w работает как обычно.
func Errorf(msg string, args ...any) error {
	return fmt.Errorf(T(msg), args...)
}
