package i18n

import (
	"regexp"
	"testing"
)

func TestDefaultIsEnglishAndPassesThrough(t *testing.T) {
	Set(EN)
	if got := T("config reloaded"); got != "config reloaded" {
		t.Errorf("английский должен возвращать ключ как есть: %q", got)
	}
	if got := T("no such key %d"); got != "no such key %d" {
		t.Errorf("неизвестный ключ должен вернуться как есть: %q", got)
	}
}

func TestRussianTranslates(t *testing.T) {
	Set(RU)
	defer Set(EN)
	if got := T("config reloaded"); got != "конфиг перечитан" {
		t.Errorf("перевод: %q", got)
	}
	if got := Sprintf("proxy %q not found", "p1"); got != `прокси "p1" не найден` {
		t.Errorf("Sprintf: %q", got)
	}
	if err := Errorf("port %d out of range", 70000); err.Error() != "порт 70000 вне диапазона" {
		t.Errorf("Errorf: %v", err)
	}
}

func TestParse(t *testing.T) {
	if l, err := Parse(""); err != nil || l != EN {
		t.Errorf("пустая строка должна давать язык по умолчанию: %v %v", l, err)
	}
	if l, err := Parse("ru"); err != nil || l != RU {
		t.Errorf("ru: %v %v", l, err)
	}
	if _, err := Parse("de"); err == nil {
		t.Error("неизвестный язык должен быть ошибкой")
	}
	Set(Lang("de"))
	if Current() != EN {
		t.Error("Set с неизвестным языком не должен ничего менять")
	}
}

// Перевод обязан сохранять глаголы формата: иначе fmt подставит
// %!s(MISSING) или потеряет аргумент.
func TestCatalogKeepsFormatVerbs(t *testing.T) {
	verbs := regexp.MustCompile(`%[-+# 0]*\d*(\.\d+)?[a-zA-Z]`)
	for key, tr := range ru {
		want := verbs.FindAllString(key, -1)
		got := verbs.FindAllString(tr, -1)
		if len(want) != len(got) {
			t.Errorf("%q: в переводе %d глаголов, в ключе %d", key, len(got), len(want))
			continue
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("%q: глагол %s вместо %s", key, got[i], want[i])
			}
		}
	}
}
