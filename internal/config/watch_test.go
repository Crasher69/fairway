package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchAppliesOnlyValidConfigs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(t *testing.T, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Исходный конфиг кладём ДО запуска сторожа — так же, как в бою, где файл
	// уже загружен. Иначе начальный штамп может быть снят после первой записи,
	// и она будет принята за исходное состояние.
	write(t, `{"proxies":[{"name":"p1","url":"http://1.1.1.1:80"}]}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes := make(chan *Config, 16)
	failures := make(chan error, 16)
	watcher := NewWatcher(path, 20*time.Millisecond)
	go watcher.Run(ctx,
		func(c *Config) { changes <- c },
		func(err error) { failures <- err })

	// Битый конфиг: должна прийти ошибка, применения быть не должно.
	write(t, `{"proxies":[{"name":"p1"`)
	select {
	case <-failures:
	case c := <-changes:
		t.Fatalf("битый конфиг применён: %+v", c)
	case <-time.After(5 * time.Second):
		t.Fatal("сторож не заметил битый конфиг")
	}

	// Об одной и той же битой версии ругаемся один раз, а не каждый тик.
	select {
	case err := <-failures:
		t.Errorf("повторная жалоба на ту же версию конфига: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// Исправленный конфиг должен примениться.
	write(t, `{"proxies":[{"name":"p1","url":"http://1.1.1.1:80"},{"name":"p2","url":"http://2.2.2.2:80"}]}`)
	select {
	case c := <-changes:
		if len(c.Proxies) != 2 {
			t.Fatalf("применён конфиг с %d прокси, ожидалось 2", len(c.Proxies))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("сторож не применил исправленный конфиг")
	}
}

func TestMarkAppliedSkipsOwnWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(t *testing.T, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(t, `{"proxies":[{"name":"p1","url":"http://1.1.1.1:80"}]}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes := make(chan *Config, 16)
	watcher := NewWatcher(path, 20*time.Millisecond)
	go watcher.Run(ctx, func(c *Config) { changes <- c }, nil)

	// Запись «своя»: панель сохранила и применила сама, сторож должен
	// промолчать. Штамп сравнивается по mtime и размеру, поэтому размер
	// меняем — иначе на файловой системе с грубым mtime тест ничего бы
	// не проверял.
	write(t, `{"proxies":[{"name":"p1","url":"http://1.1.1.1:80"},{"name":"p2","url":"http://2.2.2.2:80"}]}`)
	watcher.MarkApplied()
	select {
	case c := <-changes:
		t.Fatalf("сторож применил собственную запись панели: %d прокси", len(c.Proxies))
	case <-time.After(300 * time.Millisecond):
	}

	// А чужую правку по-прежнему замечает.
	write(t, `{"proxies":[{"name":"p1","url":"http://1.1.1.1:80"},{"name":"p2","url":"http://2.2.2.2:80"},{"name":"p3","url":"http://3.3.3.3:80"}]}`)
	select {
	case c := <-changes:
		if len(c.Proxies) != 3 {
			t.Fatalf("применён конфиг с %d прокси, ожидалось 3", len(c.Proxies))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("сторож не заметил ручную правку после MarkApplied")
	}
}
