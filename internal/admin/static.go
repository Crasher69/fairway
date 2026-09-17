package admin

import (
	"embed"
	"io/fs"
	"net/http"
)

// Файлы админки вшиваются в бинарник: на выходе по-прежнему один файл,
// который достаточно скопировать на сервер.
//
//go:embed web
var webFS embed.FS

// staticFiles — то, что отдаётся без проверки доступа: оболочка панели,
// в которой рисуется форма входа. Список явный, а не «всё, что не /api»:
// иначе любая новая ручка без префикса /api молча стала бы открытой.
var staticFiles = map[string]bool{
	"/":            true,
	"/index.html":  true,
	"/app.js":      true,
	"/i18n.js":     true,
	"/style.css":   true,
	"/icon.svg":    true,
	"/favicon.png": true,
}

func isStaticPath(path string) bool { return staticFiles[path] }

func staticHandler() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// Каталог вшит на этапе компиляции — если его нет, это ошибка сборки.
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
