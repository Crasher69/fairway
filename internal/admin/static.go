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

func staticHandler() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// Каталог вшит на этапе компиляции — если его нет, это ошибка сборки.
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
