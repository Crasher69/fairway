// Command mkicon генерирует иконку приложения из internal/brand:
//   - cmd/fairway/rsrc_windows_<arch>.syso — ресурс со значком, линковщик
//     Go подхватывает его сам, и у exe появляется иконка в проводнике;
//   - internal/admin/web/favicon.png — значок вкладки для браузеров, не
//     понимающих SVG-favicon;
//   - docs/icon.png — картинка для README.
//
// Результаты лежат в репозитории: обычная сборка `go build ./cmd/fairway`
// не должна требовать генерации. Перезапускать после правки рисунка:
//
//	go generate ./cmd/fairway
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"fairway/internal/brand"
)

func main() {
	root := flag.String("root", ".", "repository root")
	ico := flag.String("ico", "", "additionally write an .ico to this path")
	flag.Parse()

	write := func(rel string, data []byte) {
		path := filepath.Join(*root, rel)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatalf("%s: %v", rel, err)
		}
		fmt.Printf("  %s (%d bytes)\n", rel, len(data))
	}

	for _, m := range brand.Machines {
		write(filepath.Join("cmd", "fairway", "rsrc_windows_"+m.Name+".syso"), brand.Syso(m))
	}
	write(filepath.Join("internal", "admin", "web", "favicon.png"), brand.PNG(32))
	write(filepath.Join("docs", "icon.png"), brand.PNG(128))
	if *ico != "" {
		if err := os.WriteFile(*ico, brand.ICO(), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  %s\n", *ico)
	}
}
