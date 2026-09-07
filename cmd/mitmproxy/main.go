// Command mitmproxy — адаптивный прокси-балансировщик с опциональным MITM.
package main

import (
	"flag"
	"log"
)

var version = "dev"

func main() {
	var (
		proxyAddr = flag.String("proxy", ":8080", "адрес прокси-сервера")
		adminAddr = flag.String("admin", "127.0.0.1:8081", "адрес админки (только loopback по умолчанию)")
		dataDir   = flag.String("data", "./data", "каталог для CA, конфига и снапшотов рейтингов")
	)
	flag.Parse()

	log.Printf("mitmproxy %s: proxy=%s admin=%s data=%s", version, *proxyAddr, *adminAddr, *dataDir)
	log.Fatal("не реализовано: следующий шаг — internal/forward (CONNECT-туннель)")
}
