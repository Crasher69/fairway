// Command benchtarget — цель для нагрузочного теста: отдаёт тело заданного
// размера по HTTP или HTTPS с самоподписанным сертификатом. Вместе с
// cmd/loadgen и самим fairway в режиме direct составляет стенд, который
// собирается из одного репозитория без сторонних утилит (см. docs/BENCHMARK.md).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19005", "listen address")
	size := flag.Int("size", 20000, "response body size, bytes")
	useTLS := flag.Bool("tls", false, "serve HTTPS with a self-signed certificate")
	flag.Parse()

	body := []byte(strings.Repeat("x", *size))
	srv := &http.Server{
		Addr: *addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(body)
		}),
	}
	if !*useTLS {
		log.Printf("http target on %s, %d bytes per response", *addr, *size)
		log.Fatal(srv.ListenAndServe())
	}

	// Самоподписанный сертификат на 127.0.0.1: клиенту достаточно -insecure,
	// а fairway в режиме MITM — флага -insecure-origin.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "benchtarget"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	log.Printf("https target on %s, %d bytes per response", *addr, *size)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
