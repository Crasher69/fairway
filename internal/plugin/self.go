package plugin

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"

	"fairway/internal/config"
)

// SelfClient — клиент для http.fetch с via_fairway: запрос идёт через прокси
// самого fairway и получает лист по правилу своего домена, как любой
// клиент. proxyAddr — адрес, который слушает прокси; auth читается на
// каждый запрос, чтобы включённый из панели вход действовал сразу. caPEM —
// корневой сертификат MITM: на домене с "mitm": true fairway отвечает своим
// сертификатом, и ему нужно доверять.
func SelfClient(proxyAddr string, auth func() config.ProxyAuth, caPEM []byte) *http.Client {
	addr := loopback(proxyAddr)
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AppendCertsFromPEM(caPEM)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(*http.Request) (*url.URL, error) {
		u := &url.URL{Scheme: "http", Host: addr}
		if a := auth(); a.Enabled && len(a.Users) > 0 {
			u.User = url.UserPassword(a.Users[0].Login, a.Users[0].Password)
		}
		return u, nil
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	return &http.Client{Transport: transport}
}

// loopback превращает адрес, который слушают на всех интерфейсах (":7770",
// "0.0.0.0:7770", "[::]:7770"), в адрес, по которому до него достучаться
// с этой же машины.
func loopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch ip := net.ParseIP(host); {
	case host == "" || (ip != nil && ip.To4() != nil && ip.IsUnspecified()):
		host = "127.0.0.1"
	case ip != nil && ip.IsUnspecified():
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}
