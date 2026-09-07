package mitmca

import (
	"container/list"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// maxCachedCerts — предел кэша выпущенных сертификатов. Выпуск на ECDSA
// занимает доли миллисекунды, но повторять его на каждое рукопожатие незачем.
const maxCachedCerts = 2048

// Issuer выпускает сертификаты доменов, подписанные корневым CA, и держит
// их в LRU-кэше.
type Issuer struct {
	ca *CA

	mu    sync.Mutex
	cache map[string]*list.Element
	order *list.List // фронт — самые свежие
}

type cacheEntry struct {
	host string
	cert *tls.Certificate
}

// NewIssuer создаёт выпускающий центр поверх корневого CA.
func NewIssuer(ca *CA) *Issuer {
	return &Issuer{
		ca:    ca,
		cache: make(map[string]*list.Element, 64),
		order: list.New(),
	}
}

// ServerConfig — TLS-конфигурация для разговора с клиентом от имени домена.
//
// Сертификат подбирается по SNI, а если клиент его не прислал — по хосту из
// CONNECT. ALPN ограничен http/1.1: HTTP/2 клиенту предлагать нельзя, иначе
// он начнёт слать бинарные фреймы, а разбирается здесь только HTTP/1.x.
func (i *Issuer) ServerConfig(fallbackHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = fallbackHost
			}
			return i.Certificate(host)
		},
	}
}

// Certificate отдаёт сертификат для домена, выпуская его при необходимости.
func (i *Issuer) Certificate(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("пустое имя хоста")
	}

	i.mu.Lock()
	if el, ok := i.cache[host]; ok {
		entry := el.Value.(*cacheEntry)
		// Просроченный сертификат нельзя переиспользовать: клиент его отвергнет.
		if entry.cert.Leaf == nil || time.Now().Before(entry.cert.Leaf.NotAfter) {
			i.order.MoveToFront(el)
			i.mu.Unlock()
			return entry.cert, nil
		}
		i.removeLocked(el)
	}
	i.mu.Unlock()

	cert, err := i.issue(host)
	if err != nil {
		return nil, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	// Пока выпускали, сертификат мог появиться в соседней горутине.
	if el, ok := i.cache[host]; ok {
		i.order.MoveToFront(el)
		return el.Value.(*cacheEntry).cert, nil
	}
	el := i.order.PushFront(&cacheEntry{host: host, cert: cert})
	i.cache[host] = el
	for i.order.Len() > maxCachedCerts {
		i.removeLocked(i.order.Back())
	}
	return cert, nil
}

func (i *Issuer) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	i.order.Remove(el)
	delete(i.cache, el.Value.(*cacheEntry).host)
}

func (i *Issuer) issue(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{Organization},
		},
		NotBefore:   now.Add(-clockSkew),
		NotAfter:    now.Add(leafValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// SAN обязателен: браузеры давно не смотрят на CommonName.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.ca.cert, &i.ca.leafKey.PublicKey, i.ca.key)
	if err != nil {
		return nil, fmt.Errorf("выпуск сертификата для %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, i.ca.cert.Raw},
		PrivateKey:  i.ca.leafKey,
		Leaf:        leaf,
	}, nil
}

// CachedCount — сколько сертификатов сейчас в кэше (для админки).
func (i *Issuer) CachedCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.order.Len()
}

// normalizeHost приводит имя к виду, пригодному для сертификата.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}
