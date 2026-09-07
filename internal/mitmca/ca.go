// Package mitmca — собственный корневой центр сертификации и выпуск
// сертификатов доменов на лету.
//
// Имя CA намеренно устроено так, чтобы админ, открывший хранилище
// сертификатов, сразу понял три вещи: что это Fairway, что центр локальный
// (а не настоящий удостоверяющий) и на какой машине он выпущен. Мимикрия под
// реальные CA недопустима — она превращает инструмент в вредоносный.
package mitmca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// Organization — поле O в сертификатах.
	Organization = "Fairway Proxy"
	// caCommonNamePrefix — начало CN корневого сертификата.
	caCommonNamePrefix = "Fairway Local Root CA"

	// caValidity — срок жизни корневого сертификата. Пять лет: раскатка по
	// машинам сети дело небыстрое, чаще этого перевыпускать никто не станет.
	caValidity = 5 * 365 * 24 * time.Hour
	// leafValidity — срок жизни сертификата домена. Короткий намеренно:
	// такие сертификаты выпускаются на лету и живут в памяти.
	leafValidity = 90 * 24 * time.Hour
	// clockSkew — насколько сертификат «начинается в прошлом», чтобы
	// расхождение часов на клиенте не ломало проверку.
	clockSkew = time.Hour
)

// CA — корневой центр и ключ, которым подписываются сертификаты доменов.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	// leafKey переиспользуется для всех выпускаемых сертификатов: генерация
	// ключа на каждый домен добавляла бы задержку в рукопожатие на ровном
	// месте. Так делают все MITM-прокси; ключ не покидает машину.
	leafKey *ecdsa.PrivateKey

	certPEM []byte
}

// LoadOrCreate поднимает CA из каталога, а если его там нет — создаёт.
// Файлы: fairway-ca.pem (сертификат, его и раздают) и fairway-ca.key (ключ).
func LoadOrCreate(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "fairway-ca.pem")
	keyPath := filepath.Join(dir, "fairway-ca.key")

	ca, err := load(certPath, keyPath)
	if err == nil {
		return ca, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	return create(dir, certPath, keyPath)
}

func load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: это не PEM-сертификат", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("%s: это не PEM-ключ", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, leafKey: leafKey, certPEM: certPEM}, nil
}

func create(dir, certPath, keyPath string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s (%s)", caCommonNamePrefix, host),
			Organization: []string{Organization},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	// Ключ CA — самое ценное, что есть у инструмента: тот, кто его получит,
	// сможет подписывать сертификаты, которым доверяет вся сеть.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, leafKey: leafKey, certPEM: certPEM}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// CertPEM — корневой сертификат в PEM. Именно этот файл раскатывается
// по машинам сети и импортируется в «Доверенные корневые центры».
func (c *CA) CertPEM() []byte { return c.certPEM }

// Subject — как центр выглядит в хранилище сертификатов.
func (c *CA) Subject() string { return c.cert.Subject.String() }

// NotAfter — до какого момента действует корневой сертификат.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Export сохраняет корневой сертификат в отдельный файл — для раздачи.
func (c *CA) Export(path string) error {
	return os.WriteFile(path, c.certPEM, 0o644)
}
