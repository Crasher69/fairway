package mitmca

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateAndReload(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "fairway-ca.pem")
	keyPath := filepath.Join(dir, "fairway-ca.key")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("не создан %s: %v", p, err)
		}
	}

	// Повторный запуск обязан взять тот же сертификат: иначе после каждого
	// рестарта пришлось бы заново раскатывать CA по всем машинам сети.
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.CertPEM()) != string(second.CertPEM()) {
		t.Error("при повторном запуске выпущен новый корневой сертификат")
	}
}

func TestCASubjectIsHonest(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	subject := ca.Subject()
	if !strings.Contains(subject, "Fairway") {
		t.Errorf("в имени CA нет названия продукта: %s", subject)
	}
	// «Local» в имени — чтобы админ в хранилище сразу видел, что центр
	// локальный, а не настоящий удостоверяющий.
	if !strings.Contains(strings.ToLower(subject), "local") {
		t.Errorf("имя CA не сообщает, что центр локальный: %s", subject)
	}
	host, _ := os.Hostname()
	if host != "" && !strings.Contains(subject, host) {
		t.Errorf("в имени CA нет машины выпуска (%s): %s", host, subject)
	}
}

func TestCAIsUsableAsAuthority(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.IsCA {
		t.Error("сертификат не помечен как CA")
	}
	if ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("у CA нет права подписывать сертификаты")
	}
	if ca.cert.MaxPathLen != 0 || !ca.cert.MaxPathLenZero {
		t.Error("CA должен запрещать промежуточные центры (MaxPathLen 0)")
	}
	if got := time.Until(ca.NotAfter()); got < 4*365*24*time.Hour {
		t.Errorf("срок жизни CA всего %s — раскатывать такой по сети бессмысленно", got)
	}
}

func TestIssueLeafChainsToCA(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	issuer := NewIssuer(ca)

	cert, err := issuer.Certificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("выпущенный сертификат без разобранного Leaf")
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("корневой сертификат не разобрался из PEM")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   roots,
	}); err != nil {
		t.Errorf("выпущенный сертификат не проходит проверку по нашему CA: %v", err)
	}

	// SAN обязателен: браузеры на CommonName давно не смотрят.
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("SAN некорректен: %v", leaf.DNSNames)
	}
	if len(cert.Certificate) != 2 {
		t.Errorf("клиенту отдаётся %d сертификата, ожидалась цепочка из листа и CA", len(cert.Certificate))
	}
}

func TestIssueForIPAddress(t *testing.T) {
	ca, _ := LoadOrCreate(t.TempDir())
	issuer := NewIssuer(ca)

	cert, err := issuer.Certificate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("для IP ожидался IP SAN, получено DNS=%v IP=%v", cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
	}
}

func TestCertificateCache(t *testing.T) {
	ca, _ := LoadOrCreate(t.TempDir())
	issuer := NewIssuer(ca)

	first, err := issuer.Certificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Регистр, порт и точка в конце — это тот же домен, а не три разных.
	for _, host := range []string{"EXAMPLE.COM", "example.com:443", "example.com."} {
		again, err := issuer.Certificate(host)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Errorf("для %q выпущен новый сертификат вместо кэшированного", host)
		}
	}
	if got := issuer.CachedCount(); got != 1 {
		t.Errorf("в кэше %d записей, ожидалась 1", got)
	}
}

func TestCacheEviction(t *testing.T) {
	ca, _ := LoadOrCreate(t.TempDir())
	issuer := NewIssuer(ca)

	for i := 0; i < maxCachedCerts+50; i++ {
		if _, err := issuer.Certificate(hostN(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := issuer.CachedCount(); got != maxCachedCerts {
		t.Errorf("кэш вырос до %d, предел %d", got, maxCachedCerts)
	}
}

func hostN(i int) string {
	return "host-" + strings.Repeat("x", i%3) + itoa(i) + ".example.com"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
