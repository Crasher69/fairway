package rating

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"fairway/internal/i18n"
)

// causeLimit — длиннее причина в таблице панели не читается.
const causeLimit = 80

// failureCause — короткая причина неудачи для строки бана: «соединение
// отклонено», а не «connecting to proxy 127.0.0.1:18099: dial tcp …:
// connectex: No connection could be made because the target machine
// actively refused it.». Полный текст остаётся в живом логе; в причине
// бана человеку нужна суть, одинаковая на любой ОС.
func failureCause(err error) string {
	if err == nil {
		return i18n.T("connection error")
	}
	var (
		dnsErr  *net.DNSError
		certErr *tls.CertificateVerificationError
		unknown x509.UnknownAuthorityError
		hostErr x509.HostnameError
		recErr  tls.RecordHeaderError
		timeout interface{ Timeout() bool }
	)
	switch {
	case errors.As(err, &dnsErr):
		return i18n.T("host not found")
	case errors.Is(err, syscall.ECONNREFUSED) || containsFold(err, "refused"):
		// На Windows отказ приходит как WSAECONNREFUSED, а не
		// ECONNREFUSED, — отсюда проверка по тексту.
		return i18n.T("connection refused")
	case errors.Is(err, syscall.ECONNRESET) || containsFold(err, "reset by peer") || containsFold(err, "forcibly closed"):
		return i18n.T("connection reset")
	case errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &timeout) && timeout.Timeout():
		return i18n.T("no reply (timeout)")
	case errors.As(err, &certErr) || errors.As(err, &unknown) || errors.As(err, &hostErr) || errors.As(err, &recErr):
		return i18n.T("TLS error")
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return i18n.T("connection closed before a reply")
	}
	// Незнакомая ошибка: последнее звено цепочки «контекст: причина» —
	// самое конкретное, остальное — где это случилось.
	text := err.Error()
	if i := strings.LastIndex(text, ": "); i >= 0 {
		text = text[i+2:]
	}
	return truncate(text, causeLimit)
}

func containsFold(err error, part string) bool {
	return strings.Contains(strings.ToLower(err.Error()), part)
}

// truncate обрезает по границе символа: причина бывает и по-русски.
func truncate(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[:limit-1]) + "…"
}
