package mitmca

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Установка корневого сертификата в доверенные — операция с серьёзными
// последствиями: после неё машина верит всему, что подписано этим ключом.
// Поэтому здесь два правила.
//
// Первое: ставим только в пользовательское хранилище, а не в машинное. Прав
// администратора не нужно, и затронут только текущий пользователь.
//
// Второе: всё делается через штатные утилиты ОС (certutil, security,
// update-ca-certificates). Лезть в системные хранилища самостоятельно — верный
// способ оставить машину в неконсистентном состоянии.

// TrustState — что известно о сертификате в хранилище системы.
type TrustState struct {
	Supported   bool   `json:"supported"`
	Installed   bool   `json:"installed"`
	Fingerprint string `json:"fingerprint"`
	Store       string `json:"store"`
	Hint        string `json:"hint,omitempty"`
}

// Fingerprint — SHA-256 отпечаток корневого сертификата в верхнем регистре.
// По нему сертификат ищется в хранилище и по нему же его сверяет человек.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// TrustStatus сообщает, стоит ли наш CA в доверенных у текущего пользователя.
func (c *CA) TrustStatus() TrustState {
	state := TrustState{Fingerprint: c.Fingerprint()}
	switch runtime.GOOS {
	case "windows":
		state.Supported = true
		state.Store = "Доверенные корневые центры сертификации (текущий пользователь)"
		state.Installed = windowsHasCert(c.Fingerprint())
	case "darwin":
		state.Supported = true
		state.Store = "Связка ключей «Вход»"
		state.Installed = darwinHasCert(c.Fingerprint())
	default:
		state.Store = "системное хранилище"
		state.Hint = "На Linux установка зависит от дистрибутива и требует прав root: " +
			"скопируйте fairway-ca.pem в /usr/local/share/ca-certificates/fairway.crt " +
			"и выполните update-ca-certificates."
	}
	return state
}

// Install добавляет корневой сертификат в доверенные текущего пользователя.
func (c *CA) Install() error {
	path, cleanup, err := c.tempCert()
	if err != nil {
		return err
	}
	defer cleanup()

	switch runtime.GOOS {
	case "windows":
		// -user: пользовательское хранилище, права администратора не нужны.
		return run("certutil", "-user", "-addstore", "-f", "Root", path)
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		return run("security", "add-trusted-cert", "-r", "trustRoot",
			"-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"), path)
	default:
		return fmt.Errorf("автоматическая установка на %s не поддерживается", runtime.GOOS)
	}
}

// Uninstall убирает сертификат из доверенных. Нужен не меньше установки:
// оставлять в системе живой корневой сертификат после того, как инструмент
// больше не используется, — плохая гигиена.
func (c *CA) Uninstall() error {
	switch runtime.GOOS {
	case "windows":
		return run("certutil", "-user", "-delstore", "Root", c.Fingerprint())
	case "darwin":
		path, cleanup, err := c.tempCert()
		if err != nil {
			return err
		}
		defer cleanup()
		return run("security", "remove-trusted-cert", path)
	default:
		return fmt.Errorf("автоматическое удаление на %s не поддерживается", runtime.GOOS)
	}
}

// tempCert кладёт сертификат во временный файл: утилитам ОС нужен путь.
func (c *CA) tempCert() (string, func(), error) {
	file, err := os.CreateTemp("", "fairway-ca-*.crt")
	if err != nil {
		return "", nil, err
	}
	if _, err := file.Write(c.certPEM); err != nil {
		file.Close()
		os.Remove(file.Name())
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		os.Remove(file.Name())
		return "", nil, err
	}
	return file.Name(), func() { os.Remove(file.Name()) }, nil
}

func windowsHasCert(fingerprint string) bool {
	// certutil ищет по отпечатку и возвращает ненулевой код, если не нашёл.
	return exec.Command("certutil", "-user", "-verifystore", "Root", fingerprint).Run() == nil
}

func darwinHasCert(fingerprint string) bool {
	out, err := exec.Command("security", "find-certificate", "-a", "-Z").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), fingerprint)
}

// run выполняет команду и возвращает её вывод в тексте ошибки: без него
// «exit status 1» ничего не объясняет.
func run(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			return fmt.Errorf("%s: %w", name, err)
		}
		return fmt.Errorf("%s: %w: %s", name, err, text)
	}
	return nil
}
