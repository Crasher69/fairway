package mitmca

import (
	"crypto/sha1"
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
// Второе: всё делается через штатные утилиты ОС (certutil, security).
// Лезть в системные хранилища самостоятельно — верный способ оставить машину
// в неконсистентном состоянии.

// TrustState — что известно о сертификате в хранилище системы.
type TrustState struct {
	Supported bool `json:"supported"`
	Installed bool `json:"installed"`
	// Scope — где именно нашёлся: у пользователя или на всю машину.
	Scope string `json:"scope,omitempty"`
	// Fingerprint — SHA-256, его показывают человеку.
	Fingerprint string `json:"fingerprint"`
	// Thumbprint — SHA-1. Windows опознаёт сертификаты только по нему,
	// SHA-256 в certutil не работает совсем.
	Thumbprint string `json:"thumbprint"`
	Store      string `json:"store"`
	Hint       string `json:"hint,omitempty"`
}

// Fingerprint — SHA-256 отпечаток в верхнем регистре: то, что видит человек
// и что показывают современные просмотрщики сертификатов.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Thumbprint — SHA-1 отпечаток. Нужен не ради безопасности, а потому что
// хранилище Windows адресует сертификаты именно им: certutil с SHA-256
// молча не находит ничего.
func (c *CA) Thumbprint() string {
	sum := sha1.Sum(c.cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// TrustStatus сообщает, стоит ли наш CA в доверенных.
func (c *CA) TrustStatus() TrustState {
	state := TrustState{Fingerprint: c.Fingerprint(), Thumbprint: c.Thumbprint()}
	switch runtime.GOOS {
	case "windows":
		state.Supported = true
		state.Store = "Доверенные корневые центры сертификации"
		// Смотрим оба хранилища: сертификат мог поставить кто-то руками,
		// и «не установлен» при живом сертификате в машинном хранилище —
		// худшее, что панель может сообщить.
		switch {
		case windowsHasCert(c.Thumbprint(), true):
			state.Installed, state.Scope = true, "текущий пользователь"
		case windowsHasCert(c.Thumbprint(), false):
			state.Installed, state.Scope = true, "вся машина"
			state.Hint = "Сертификат стоит в машинном хранилище — удалить его отсюда " +
				"нельзя, нужны права администратора."
		}
	case "darwin":
		state.Supported = true
		state.Store = "Связка ключей «Вход»"
		if darwinHasCert(c.Fingerprint()) {
			state.Installed, state.Scope = true, "текущий пользователь"
		}
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
		if !windowsHasCert(c.Thumbprint(), true) && windowsHasCert(c.Thumbprint(), false) {
			return fmt.Errorf("сертификат стоит в машинном хранилище: удалите его из " +
				"оснастки certmgr с правами администратора")
		}
		return run("certutil", "-user", "-delstore", "Root", c.Thumbprint())
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

// windowsHasCert ищет сертификат по SHA-1 в пользовательском или машинном
// хранилище.
//
// Именно -store, а не -verifystore: второй помимо поиска строит и проверяет
// цепочку, в том числе пробует узнать статус отзыва. У приватного CA нет ни
// CRL, ни OCSP, поэтому проверка падает — и установленный сертификат
// выглядел бы отсутствующим.
func windowsHasCert(thumbprint string, userStore bool) bool {
	args := []string{}
	if userStore {
		args = append(args, "-user")
	}
	args = append(args, "-store", "Root", thumbprint)
	return exec.Command("certutil", args...).Run() == nil
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
