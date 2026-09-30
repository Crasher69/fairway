package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fairway/internal/i18n"
)

// Файлы пакета плагина: каталог <каталог плагинов>/<имя>/ с ними внутри.
const (
	ManifestFile = "manifest.json"
	ModuleFile   = "plugin.wasm"
)

// Permission — право, которое плагин просит в манифесте. Без выданного
// права хост отвечает на соответствующий вызов ошибкой.
type Permission string

const (
	// ConfigRead — читать прокси, листы, домены и умолчания. Пароль панели
	// и вход на прокси плагину не отдаются никогда.
	ConfigRead Permission = "config.read"
	// ConfigWrite — менять прокси, листы и домены.
	ConfigWrite Permission = "config.write"
	// Events — получать события шины (config.applied, proxy.banned).
	Events Permission = "events"
	// Schedule — вызываться по таймеру.
	Schedule Permission = "schedule"
	// HTTPFetch — ходить по HTTP на хосты из http_hosts манифеста.
	HTTPFetch Permission = "http.fetch"
)

var knownPermissions = map[Permission]bool{
	ConfigRead: true, ConfigWrite: true, Events: true, Schedule: true, HTTPFetch: true,
}

// Kind — вид плагина. Пока есть только base; hook (обработка запросов)
// появится отдельно.
type Kind string

const KindBase Kind = "base"

// Manifest — описание плагина из manifest.json.
type Manifest struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Kind        Kind         `json:"kind"`
	Permissions []Permission `json:"permissions,omitempty"`
	// HTTPHosts — куда плагину можно ходить с http.fetch: "api.example.com"
	// или "*.example.com" (поддомены, но не сам example.com).
	HTTPHosts []string `json:"http_hosts,omitempty"`
	// SettingsSchema — JSON Schema настроек, по ней панель рисует форму.
	// Хост её не разбирает, только передаёт.
	SettingsSchema json.RawMessage `json:"settings_schema,omitempty"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// LoadManifest читает и проверяет манифест из каталога плагина. Имя в
// манифесте обязано совпадать с именем каталога: по имени плагин ищется
// в конфиге, и расхождение запутало бы, какие настройки чьи.
func LoadManifest(dir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if base := filepath.Base(dir); m.Name != base {
		return nil, i18n.Errorf("manifest name %q does not match directory %q", m.Name, base)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if !namePattern.MatchString(m.Name) {
		return i18n.Errorf("manifest: name %q must be lowercase letters, digits, '-' or '_'", m.Name)
	}
	if m.Version == "" {
		return i18n.Errorf("manifest: empty version")
	}
	if m.Kind != KindBase {
		return i18n.Errorf("manifest: kind %q is not supported (only %q for now)", m.Kind, KindBase)
	}
	for _, p := range m.Permissions {
		if !knownPermissions[p] {
			return i18n.Errorf("manifest: unknown permission %q", p)
		}
	}
	if len(m.HTTPHosts) > 0 && !m.Has(HTTPFetch) {
		return i18n.Errorf("manifest: http_hosts given without the %q permission", HTTPFetch)
	}
	for _, h := range m.HTTPHosts {
		bare := strings.TrimPrefix(h, "*.")
		if bare == "" || strings.ContainsAny(bare, "*/:") {
			return i18n.Errorf("manifest: http_hosts: %q is not a host name", h)
		}
	}
	return nil
}

// Has сообщает, просит ли плагин право.
func (m *Manifest) Has(p Permission) bool {
	for _, q := range m.Permissions {
		if q == p {
			return true
		}
	}
	return false
}

// Missing — права из манифеста, которых нет среди выданных.
func (m *Manifest) Missing(granted []string) []Permission {
	have := make(map[string]bool, len(granted))
	for _, g := range granted {
		have[g] = true
	}
	var missing []Permission
	for _, p := range m.Permissions {
		if !have[string(p)] {
			missing = append(missing, p)
		}
	}
	return missing
}

// AllowsHost сообщает, можно ли плагину ходить на этот хост.
func (m *Manifest) AllowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range m.HTTPHosts {
		h = strings.ToLower(h)
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}
