package config

import (
	"fmt"
	"strconv"
	"strings"

	"fairway/internal/i18n"
)

// ParseProxyLine разбирает одну строку из списка прокси.
//
// Поставщики выдают списки в разных видах, и все они здесь поддержаны:
//
//	socks5://user:pass@1.2.3.4:1080   строка подключения целиком
//	1.2.3.4:1080:user:pass            самый ходовой формат прайсов
//	user:pass@1.2.3.4:1080            встречается не реже
//	1.2.3.4:1080                      без авторизации
//
// Схема в строке важнее переданной по умолчанию: если человек прислал
// socks5://, значит он знает, что это socks5.
func ParseProxyLine(line, defaultScheme string) (Proxy, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Proxy{}, i18n.Errorf("empty line")
	}

	scheme := defaultScheme
	if scheme == "" {
		scheme = "http"
	}
	if index := strings.Index(line, "://"); index >= 0 {
		scheme = line[:index]
		line = line[index+3:]
	}

	var login, password string
	if at := strings.LastIndex(line, "@"); at >= 0 {
		login, password, _ = strings.Cut(line[:at], ":")
		line = line[at+1:]
	}

	parts := strings.Split(line, ":")
	switch len(parts) {
	case 2:
		// host:port
	case 4:
		// host:port:login:pass — только если креды не пришли через @
		if login != "" {
			return Proxy{}, i18n.Errorf("login given twice")
		}
		login, password = parts[2], parts[3]
		parts = parts[:2]
	default:
		return Proxy{}, i18n.Errorf("cannot parse: expected host:port, host:port:login:password or a URL with a scheme")
	}

	host := strings.TrimSpace(parts[0])
	if host == "" {
		return Proxy{}, i18n.Errorf("no address")
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return Proxy{}, i18n.Errorf("port %q: not a number", parts[1])
	}
	if port <= 0 || port > 65535 {
		return Proxy{}, i18n.Errorf("port %d out of range", port)
	}

	return Proxy{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Login:    login,
		Password: password,
	}, nil
}

// ImportResult — что получилось из списка. Ошибки по строкам возвращаются
// целиком: человек должен увидеть, какая именно строка не разобралась,
// а не «импортировано 47 из 50».
type ImportResult struct {
	Added    []Proxy       `json:"added"`
	Skipped  []ImportIssue `json:"skipped"`
	Failed   []ImportIssue `json:"failed"`
	AddedN   int           `json:"added_count"`
	SkippedN int           `json:"skipped_count"`
	FailedN  int           `json:"failed_count"`
}

// ImportIssue — строка, которая не попала в конфиг, и почему.
type ImportIssue struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// ImportProxies разбирает список и добавляет прокси в конфиг.
//
// Имена присваиваются сами: набивать полсотни имён руками никто не станет.
// Дубликаты по адресу пропускаются, а не заменяются: повторная вставка того
// же списка не должна ничего ломать.
func (c *Config) ImportProxies(text, scheme, prefix, country, comment string) ImportResult {
	if prefix == "" {
		prefix = "proxy"
	}
	taken := make(map[string]bool, len(c.Proxies))
	addresses := make(map[string]bool, len(c.Proxies))
	for _, p := range c.Proxies {
		taken[p.Name] = true
		addresses[fmt.Sprintf("%s:%d", p.Host, p.Port)] = true
	}

	var result ImportResult
	counter := 0
	for number, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		issue := ImportIssue{Line: number + 1, Text: trimmed}

		proxy, err := ParseProxyLine(trimmed, scheme)
		if err != nil {
			issue.Reason = err.Error()
			result.Failed = append(result.Failed, issue)
			continue
		}
		address := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
		if addresses[address] {
			issue.Reason = i18n.T("this address already exists")
			result.Skipped = append(result.Skipped, issue)
			continue
		}

		// Имя ищем свободное: в конфиге уже могут быть proxy-1 и proxy-2.
		for {
			counter++
			candidate := fmt.Sprintf("%s-%d", prefix, counter)
			if !taken[candidate] {
				proxy.Name = candidate
				taken[candidate] = true
				break
			}
		}
		proxy.Country = country
		proxy.Comment = comment

		addresses[address] = true
		c.Proxies = append(c.Proxies, proxy)
		result.Added = append(result.Added, proxy)
	}

	result.AddedN = len(result.Added)
	result.SkippedN = len(result.Skipped)
	result.FailedN = len(result.Failed)
	return result
}
