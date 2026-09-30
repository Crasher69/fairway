package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"fairway/internal/config"
	"fairway/internal/i18n"
	"fairway/internal/plugin"
)

// pluginView — плагин для панели: что о нём знает менеджер плюс его
// запись в конфиге (выданные права и настройки — их правят формы).
type pluginView struct {
	plugin.Status
	Granted  []string        `json:"granted"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type pluginsResponse struct {
	Dir     string       `json:"dir"`
	Plugins []pluginView `json:"plugins"`
}

func (s *Server) pluginViews() pluginsResponse {
	resp := pluginsResponse{Plugins: []pluginView{}}
	if s.Plugins == nil {
		return resp
	}
	resp.Dir = s.Plugins.Dir
	entries := map[string]config.Plugin{}
	for _, p := range s.Config().Plugins {
		entries[p.Name] = p
	}
	for _, st := range s.Plugins.Plugins() {
		entry := entries[st.Name]
		resp.Plugins = append(resp.Plugins, pluginView{
			Status:   st,
			Granted:  append([]string{}, entry.Granted...),
			Settings: entry.Settings,
		})
	}
	return resp
}

func (s *Server) plugins(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.pluginViews())
}

// savePlugin включает и выключает плагин, выдаёт права, сохраняет
// настройки. Не переданное поле не меняется. Плагин подхватит правку сам:
// менеджер сверяется с каждой применённой версией конфига.
func (s *Server) savePlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Enabled  *bool            `json:"enabled"`
		Granted  *[]string        `json:"granted"`
		Settings *json.RawMessage `json:"settings"`
	}
	if !decode(w, r, &body) {
		return
	}
	_, err := s.Editor.Edit(func(cfg *config.Config) error {
		index := -1
		for i, p := range cfg.Plugins {
			if p.Name == name {
				index = i
				break
			}
		}
		if index < 0 {
			cfg.Plugins = append(cfg.Plugins, config.Plugin{Name: name})
			index = len(cfg.Plugins) - 1
		}
		entry := &cfg.Plugins[index]
		if body.Enabled != nil {
			entry.Enabled = *body.Enabled
		}
		if body.Granted != nil {
			entry.Granted = *body.Granted
		}
		if body.Settings != nil {
			var compact bytes.Buffer
			if err := json.Compact(&compact, *body.Settings); err != nil {
				return err
			}
			entry.Settings = compact.Bytes()
			// null и {} — «настроек нет»: в файле незачем хранить пустое.
			if s := compact.String(); s == "null" || s == "{}" {
				entry.Settings = nil
			}
		}
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, config.ErrNoEditor) {
			status = http.StatusNotImplemented
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, s.pluginViews())
}

// pluginCall — вызов со страницы плагина. Страница живёт в изолированном
// iframe и сама к API не ходит: запрос за неё делает панель.
func (s *Server) pluginCall(w http.ResponseWriter, r *http.Request) {
	if s.Plugins == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Method == "" {
		http.Error(w, i18n.T("empty method"), http.StatusBadRequest)
		return
	}
	// Своя граница поверх таймаута плагина: запрос панели не должен висеть
	// дольше, чем плагин имеет право думать.
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	result, err := s.Plugins.Call(ctx, r.PathValue("name"), body.Method, body.Params)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, plugin.ErrNotRunning) {
			status = http.StatusConflict
			err = errors.New(i18n.T("plugin is not running"))
		}
		http.Error(w, err.Error(), status)
		return
	}
	if len(result) == 0 {
		result = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (s *Server) pluginLog(w http.ResponseWriter, r *http.Request) {
	lines := []plugin.LogLine{}
	if s.Plugins != nil {
		lines = append(lines, s.Plugins.Log(r.PathValue("name"))...)
	}
	writeJSON(w, lines)
}

// pluginUI отдаёт страницу плагина как текст. Именно текст: HTML плагина,
// отданный как страница с адреса панели, выполнился бы с её правами —
// с cookie входа и доступом ко всему API. Панель вставляет его в iframe
// без same-origin, где у скриптов плагина нет ни того, ни другого.
func (s *Server) pluginUI(w http.ResponseWriter, r *http.Request) {
	if s.Plugins == nil {
		http.NotFound(w, r)
		return
	}
	html, err := s.Plugins.UI(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(html)
}
