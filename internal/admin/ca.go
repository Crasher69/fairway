package admin

import (
	"net/http"
	"time"

	"fairway/internal/i18n"
	"fairway/internal/mitmca"
)

type caResponse struct {
	Subject     string            `json:"subject"`
	NotAfter    time.Time         `json:"not_after"`
	Fingerprint string            `json:"fingerprint"`
	Trust       mitmca.TrustState `json:"trust"`
}

func (s *Server) caInfo(w http.ResponseWriter, r *http.Request) {
	if s.CA == nil {
		http.Error(w, i18n.T("root certificate is unavailable"), http.StatusNotFound)
		return
	}
	writeJSON(w, caResponse{
		Subject:     s.CA.Subject(),
		NotAfter:    s.CA.NotAfter(),
		Fingerprint: s.CA.Fingerprint(),
		Trust:       s.CA.TrustStatus(),
	})
}

// caInstall ставит корневой сертификат в доверенные текущего пользователя.
//
// Ручка мощная: после неё машина верит всему, что подписано нашим ключом.
// Защищает её то же, что и остальную панель — loopback и токен. Ставим
// только в пользовательское хранилище, права администратора не нужны.
func (s *Server) caInstall(w http.ResponseWriter, r *http.Request) {
	if s.CA == nil {
		http.Error(w, i18n.T("root certificate is unavailable"), http.StatusNotFound)
		return
	}
	if err := s.CA.Install(); err != nil {
		http.Error(w, i18n.T("install failed: ")+err.Error(), http.StatusInternalServerError)
		return
	}
	s.caInfo(w, r)
}

func (s *Server) caUninstall(w http.ResponseWriter, r *http.Request) {
	if s.CA == nil {
		http.Error(w, i18n.T("root certificate is unavailable"), http.StatusNotFound)
		return
	}
	if err := s.CA.Uninstall(); err != nil {
		http.Error(w, i18n.T("uninstall failed: ")+err.Error(), http.StatusInternalServerError)
		return
	}
	s.caInfo(w, r)
}
