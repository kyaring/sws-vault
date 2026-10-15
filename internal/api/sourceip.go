package api

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

var untrustedForwardedWarning sync.Once

func (s *Server) warnUntrustedForwarded(r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != "" && len(s.C.TrustedProxyCIDRs) == 0 {
		untrustedForwardedWarning.Do(func() {
			slog.Warn("X-Forwarded-For received without SWSV_TRUSTED_PROXY_CIDRS; using socket peer IP")
		})
	}
}

func (s *Server) sourceIP(r *http.Request) string {
	s.warnUntrustedForwarded(r)
	peer := remoteIP(r)
	if !ipAllowed(peer, s.C.TrustedProxyCIDRs) {
		return peer
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	current := peer
	for i := len(chain) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(chain[i])
		if net.ParseIP(candidate) == nil {
			continue
		}
		current = candidate
		if !ipAllowed(candidate, s.C.TrustedProxyCIDRs) {
			return candidate
		}
	}
	return current
}
