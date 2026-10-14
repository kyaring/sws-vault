package api

import (
	"net"
	"net/http"
	"strings"
)

func (s *Server) sourceIP(r *http.Request) string {
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
