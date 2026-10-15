package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kyaring/sws-vault/internal/provider"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) verifySecret(q SecretRequest, baseURL string) error {
	method, target, e := provider.Verification(q.Provider, baseURL)
	if e != nil {
		return e
	}
	if q.Provider == "generic" {
		target = strings.TrimSpace(baseURL)
		method = http.MethodGet
		if target == "" {
			return errors.New("verification URL required")
		}
	}
	u, e := url.Parse(target)
	if e != nil || u.Host == "" {
		return errors.New("invalid verification URL")
	}
	hosts := q.Bindings.Hosts
	if len(hosts) == 0 {
		hosts = provider.DefaultHosts(q.Provider)
	}
	if len(hosts) == 0 {
		return errors.New("explicit host binding required")
	}
	matched := boundHost(u, hosts)
	if !matched {
		return errors.New("verification host is not bound")
	}
	headers, e := provider.Build(q.Provider, q.Value, q.Username, q.Bindings.Headers)
	if e != nil {
		return e
	}
	resp, e := (s.FetchEngine).Do(context.Background(), target, method, hosts, q.Bindings.AllowPrivate, q.Bindings.AllowHTTP, nil, headers, nil, q.Value)
	if e != nil {
		return errors.New("provider verification request rejected")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider verification failed: HTTP %d", resp.StatusCode)
	}
	if q.Provider == "cloudflare-token" {
		var result struct {
			Success bool `json:"success"`
		}
		if json.Unmarshal([]byte(resp.Body), &result) != nil || !result.Success {
			return errors.New("provider verification failed: invalid response")
		}
	}
	return nil
}

func boundHost(u *url.URL, hosts []string) bool {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	for _, raw := range hosts {
		h := strings.ToLower(strings.TrimSpace(raw))
		if h == "" {
			continue
		}
		if strings.Contains(h, ":") {
			if strings.EqualFold(h, u.Host) {
				return true
			}
			continue
		}
		if h == host && (port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80")) {
			return true
		}
	}
	return false
}
