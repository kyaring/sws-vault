package api

import (
	"errors"
	"github.com/kyaring/sws-vault/internal/provider"
	"net/url"
	"strconv"
	"strings"
)

func validHostBinding(h string) bool {
	if h == "" || strings.ContainsAny(h, " \t\r\n/@\\") || strings.Contains(h, "%") {
		return false
	}
	u, err := url.Parse("https://" + h)
	if err != nil || u.Host != h || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

func validateSecret(q SecretRequest) error {
	if !namePattern.MatchString(q.NS) || strings.TrimSpace(q.Label) == "" || len(q.Label) > 128 || q.Value == "" || len(q.Value) > 1<<20 {
		return errors.New("invalid secret fields")
	}
	types := map[string]bool{"login": true, "api_key": true, "token": true, "webhook": true, "ssh_key": true, "note": true}
	if !types[q.Type] {
		return errors.New("invalid secret type")
	}
	providers := map[string]bool{"cloudflare-token": true, "cloudflare-global-key": true, "github-pat": true, "gitea-token": true, "generic": true}
	if !providers[q.Provider] {
		return errors.New("invalid provider")
	}
	if q.Provider == "cloudflare-global-key" && (q.Type != "login" || strings.TrimSpace(q.Username) == "") {
		return errors.New("global key requires login username")
	}
	if q.Provider == "generic" && len(q.Bindings.Headers) > 0 {
		if _, e := provider.Build(q.Provider, q.Value, q.Username, q.Bindings.Headers); e != nil {
			return e
		}
	}
	for _, h := range q.Bindings.Hosts {
		if !validHostBinding(strings.TrimSpace(h)) {
			return errors.New("invalid host binding")
		}
	}
	return nil
}
