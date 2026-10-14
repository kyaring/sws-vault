package provider

import (
	"errors"
	"net/http"
	"strings"
)

var defaults = map[string][]string{"cloudflare-token": {"api.cloudflare.com"}, "cloudflare-global-key": {"api.cloudflare.com"}, "github-pat": {"api.github.com"}}

func DefaultHosts(name string) []string { v := defaults[name]; return append([]string(nil), v...) }
func Build(name, value, username string, custom map[string]string) (http.Header, error) {
	h := http.Header{}
	switch name {
	case "cloudflare-token", "github-pat":
		h.Set("Authorization", "Bearer "+value)
	case "cloudflare-global-key":
		if strings.TrimSpace(username) == "" {
			return nil, errors.New("username required")
		}
		h.Set("X-Auth-Email", username)
		h.Set("X-Auth-Key", value)
	case "gitea-token":
		h.Set("Authorization", "token "+value)
	case "generic":
		if len(custom) == 0 {
			return nil, errors.New("generic header template required")
		}
		for k, v := range custom {
			if strings.TrimSpace(k) == "" || strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
				return nil, errors.New("invalid header template")
			}
			v = strings.ReplaceAll(v, "{v}", value)
			v = strings.ReplaceAll(v, "{username}", username)
			if strings.ContainsAny(v, "{}") {
				return nil, errors.New("unsupported header placeholder")
			}
			h.Set(k, v)
		}
	default:
		return nil, errors.New("unknown provider")
	}
	return h, nil
}
func Verification(name, baseURL string) (string, string, error) {
	switch name {
	case "cloudflare-token":
		return "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", nil
	case "cloudflare-global-key":
		return "GET", "https://api.cloudflare.com/client/v4/user", nil
	case "github-pat":
		return "GET", "https://api.github.com/user", nil
	case "gitea-token":
		if !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://") {
			return "", "", errors.New("gitea base URL required")
		}
		return "GET", strings.TrimRight(baseURL, "/") + "/api/v1/user", nil
	case "generic":
		return "", "", nil
	default:
		return "", "", errors.New("unknown provider")
	}
}
