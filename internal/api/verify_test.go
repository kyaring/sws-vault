package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/kyaring/sws-vault/internal/fetch"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type publicResolver struct{}

func (publicResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}
func TestProviderVerificationTemplatesOverTestServer(t *testing.T) {
	sentinel := "SENTINEL-VALUE-7f3a9c"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/v4/user/tokens/verify":
			if r.Header.Get("Authorization") != "Bearer "+sentinel {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/client/v4/user":
			if r.Header.Get("X-Auth-Email") != "fake@example.invalid" || r.Header.Get("X-Auth-Key") != sentinel {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/user":
			if r.Header.Get("Authorization") != "Bearer "+sentinel {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(200)
		case "/api/v1/user":
			if r.Header.Get("Authorization") != "token "+sentinel {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	engine := fetch.Engine{Resolver: publicResolver{}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}}
	s := &Server{FetchEngine: engine}
	tests := []struct {
		name, base string
		q          SecretRequest
	}{{name: "cloudflare-token", q: SecretRequest{Provider: "cloudflare-token", Type: "token", Value: sentinel}}, {name: "cloudflare-global-key", q: SecretRequest{Provider: "cloudflare-global-key", Type: "login", Username: "fake@example.invalid", Value: sentinel}}, {name: "github-pat", q: SecretRequest{Provider: "github-pat", Type: "token", Value: sentinel}}, {name: "gitea-token", base: "https://gitea.example.invalid", q: SecretRequest{Provider: "gitea-token", Type: "token", Value: sentinel, Bindings: Binding{Hosts: []string{"gitea.example.invalid"}}}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if e := s.verifySecret(tt.q, tt.base); e != nil {
				t.Fatalf("verification failed: %v", e)
			}
		})
	}
}
