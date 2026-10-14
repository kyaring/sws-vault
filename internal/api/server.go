package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
	"net"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	C       config.Config
	S       *store.Store
	Master  []byte
	Keys    map[uint32][]byte
	Current uint32
	Mux     *http.ServeMux
}
type Client struct {
	ID, NS, Name, Scopes, CIDRs, Expires string
	Disabled                             int
}
type Binding struct {
	Hosts          []string          `json:"hosts"`
	Headers        map[string]string `json:"headers"`
	AllowResolve   bool              `json:"allow_resolve"`
	AllowPrivate   bool              `json:"allow_private"`
	AllowHTTP      bool              `json:"allow_http"`
	AllowedClients []string          `json:"allowed_clients"`
}
type SecretRequest struct {
	NS       string  `json:"ns"`
	Label    string  `json:"label"`
	Provider string  `json:"provider"`
	Type     string  `json:"type"`
	Value    string  `json:"value"`
	Username string  `json:"username"`
	Bindings Binding `json:"bindings"`
}
type Metadata struct {
	ID          string  `json:"id"`
	NS          string  `json:"ns"`
	Label       string  `json:"label"`
	Provider    string  `json:"provider"`
	Type        string  `json:"type"`
	Preview     string  `json:"preview"`
	Fingerprint string  `json:"fingerprint"`
	Bindings    Binding `json:"bindings"`
	CreatedAt   string  `json:"created_at"`
	RotatedAt   string  `json:"rotated_at"`
	LastUsedAt  string  `json:"last_used_at"`
	Status      string  `json:"status"`
}

func New(c config.Config, s *store.Store, key []byte) *Server {
	x := &Server{C: c, S: s, Master: key, Keys: map[uint32][]byte{1: key}, Current: 1, Mux: http.NewServeMux()}
	x.routes()
	return x
}
func NewWithKeyring(c config.Config, st *store.Store, ring *vaultcrypto.Keyring) *Server {
	x := &Server{C: c, S: st, Keys: ring.Keys, Current: ring.Current, Master: ring.Keys[ring.Current], Mux: http.NewServeMux()}
	x.routes()
	return x
}
func (s *Server) routes() {
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, map[string]string{"status": "ok"}) })
	s.Mux.HandleFunc("GET /v1/secrets", s.auth("secrets:list", s.list))
	s.Mux.HandleFunc("POST /v1/secrets", s.auth("secrets:write", s.create))
	s.Mux.HandleFunc("PUT /v1/secrets/{id}/value", s.auth("secrets:write", s.rotate))
	s.Mux.HandleFunc("POST /v1/resolve", s.auth("resolve", s.resolve))
	s.Mux.HandleFunc("POST /v1/intents", s.auth("intents:create", s.intent))
	s.Mux.HandleFunc("POST /v1/fetch", s.auth("fetch", s.fetch))
	s.Mux.HandleFunc("/mcp", s.auth("", s.mcp))
	s.Mux.HandleFunc("/admin/", s.admin)
	s.Mux.HandleFunc("GET /i/{token}", s.intentPage)
	s.Mux.HandleFunc("POST /i/{token}", s.intentSubmit)
}
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		s.Mux.ServeHTTP(w, r)
	})
}
func (s *Server) Serve() error {
	srv := &http.Server{Addr: s.C.ListenAddr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second}
	return srv.ListenAndServe()
}
func (s *Server) auth(scope string, next func(http.ResponseWriter, *http.Request, Client)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || token == r.Header.Get("Authorization") {
			errOut(w, 401, "unauthorized")
			return
		}
		h := sha256.Sum256([]byte(token))
		var c Client
		e := s.S.DB.QueryRow(`SELECT id,ns,name,scopes,cidrs,expires_at,disabled FROM clients WHERE token_hash=?`, h[:]).Scan(&c.ID, &c.NS, &c.Name, &c.Scopes, &c.CIDRs, &c.Expires, &c.Disabled)
		if e != nil || c.Disabled != 0 || (c.Expires != "" && time.Now().UTC().Format(time.RFC3339) >= c.Expires) {
			errOut(w, 401, "unauthorized")
			return
		}
		if scope != "" && !hasScope(c.Scopes, scope) {
			errOut(w, 403, "forbidden")
			return
		}
		if c.CIDRs != "" && !ipAllowed(remoteIP(r), strings.Split(c.CIDRs, ",")) {
			errOut(w, 403, "forbidden")
			return
		}
		next(w, r, c)
	}
}
func hasScope(s, n string) bool {
	for _, v := range strings.Split(s, ",") {
		if strings.TrimSpace(v) == n {
			return true
		}
	}
	return false
}
func remoteIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func ipAllowed(ip string, cidrs []string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	for _, v := range cidrs {
		_, n, e := net.ParseCIDR(strings.TrimSpace(v))
		if e == nil && n.Contains(a) {
			return true
		}
	}
	return false
}
func decode(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("empty body")
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func errOut(w http.ResponseWriter, status int, msg string) {
	jsonOut(w, status, map[string]string{"error": msg})
}
func (s *Server) audit(actor, ns, action, id, host, result, ip string) {
	_, _ = s.S.DB.Exec(`INSERT INTO audit(at,actor,ns,secret_id,action,target_host,result,source_ip) VALUES(?,?,?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), actor, ns, id, action, host, result, ip)
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func ref(v string) (string, string, bool) {
	if !strings.HasPrefix(v, "vault:") {
		return "", "", false
	}
	p := strings.Split(strings.TrimPrefix(v, "vault:"), "/")
	if len(p) != 2 || p[0] == "" || p[1] == "" {
		return "", "", false
	}
	return p[0], p[1], true
}
func randomID() (string, error) {
	b, e := vaultcrypto.Random(16)
	if e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}

var _ = sql.ErrNoRows
