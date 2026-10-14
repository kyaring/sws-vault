package api

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T, scopes string) (*Server, *store.Store, string, string) {
	t.Helper()
	rateState.Lock()
	delete(rateState.m, "c1")
	rateState.Unlock()
	d := t.TempDir()
	s, e := store.Open(filepath.Join(d, "vault.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	key, _ := vaultcrypto.NewKey()
	token := "swsv_test-fake-token"
	h := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Format(time.RFC3339)
	_, e = s.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ns1','ns1',?)`, now)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('c1','ns1','test',?,?,?)`, h[:], scopes, now)
	if e != nil {
		t.Fatal(e)
	}
	return New(config.Config{DataDir: d, ListenAddr: "127.0.0.1:0"}, s, key), s, token, d
}
func request(t *testing.T, s *Server, token, method, path, body string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}
func TestSentinelNeverListedOrAudited(t *testing.T) {
	s, st, token, d := testServer(t, "secrets:write,secrets:list,resolve")
	sentinel := "SENTINEL-VALUE-7f3a9c"
	body := `{"ns":"ns1","label":"fake","provider":"generic","type":"token","value":"` + sentinel + `","bindings":{"allow_resolve":true}}`
	code, _ := request(t, s, token, "POST", "/v1/secrets", body)
	if code != 201 {
		t.Fatalf("create status %d", code)
	}
	code, out := request(t, s, token, "GET", "/v1/secrets?ns=ns1", "")
	if code != 200 || strings.Contains(out, sentinel) {
		t.Fatalf("list exposed sentinel: status %d", code)
	}
	var m map[string]any
	if json.Unmarshal([]byte(out), &m) != nil {
		t.Fatal("invalid list response")
	}
	var audit string
	if e := st.DB.QueryRow(`SELECT group_concat(action || result,' ') FROM audit`).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(audit, sentinel) {
		t.Fatal("audit exposed sentinel")
	}
	if e := st.Close(); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"vault.db", "vault.db-wal", "vault.db-shm"} {
		b, e := os.ReadFile(filepath.Join(d, name))
		if e == nil && strings.Contains(string(b), sentinel) {
			t.Fatalf("database artifact %s contains plaintext sentinel", name)
		}
	}
}
func TestScopeAndNamespaceIsolation(t *testing.T) {
	s, _, token, _ := testServer(t, "secrets:list")
	code, _ := request(t, s, token, "POST", "/v1/secrets", `{"label":"x","value":"SENTINEL-VALUE-7f3a9c"}`)
	if code != 403 {
		t.Fatalf("scope status=%d", code)
	}
	code, _ = request(t, s, token, "GET", "/v1/secrets?ns=other", "")
	if code != 404 {
		t.Fatalf("cross namespace status=%d", code)
	}
}
func TestSecurityHeaders(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("security headers missing")
	}
}
func TestRateLimitAndCIDR(t *testing.T) {
	s, st, token, _ := testServer(t, "secrets:list")
	for i := 0; i < 60; i++ {
		code, _ := request(t, s, token, "GET", "/v1/secrets", "")
		if code != 200 {
			t.Fatalf("request %d status %d", i, code)
		}
	}
	code, _ := request(t, s, token, "GET", "/v1/secrets", "")
	if code != 429 {
		t.Fatalf("rate limit status %d", code)
	}
	if !ipAllowed("192.0.2.5", []string{"192.0.2.0/24"}) || ipAllowed("192.0.3.5", []string{"192.0.2.0/24"}) {
		t.Fatal("CIDR check incorrect")
	}
	_, e := st.DB.Exec(`UPDATE clients SET disabled=1 WHERE id='c1'`)
	if e != nil {
		t.Fatal(e)
	}
	code, _ = request(t, s, token, "GET", "/v1/secrets", "")
	if code != 401 {
		t.Fatalf("disabled client status %d", code)
	}
}
