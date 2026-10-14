package api

import (
	"encoding/json"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) list(w http.ResponseWriter, r *http.Request, c Client) {
	ns := r.URL.Query().Get("ns")
	if ns == "" {
		ns = c.NS
	}
	if ns != c.NS {
		errOut(w, 404, "not found")
		return
	}
	rows, e := s.S.DB.Query(`SELECT id,ns,label,provider,type,preview,fingerprint,bindings,created_at,rotated_at,last_used_at,status FROM secrets WHERE ns=? AND status='active' ORDER BY created_at DESC`, ns)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer rows.Close()
	out := []Metadata{}
	for rows.Next() {
		var m Metadata
		var b string
		if rows.Scan(&m.ID, &m.NS, &m.Label, &m.Provider, &m.Type, &m.Preview, &m.Fingerprint, &b, &m.CreatedAt, &m.RotatedAt, &m.LastUsedAt, &m.Status) != nil {
			errOut(w, 500, "internal error")
			return
		}
		_ = json.Unmarshal([]byte(b), &m.Bindings)
		m.Bindings.Username = mask(m.Bindings.Username)
		out = append(out, m)
	}
	s.audit(c.ID, c.NS, "list", "", "", "ok", s.sourceIP(r))
	jsonOut(w, 200, map[string]any{"secrets": out})
}
func (s *Server) create(w http.ResponseWriter, r *http.Request, c Client) {
	var q SecretRequest
	if decode(r, &q) != nil {
		errOut(w, 400, "invalid request")
		return
	}
	if q.NS == "" {
		q.NS = c.NS
	}
	if q.NS != c.NS {
		errOut(w, 404, "not found")
		return
	}
	if q.Value == "" || len(q.Value) > 1<<20 || strings.TrimSpace(q.Label) == "" {
		errOut(w, 400, "invalid request")
		return
	}
	m, e := s.save(q, false, "")
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	s.audit(c.ID, c.NS, "write", m.ID, "", "ok", s.sourceIP(r))
	jsonOut(w, 201, m)
}
func (s *Server) rotate(w http.ResponseWriter, r *http.Request, c Client) {
	var q struct {
		Value string `json:"value"`
	}
	if decode(r, &q) != nil {
		errOut(w, 400, "invalid request")
		return
	}
	id := r.PathValue("id")
	var ns, label, provider, typ, b string
	e := s.S.DB.QueryRow(`SELECT ns,label,provider,type,bindings FROM secrets WHERE id=?`, id).Scan(&ns, &label, &provider, &typ, &b)
	if e != nil || ns != c.NS {
		errOut(w, 404, "not found")
		return
	}
	var bd Binding
	_ = json.Unmarshal([]byte(b), &bd)
	m, e := s.save(SecretRequest{NS: ns, Label: label, Provider: provider, Type: typ, Value: q.Value, Bindings: bd}, true, id)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	s.audit(c.ID, c.NS, "rotate", id, "", "ok", s.sourceIP(r))
	jsonOut(w, 200, m)
}
func (s *Server) save(q SecretRequest, rotate bool, id string) (Metadata, error) {
	if err := validateSecret(q); err != nil {
		return Metadata{}, err
	}
	if q.Username != "" {
		q.Bindings.Username = q.Username
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if id == "" {
		var e error
		id, e = randomID()
		if e != nil {
			return Metadata{}, e
		}
	}
	dek, e := vaultcrypto.NewKey()
	if e != nil {
		return Metadata{}, e
	}
	defer wipe(dek)
	ct, e := vaultcrypto.Seal(dek, []byte(q.Value), vaultcrypto.SecretAAD(q.NS, id, q.Type, s.Current))
	if e != nil {
		return Metadata{}, e
	}
	wrapped, e := s.wrapDEK(q.NS, id, s.Current, dek)
	if e != nil {
		return Metadata{}, e
	}
	preview := q.Value
	if q.Type == "webhook" {
		if u, e := url.Parse(q.Value); e == nil {
			preview = u.Host
		}
	} else if q.Type == "login" {
		preview = mask(q.Username)
	} else {
		if len(preview) > 4 {
			preview = preview[len(preview)-4:]
		}
		preview = "••••" + preview
	}
	if len(preview) > 80 {
		preview = preview[:80]
	}
	fp, e := s.fingerprint([]byte(q.Value))
	if e != nil {
		return Metadata{}, e
	}
	bb, _ := json.Marshal(q.Bindings)
	_, e = s.S.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, q.NS, q.NS, now)
	if e != nil {
		return Metadata{}, e
	}
	if rotate {
		_, e = s.S.DB.Exec(`UPDATE secrets SET ciphertext=?,dek_wrapped=?,key_version=?,preview=?,fingerprint=?,bindings=?,rotated_at=? WHERE id=?`, ct, wrapped, s.Current, preview, fp, string(bb), now, id)
	} else {
		_, e = s.S.DB.Exec(`INSERT INTO secrets(id,ns,label,provider,type,ciphertext,dek_wrapped,key_version,preview,fingerprint,bindings,created_at,rotated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, q.NS, q.Label, q.Provider, q.Type, ct, wrapped, s.Current, preview, fp, string(bb), now, now)
	}
	if e != nil {
		return Metadata{}, e
	}
	publicBindings := q.Bindings
	publicBindings.Username = mask(publicBindings.Username)
	return Metadata{ID: id, NS: q.NS, Label: q.Label, Provider: q.Provider, Type: q.Type, Preview: preview, Fingerprint: fp, Bindings: publicBindings, CreatedAt: now, RotatedAt: now, Status: "active"}, nil
}
func mask(v string) string {
	if v == "" {
		return ""
	}
	if len(v) < 3 {
		return "***"
	}
	return v[:1] + strings.Repeat("*", len(v)-2) + v[len(v)-1:]
}
func (s *Server) resolve(w http.ResponseWriter, r *http.Request, c Client) {
	w.Header().Set("Cache-Control", "no-store")
	var q struct {
		Secret string `json:"secret"`
	}
	if decode(r, &q) != nil {
		errOut(w, 400, "invalid request")
		return
	}
	ns, id, ok := ref(q.Secret)
	if !ok || ns != c.NS {
		errOut(w, 404, "not found")
		return
	}
	var typ, status, b string
	var ct, wrapped []byte
	var kv int
	e := s.S.DB.QueryRow(`SELECT type,status,ciphertext,dek_wrapped,key_version,bindings FROM secrets WHERE ns=? AND id=?`, ns, id).Scan(&typ, &status, &ct, &wrapped, &kv, &b)
	if e != nil || status != "active" {
		errOut(w, 404, "not found")
		return
	}
	var bd Binding
	if json.Unmarshal([]byte(b), &bd) != nil || !bd.AllowResolve {
		errOut(w, 403, "forbidden")
		return
	}
	if len(bd.AllowedClients) > 0 {
		allowed := false
		for _, clientID := range bd.AllowedClients {
			if clientID == c.ID {
				allowed = true
			}
		}
		if !allowed {
			errOut(w, 403, "forbidden")
			return
		}
	}
	dek, e := s.unwrapDEK(ns, id, uint32(kv), wrapped)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer wipe(dek)
	v, e := vaultcrypto.Open(dek, ct, vaultcrypto.SecretAAD(ns, id, typ, uint32(kv)))
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer wipe(v)
	_, _ = s.S.DB.Exec(`UPDATE secrets SET last_used_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), id)
	s.audit(c.ID, c.NS, "resolve", id, "", "ok", s.sourceIP(r))
	jsonOut(w, 200, map[string]string{"value": string(v), "username": bd.Username})
}
