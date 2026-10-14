package api

import (
	"crypto/sha256"
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
		out = append(out, m)
	}
	s.audit(c.ID, c.NS, "list", "", "", "ok", remoteIP(r))
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
	s.audit(c.ID, c.NS, "write", m.ID, "", "ok", remoteIP(r))
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
	s.audit(c.ID, c.NS, "rotate", id, "", "ok", remoteIP(r))
	jsonOut(w, 200, m)
}
func (s *Server) save(q SecretRequest, rotate bool, id string) (Metadata, error) {
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
	ct, e := vaultcrypto.Seal(dek, []byte(q.Value), []byte(q.NS+"/"+id+"/"+q.Type))
	if e != nil {
		return Metadata{}, e
	}
	wrapped, e := vaultcrypto.Seal(s.Keys[s.Current], dek, []byte(q.NS+"/"+id+"/dek"))
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
	fp := vaultcrypto.Fingerprint(s.Keys[s.Current], []byte(q.Value))
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
	return Metadata{ID: id, NS: q.NS, Label: q.Label, Provider: q.Provider, Type: q.Type, Preview: preview, Fingerprint: fp, Bindings: q.Bindings, CreatedAt: now, RotatedAt: now, Status: "active"}, nil
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
	dek, e := vaultcrypto.Open(s.Keys[uint32(kv)], wrapped, []byte(ns+"/"+id+"/dek"))
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer wipe(dek)
	v, e := vaultcrypto.Open(dek, ct, []byte(ns+"/"+id+"/"+typ))
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer wipe(v)
	w.Header().Set("Cache-Control", "no-store")
	s.audit(c.ID, c.NS, "resolve", id, "", "ok", remoteIP(r))
	jsonOut(w, 200, map[string]string{"value": string(v)})
}
func (s *Server) intent(w http.ResponseWriter, r *http.Request, c Client) {
	raw, e := vaultcrypto.Random(32)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	token := vaultcrypto.Encode(raw)
	wipe(raw)
	h := sha256.Sum256([]byte(token))
	exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	_, e = s.S.DB.Exec(`INSERT INTO intents(token_hash,ns,label,expires_at) VALUES(?,?,?,?)`, h[:], c.NS, "new secret", exp)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	base := s.C.PublicBaseURL
	if base == "" {
		base = "http://127.0.0.1:9531"
	}
	s.audit(c.ID, c.NS, "intent", "", "", "ok", remoteIP(r))
	jsonOut(w, 201, map[string]string{"url": base + "/i/" + token, "expires_at": exp})
}
func (s *Server) intentPage(w http.ResponseWriter, r *http.Request)   { errOut(w, 404, "not found") }
func (s *Server) intentSubmit(w http.ResponseWriter, r *http.Request) { errOut(w, 404, "not found") }
