package api

import (
	"encoding/json"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	fetchengine "github.com/kyaring/sws-vault/internal/fetch"
	"github.com/kyaring/sws-vault/internal/provider"
	"net/http"
	"net/url"
)

type fetchRequest struct {
	Secret  string            `json:"secret"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func (s *Server) fetch(w http.ResponseWriter, r *http.Request, c Client) {
	var q fetchRequest
	if decode(r, &q) != nil {
		errOut(w, 400, "invalid request")
		return
	}
	ns, id, ok := ref(q.Secret)
	if !ok || ns != c.NS {
		errOut(w, 404, "not found")
		return
	}
	var typ, status, prov, b string
	var ct, wrapped []byte
	var version int
	e := s.S.DB.QueryRow(`SELECT type,status,provider,ciphertext,dek_wrapped,key_version,bindings FROM secrets WHERE ns=? AND id=?`, ns, id).Scan(&typ, &status, &prov, &ct, &wrapped, &version, &b)
	if e != nil || status != "active" {
		errOut(w, 404, "not found")
		return
	}
	var bd Binding
	if json.Unmarshal([]byte(b), &bd) != nil {
		errOut(w, 500, "internal error")
		return
	}
	if len(bd.AllowedClients) > 0 {
		found := false
		for _, v := range bd.AllowedClients {
			if v == c.ID {
				found = true
			}
		}
		if !found {
			errOut(w, 403, "forbidden")
			return
		}
	}
	dek, e := vaultcrypto.Open(s.Keys[uint32(version)], wrapped, []byte(ns+"/"+id+"/dek"))
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer wipe(dek)
	value, e := vaultcrypto.Open(dek, ct, []byte(ns+"/"+id+"/"+typ))
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer wipe(value)
	hosts := bd.Hosts
	if len(hosts) == 0 {
		hosts = provider.DefaultHosts(prov)
	}
	injected, e := provider.Build(prov, string(value), bd.Username, bd.Headers)
	if e != nil {
		errOut(w, 400, "provider binding invalid")
		return
	}
	caller := http.Header{}
	for k, v := range q.Headers {
		caller.Set(k, v)
	}
	resp, e := (fetchengine.Engine{}).Do(r.Context(), q.URL, q.Method, hosts, bd.AllowPrivate, bd.AllowHTTP, caller, injected, []byte(q.Body), string(value))
	host := ""
	if u, pe := url.Parse(q.URL); pe == nil {
		host = u.Host
	}
	if e != nil {
		s.audit(c.ID, c.NS, "fetch", id, host, "rejected", remoteIP(r))
		errOut(w, 400, "target rejected by fetch policy")
		return
	}
	s.audit(c.ID, c.NS, "fetch", id, host, "ok", remoteIP(r))
	jsonOut(w, 200, resp)
}
