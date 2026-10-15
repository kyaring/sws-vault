package api

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"strings"
)

type generateRequest struct {
	NS       string  `json:"ns"`
	Label    string  `json:"label"`
	Provider string  `json:"provider"`
	Type     string  `json:"type"`
	Length   int     `json:"length"`
	Charset  string  `json:"charset"`
	Bindings Binding `json:"bindings"`
}

func (s *Server) generate(w http.ResponseWriter, r *http.Request, c Client) {
	var q generateRequest
	if decode(r, &q) != nil {
		errOut(w, 400, "invalid request")
		return
	}
	if strings.TrimSpace(q.Label) == "" || strings.TrimSpace(q.Type) == "" || (q.NS != "" && q.NS != c.NS) {
		errOut(w, 400, "invalid request")
		return
	}
	if q.Length < 16 || q.Length > 4096 {
		errOut(w, 400, "length must be between 16 and 4096")
		return
	}
	chars := q.Charset
	if chars == "" {
		chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
	}
	if len(chars) < 2 || len(chars) > 256 {
		errOut(w, 400, "invalid charset")
		return
	}
	var b strings.Builder
	for i := 0; i < q.Length; i++ {
		n, e := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if e != nil {
			errOut(w, 500, "internal error")
			return
		}
		b.WriteByte(chars[n.Int64()])
	}
	value := b.String()
	m, e := s.save(SecretRequest{NS: c.NS, Label: q.Label, Provider: q.Provider, Type: q.Type, Value: value, Bindings: q.Bindings}, false, "")
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	s.audit(c.ID, c.NS, "generate", m.ID, "", "ok", s.sourceIP(r))
	jsonOut(w, 201, m)
}
