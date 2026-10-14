package cli

import (
	"encoding/base64"
	"io"
	"net/url"
	"sort"
	"strings"
)

type Redactor struct {
	w        io.Writer
	buf      []byte
	patterns []string
	keep     int
}

func NewRedactor(w io.Writer, values []string) *Redactor {
	r := &Redactor{w: w}
	for _, v := range values {
		if v == "" {
			continue
		}
		r.patterns = append(r.patterns, v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawStdEncoding.EncodeToString([]byte(v)), base64.URLEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)), url.QueryEscape(v), url.PathEscape(v))
	}
	sort.Slice(r.patterns, func(i, j int) bool { return len(r.patterns[i]) > len(r.patterns[j]) })
	for _, p := range r.patterns {
		if len(p) > r.keep {
			r.keep = len(p)
		}
	}
	if r.keep > 0 {
		r.keep--
	}
	return r
}
func (r *Redactor) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	if len(r.buf) <= r.keep {
		return len(p), nil
	}
	n := len(r.buf) - r.keep
	all := string(r.buf)
	for _, pat := range r.patterns {
		if pat == "" {
			continue
		}
		from := 0
		for {
			at := strings.Index(all[from:], pat)
			if at < 0 {
				break
			}
			start := from + at
			end := start + len(pat)
			if start < n && end > n {
				n = start
			}
			from = start + 1
			if from >= len(all) {
				break
			}
		}
	}
	if n <= 0 {
		return len(p), nil
	}
	safe := string(r.buf[:n])
	r.buf = append([]byte(nil), r.buf[n:]...)
	_, e := io.WriteString(r.w, r.redact(safe))
	return len(p), e
}
func (r *Redactor) Flush() error {
	if len(r.buf) == 0 {
		return nil
	}
	_, e := io.WriteString(r.w, r.redact(string(r.buf)))
	r.buf = nil
	return e
}
func (r *Redactor) redact(s string) string {
	for _, p := range r.patterns {
		if p != "" {
			s = strings.ReplaceAll(s, p, "[REDACTED]")
		}
	}
	return s
}
