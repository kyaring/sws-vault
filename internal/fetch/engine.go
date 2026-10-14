package fetch

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const MaxResponseBytes = 1 << 20
const RequestTimeout = 15 * time.Second

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type Engine struct {
	Resolver        Resolver
	DialContext     func(context.Context, string, string) (net.Conn, error)
	TLSClientConfig *tls.Config
}
type Response struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	Truncated  bool                `json:"truncated"`
}

func (e Engine) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	r := e.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupIPAddr(ctx, host)
}
func hostAllowed(u *url.URL, allowed []string) bool {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	for _, raw := range allowed {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if strings.Contains(v, ":") {
			if strings.EqualFold(v, u.Host) {
				return true
			}
			continue
		}
		if v == host && (port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80")) {
			return true
		}
	}
	return false
}
func unsafeIP(ip net.IP) bool {
	a, err := netip.ParseAddr(ip.String())
	if err != nil {
		return true
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified()
}
func metadataIP(ip net.IP) bool {
	a, err := netip.ParseAddr(ip.String())
	if err != nil {
		return true
	}
	return a == netip.MustParseAddr("169.254.169.254") || a == netip.MustParseAddr("169.254.170.2") || a == netip.MustParseAddr("100.100.100.200") || a == netip.MustParseAddr("fd00:ec2::254")
}
func redact(v, secret string) string {
	if secret == "" {
		return v
	}
	variants := []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)), base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)), url.QueryEscape(secret), url.PathEscape(secret)}
	for _, x := range variants {
		if x != "" {
			v = strings.ReplaceAll(v, x, "[REDACTED]")
		}
	}
	return v
}
func (e Engine) Do(ctx context.Context, target, method string, allowed []string, allowPrivate, allowHTTP bool, caller, injected http.Header, body []byte, secret string) (Response, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || u.User != nil {
		return Response{}, badTarget()
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return Response{}, badTarget()
	}
	if !hostAllowed(u, allowed) {
		return Response{}, badTarget()
	}
	ips, err := e.lookup(ctx, strings.ToLower(u.Hostname()))
	if err != nil || len(ips) == 0 {
		return Response{}, badTarget()
	}
	var pin net.IP
	for _, entry := range ips {
		if metadataIP(entry.IP) {
			return Response{}, badTarget()
		}
		if !allowPrivate && unsafeIP(entry.IP) {
			return Response{}, badTarget()
		}
		if pin == nil {
			pin = append(net.IP(nil), entry.IP...)
		}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, TLSClientConfig: e.TLSClientConfig, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true, DialContext: func(c context.Context, n, a string) (net.Conn, error) {
		if e.DialContext != nil {
			return e.DialContext(c, n, a)
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(c, n, net.JoinHostPort(pin.String(), port))
	}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return Response{}, badTarget()
	}
	for k, vs := range caller {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "cookie" || strings.HasPrefix(lk, "x-auth-") || lk == "host" {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for k, vs := range injected {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return Response{}, err
	}
	truncated := len(raw) > MaxResponseBytes
	if truncated {
		raw = raw[:MaxResponseBytes]
	}
	out := Response{StatusCode: resp.StatusCode, Headers: map[string][]string{}, Body: redact(string(raw), secret), Truncated: truncated}
	for k, vs := range resp.Header {
		for i, v := range vs {
			vs[i] = redact(v, secret)
		}
		out.Headers[k] = vs
	}
	return out, nil
}

func badTarget() error { return errors.New("target rejected by fetch policy") }
