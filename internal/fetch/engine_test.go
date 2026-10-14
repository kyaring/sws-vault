package fetch

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type fixedResolver struct{ ip net.IP }

func (f fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: f.ip}}, nil
}

type changingResolver struct{ calls atomic.Int32 }

func (r *changingResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	if r.calls.Add(1) == 1 {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
}
func testURL(s *httptest.Server) string {
	return strings.Replace(s.URL, "127.0.0.1", "example.test", 1)
}
func testHost(s *httptest.Server) string {
	return "example.test:" + strings.Split(strings.TrimPrefix(s.URL, "http://127.0.0.1:"), "/")[0]
}
func TestFetchPinsIPDropsAuthAndRedacts(t *testing.T) {
	sentinel := "SENTINEL-VALUE-7f3a9c"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer injected" {
			t.Errorf("caller auth was not replaced")
		}
		if r.Header.Get("Cookie") != "" {
			t.Errorf("caller cookie was forwarded")
		}
		w.Header().Set("X-Echo", r.Header.Get("X-Api-Key"))
		_, _ = w.Write([]byte(r.Header.Get("X-Api-Key") + " " + base64.StdEncoding.EncodeToString([]byte(sentinel))))
	}))
	defer srv.Close()
	e := Engine{Resolver: fixedResolver{net.ParseIP("127.0.0.1")}}
	caller := http.Header{"Authorization": []string{"Bearer caller"}, "Cookie": []string{"session=bad"}, "X-Api-Key": []string{"caller"}}
	inject := http.Header{"Authorization": []string{"Bearer injected"}, "X-Api-Key": []string{sentinel}}
	resp, err := e.Do(context.Background(), testURL(srv), "GET", []string{testHost(srv)}, true, true, caller, inject, nil, sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.Body, sentinel) || strings.Contains(resp.Body, base64.StdEncoding.EncodeToString([]byte(sentinel))) || strings.Contains(resp.Body, url.QueryEscape(sentinel)) || strings.Contains(resp.Body, url.PathEscape(sentinel)) || strings.Contains(strings.Join(resp.Headers["X-Echo"], ""), sentinel) {
		t.Fatal("response exposed injected value")
	}
}
func TestFetchRejectsUnapprovedHostPrivateAndMetadata(t *testing.T) {
	e := Engine{Resolver: fixedResolver{net.ParseIP("127.0.0.1")}}
	if _, err := e.Do(context.Background(), "http://example.test/", "GET", []string{"other.test"}, true, true, nil, nil, nil, ""); err == nil {
		t.Fatal("unapproved host accepted")
	}
	if _, err := e.Do(context.Background(), "http://example.test/", "GET", []string{"example.test"}, false, true, nil, nil, nil, ""); err == nil {
		t.Fatal("loopback accepted without private allowance")
	}
	e.Resolver = fixedResolver{net.ParseIP("169.254.169.254")}
	if _, err := e.Do(context.Background(), "http://example.test/", "GET", []string{"example.test"}, true, true, nil, nil, nil, ""); err == nil {
		t.Fatal("metadata IP accepted")
	}
}
func TestFetchDoesNotFollowRedirectAndCapsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/next", 302)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+10)))
	}))
	defer srv.Close()
	e := Engine{Resolver: fixedResolver{net.ParseIP("127.0.0.1")}}
	base := testURL(srv)
	r, err := e.Do(context.Background(), base+"/redirect", "GET", []string{testHost(srv)}, true, true, nil, nil, nil, "")
	if err != nil || r.StatusCode != 302 {
		t.Fatalf("redirect followed or failed: %d %v", r.StatusCode, err)
	}
	r, err = e.Do(context.Background(), base+"/body", "GET", []string{testHost(srv)}, true, true, nil, nil, nil, "")
	if err != nil || !r.Truncated || len(r.Body) != MaxResponseBytes {
		t.Fatalf("body cap failed: %d %v", len(r.Body), err)
	}
}
func TestFetchUsesPinnedAddressAfterDNSChanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	resolver := &changingResolver{}
	e := Engine{Resolver: resolver}
	resp, err := e.Do(context.Background(), testURL(srv), "GET", []string{testHost(srv)}, true, true, nil, nil, nil, "")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("pinned fetch failed: %v", err)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("DNS resolved %d times", resolver.calls.Load())
	}
}
