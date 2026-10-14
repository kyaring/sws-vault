package api

import (
	"context"
	"encoding/json"
	"github.com/kyaring/sws-vault/internal/fetch"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testLoopResolver struct{}

func (testLoopResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}
func TestVerificationFailureDoesNotSave(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:write")
	s.FetchEngine = fetch.Engine{Resolver: testLoopResolver{}}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer backend.Close()
	u, _ := url.Parse(strings.Replace(backend.URL, "127.0.0.1", "example.test", 1))
	sessions.Lock()
	sessions.m["verify-fake-session"] = adminSession{csrf: "verify-fake-csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	headers, _ := json.Marshal(map[string]string{"X-Api-Key": "{v}"})
	form := url.Values{"csrf": {"verify-fake-csrf"}, "ns": {"ns1"}, "label": {"verify-fake"}, "provider": {"generic"}, "type": {"token"}, "value": {"SENTINEL-VALUE-7f3a9c"}, "hosts": {u.Host}, "headers": {string(headers)}, "base_url": {u.String()}, "verify": {"on"}, "allow_private": {"on"}, "allow_http": {"on"}}
	r := httptest.NewRequest("POST", "/admin/secrets/new", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "verify-fake-session"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("failed verification status %d", w.Code)
	}
	var count int
	if e := st.DB.QueryRow(`SELECT count(*) FROM secrets WHERE label='verify-fake'`).Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 0 {
		t.Fatal("secret stored after failed provider verification")
	}
}
