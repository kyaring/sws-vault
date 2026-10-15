package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestIntentOneTimeAndCSRF(t *testing.T) {
	s, _, token, _ := testServer(t, "intents:create,secrets:list")
	status, out := request(t, s, token, "POST", "/v1/intents", `{"label":"fake-intent"}`)
	if status != 201 {
		t.Fatalf("intent create: %d %s", status, out)
	}
	var link struct {
		URL string `json:"url"`
	}
	if json.Unmarshal([]byte(out), &link) != nil {
		t.Fatal("bad intent response")
	}
	u, e := url.Parse(link.URL)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", u.Path, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("intent page: %d", w.Code)
	}
	re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	match := re.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("csrf field missing")
	}
	cookies := w.Result().Cookies()
	var csrf *http.Cookie
	for _, c := range cookies {
		if c.Name == "sv_intent_csrf" {
			csrf = c
		}
	}
	if csrf == nil {
		t.Fatal("csrf cookie missing")
	}
	form := url.Values{"csrf": {match[1]}, "provider": {"generic"}, "type": {"token"}, "value": {"SENTINEL-VALUE-7f3a9c"}}
	r = httptest.NewRequest("POST", u.Path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrf)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "SENTINEL-VALUE-7f3a9c") {
		t.Fatalf("intent submit failed or leaked: %d", w.Code)
	}
	r = httptest.NewRequest("POST", u.Path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrf)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("intent replay status %d", w.Code)
	}
}
