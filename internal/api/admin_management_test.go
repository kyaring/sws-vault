package api

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPanelCreatesAndDisablesClientAndIntent(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	sessions.Lock()
	sessions.m["manage-session"] = adminSession{csrf: "manage-csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	post := func(path string, v url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "manage-session"})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	ns := post("/admin/namespaces", url.Values{"csrf": {"manage-csrf"}, "name": {"panel-ns"}})
	if ns.Code != http.StatusSeeOther {
		t.Fatalf("namespace create: %d", ns.Code)
	}
	client := post("/admin/clients", url.Values{"csrf": {"manage-csrf"}, "ns": {"panel-ns"}, "name": {"panel-client"}, "scopes": {"secrets:list"}})
	if client.Code != 200 {
		t.Fatalf("client create: %d", client.Code)
	}
	tokenMatch := regexp.MustCompile(`swsv_[A-Za-z0-9_-]{43}`).FindString(client.Body.String())
	if tokenMatch == "" {
		t.Fatal("one-time client token missing")
	}
	if strings.Count(client.Body.String(), tokenMatch) != 1 {
		t.Fatal("client token displayed more than once")
	}
	sum := sha256.Sum256([]byte(tokenMatch))
	var stored []byte
	var clientID string
	if e := st.DB.QueryRow(`SELECT id,token_hash FROM clients WHERE ns='panel-ns' AND name='panel-client'`).Scan(&clientID, &stored); e != nil {
		t.Fatal(e)
	}
	if string(stored) != string(sum[:]) {
		t.Fatal("client token was not stored as hash")
	}
	intent := post("/admin/intents/new", url.Values{"csrf": {"manage-csrf"}, "ns": {"panel-ns"}, "label": {"fake-intent"}})
	if intent.Code != 200 || !strings.Contains(intent.Body.String(), "/i/") {
		t.Fatalf("intent create: %d", intent.Code)
	}
	intentToken := regexp.MustCompile(`/i/([A-Za-z0-9_-]{40,})`).FindStringSubmatch(intent.Body.String())
	if len(intentToken) != 2 {
		t.Fatal("intent token missing")
	}
	ih := sha256.Sum256([]byte(intentToken[1]))
	var saved []byte
	if e := st.DB.QueryRow(`SELECT token_hash FROM intents WHERE ns='panel-ns' AND label='fake-intent'`).Scan(&saved); e != nil {
		t.Fatal(e)
	}
	if string(saved) != string(ih[:]) {
		t.Fatal("intent token was not stored as hash")
	}
	disabled := post("/admin/clients/"+clientID+"/disable", url.Values{"csrf": {"manage-csrf"}})
	if disabled.Code != http.StatusSeeOther {
		t.Fatalf("client disable: %d", disabled.Code)
	}
	var flag int
	if e := st.DB.QueryRow(`SELECT disabled FROM clients WHERE id=?`, clientID).Scan(&flag); e != nil || flag != 1 {
		t.Fatal("client was not disabled")
	}
}
