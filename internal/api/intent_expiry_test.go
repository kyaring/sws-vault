package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIntentExpiresAndStoresOnlyHash(t *testing.T) {
	s, st, token, _ := testServer(t, "intents:create")
	status, out := request(t, s, token, "POST", "/v1/intents", `{"label":"fake-expiry"}`)
	if status != 201 {
		t.Fatalf("create intent status %d", status)
	}
	var v struct {
		URL string `json:"url"`
	}
	if json.Unmarshal([]byte(out), &v) != nil {
		t.Fatal("bad intent response")
	}
	u, _ := url.Parse(v.URL)
	if _, e := st.DB.Exec(`UPDATE intents SET expires_at=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", u.Path, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("expired intent status %d", w.Code)
	}
	var stored []byte
	if e := st.DB.QueryRow(`SELECT token_hash FROM intents LIMIT 1`).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if len(stored) != 32 {
		t.Fatalf("intent token hash length %d", len(stored))
	}
}
