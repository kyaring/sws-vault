package api

import (
	"testing"
	"time"
)

func TestClientCIDRExpiryAndDisable(t *testing.T) {
	s, st, token, _ := testServer(t, "secrets:list")
	if _, e := st.DB.Exec(`UPDATE clients SET cidrs='203.0.113.0/24' WHERE id='c1'`); e != nil {
		t.Fatal(e)
	}
	code, _ := request(t, s, token, "GET", "/v1/secrets", "")
	if code != 403 {
		t.Fatalf("CIDR mismatch status %d", code)
	}
	if _, e := st.DB.Exec(`UPDATE clients SET cidrs='',expires_at=? WHERE id='c1'`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	code, _ = request(t, s, token, "GET", "/v1/secrets", "")
	if code != 401 {
		t.Fatalf("expired client status %d", code)
	}
	if _, e := st.DB.Exec(`UPDATE clients SET expires_at='',disabled=1 WHERE id='c1'`); e != nil {
		t.Fatal(e)
	}
	code, _ = request(t, s, token, "GET", "/v1/secrets", "")
	if code != 401 {
		t.Fatalf("disabled client status %d", code)
	}
}
