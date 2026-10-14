package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResolveIsExplicitPlaintextBoundaryAndRotateMetadataOnly(t *testing.T) {
	s, _, token, _ := testServer(t, "secrets:write,resolve")
	sentinel := "SENTINEL-VALUE-7f3a9c"
	body := `{"label":"fake","provider":"generic","type":"token","value":"` + sentinel + `","bindings":{"allow_resolve":true}}`
	code, out := request(t, s, token, "POST", "/v1/secrets", body)
	if code != 201 || strings.Contains(out, sentinel) {
		t.Fatalf("write response leaked value: %d", code)
	}
	var m Metadata
	if json.Unmarshal([]byte(out), &m) != nil {
		t.Fatal("invalid metadata")
	}
	code, out = request(t, s, token, "PUT", "/v1/secrets/"+m.ID+"/value", `{"value":"SENTINEL-VALUE-7f3a9c"}`)
	if code != 200 || strings.Contains(out, sentinel) {
		t.Fatalf("rotate response leaked value: %d", code)
	}
	code, out = request(t, s, token, "POST", "/v1/resolve", `{"secret":"vault:ns1/`+m.ID+`"}`)
	if code != 200 || !strings.Contains(out, sentinel) {
		t.Fatalf("resolve boundary failed: %d", code)
	}
}
