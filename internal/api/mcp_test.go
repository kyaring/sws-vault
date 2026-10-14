package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPToolsAndScope(t *testing.T) {
	s, _, token, _ := testServer(t, "secrets:list")
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "vault_list") || !strings.Contains(w.Body.String(), "vault_fetch") || !strings.Contains(w.Body.String(), "vault_intent") {
		t.Fatalf("tools/list invalid: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_fetch","arguments":{"secret":"vault:ns1/id","url":"https://example.test"}}}`))
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "forbidden") {
		t.Fatalf("MCP ignored fetch scope: %s", w.Body.String())
	}
}
