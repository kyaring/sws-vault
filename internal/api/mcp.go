package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) admin(w http.ResponseWriter, r *http.Request) { s.adminHandler(w, r) }
func (s *Server) mcp(w http.ResponseWriter, r *http.Request, c Client) {
	var q map[string]any
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		errOut(w, 400, "invalid request")
		return
	}
	method, _ := q["method"].(string)
	id := q["id"]
	switch method {
	case "initialize":
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "sws-vault", "version": "1"}}})
	case "tools/list":
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"tools": []any{map[string]any{"name": "vault_list", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "vault_fetch", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "vault_intent", "inputSchema": map[string]any{"type": "object"}}}}})
	case "tools/call":
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "tool not implemented"}})
	default:
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "method not found"}})
	}
}
