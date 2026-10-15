package api

import (
	"bytes"
	"encoding/json"
	mcpservice "github.com/kyaring/sws-vault/internal/mcp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

func (s *Server) admin(w http.ResponseWriter, r *http.Request) { s.adminHandler(w, r) }
func (s *Server) mcp(w http.ResponseWriter, r *http.Request, c Client) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
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
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"tools": mcpservice.Tools()}})
	case "tools/call":
		s.mcpCall(w, id, q, c, r)
	default:
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "method not found"}})
	}
}
func (s *Server) mcpCall(w http.ResponseWriter, id any, q map[string]any, c Client, original *http.Request) {
	p, _ := q["params"].(map[string]any)
	name, _ := p["name"].(string)
	args, _ := p["arguments"].(map[string]any)
	method, path, scope := "POST", "/v1/secrets", ""
	var body []byte
	switch name {
	case "vault_list":
		scope = "secrets:list"
		method = "GET"
		ns, _ := args["ns"].(string)
		if ns == "" {
			ns = c.NS
		}
		path = "/v1/secrets?ns=" + url.QueryEscape(ns)
	case "vault_fetch":
		scope = "fetch"
		path = "/v1/fetch"
		body, _ = json.Marshal(args)
	case "vault_intent":
		scope = "intents:create"
		path = "/v1/intents"
		body, _ = json.Marshal(args)
	default:
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32602, "message": "unknown tool"}})
		return
	}
	if !hasScope(c.Scopes, scope) {
		jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32003, "message": "forbidden"}})
		return
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = original.RemoteAddr
	if xff := original.Header.Get("X-Forwarded-For"); xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	switch name {
	case "vault_list":
		s.list(rr, req, c)
	case "vault_fetch":
		s.fetch(rr, req, c)
	case "vault_intent":
		s.intent(rr, req, c)
	}
	text := strings.TrimSpace(rr.Body.String())
	isErr := rr.Code >= 400
	jsonOut(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": text}}, "isError": isErr}})
}
