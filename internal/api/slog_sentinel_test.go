package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
)

func TestSlogDoesNotLeakSecretDuringStoreAndResolve(t *testing.T) {
	const sentinel = "SWSV-SLOG-SENTINEL-DO-NOT-LOG-93a1"
	dir := t.TempDir()
	key, err := vaultcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	server := New(config.Config{DataDir: dir, DBPath: filepath.Join(dir, "vault.db"), RateLimitPerMinute: 100}, st, key)
	client := Client{ID: "test-client", NS: "sentinelns", Name: "test", Scopes: "secrets:write,resolve"}
	body, _ := json.Marshal(SecretRequest{NS: "sentinelns", Label: "sentinel test", Provider: "generic", Type: "token", Value: sentinel, Bindings: Binding{AllowResolve: true}})
	createReq := httptest.NewRequest("POST", "/v1/secrets", bytes.NewReader(body))
	createReq.RemoteAddr = "127.0.0.1:1234"
	createRec := httptest.NewRecorder()
	server.create(createRec, createReq, client)
	if createRec.Code != 201 {
		t.Fatalf("create status=%d body=%s", createRec.Code, createRec.Body.String())
	}
	var metadata Metadata
	if err := json.Unmarshal(createRec.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	resolveBody, _ := json.Marshal(map[string]string{"secret": "vault:" + metadata.NS + "/" + metadata.ID})
	resolveReq := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(resolveBody))
	resolveReq.RemoteAddr = "127.0.0.1:1234"
	resolveRec := httptest.NewRecorder()
	server.resolve(resolveRec, resolveReq, client)
	if resolveRec.Code != 200 {
		t.Fatalf("resolve status=%d body=%s", resolveRec.Code, resolveRec.Body.String())
	}
	if !strings.Contains(resolveRec.Body.String(), sentinel) {
		t.Fatal("resolve response did not contain test sentinel; workflow did not exercise plaintext boundary")
	}
	captured := logs.String()
	if !strings.Contains(captured, "secret stored") || !strings.Contains(captured, "secret resolved") {
		t.Fatalf("self-check: expected store and resolve log records, got %q", captured)
	}
	if strings.Contains(captured, sentinel) {
		t.Fatalf("sensitive value leaked into slog output: %s", captured)
	}
}
