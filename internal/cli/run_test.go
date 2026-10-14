package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyaring/sws-vault/internal/api"
	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
)

func captureCommandIO(t *testing.T, input string, fn func() error) (string, string, error) {
	t.Helper()
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	_, _ = inW.Write([]byte(input))
	_ = inW.Close()
	os.Stdin = inR
	os.Stdout = outW
	os.Stderr = errW
	e := fn()
	_ = outW.Close()
	_ = errW.Close()
	os.Stdin = oldIn
	os.Stdout = oldOut
	os.Stderr = oldErr
	out, _ := io.ReadAll(outR)
	er, _ := io.ReadAll(errR)
	_ = inR.Close()
	_ = outR.Close()
	_ = errR.Close()
	return string(out), string(er), e
}

func TestRunRedactsAndPassesExitCode(t *testing.T) {
	sentinel := "SENTINEL-VALUE-7f3a9c"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resolve" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"` + sentinel + `"}`))
	}))
	defer srv.Close()
	t.Setenv("SWSV_URL", srv.URL)
	t.Setenv("SWSV_TOKEN", "fake-client-token")
	t.Setenv("SWSV_NS", "demo")
	out, stderr, e := captureCommandIO(t, "", func() error {
		return Run([]string{"--env", "API_TOKEN=vault:demo/id", "--", "sh", "-c", "printf %s \"$API_TOKEN\"; printf %s \"$API_TOKEN\" >&2; exit 7"})
	})
	var ee *exec.ExitError
	if !errors.As(e, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("exit code not passed through: %v", e)
	}
	if strings.Contains(out, sentinel) || strings.Contains(stderr, sentinel) || !strings.Contains(out, "[REDACTED]") || !strings.Contains(stderr, "[REDACTED]") {
		t.Fatalf("child output not redacted: stdout=%q stderr=%q", out, stderr)
	}
}
func TestGitCredentialProtocol(t *testing.T) {
	sentinel := "SENTINEL-VALUE-7f3a9c"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-client-token" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/secrets":
			_, _ = w.Write([]byte(`{"secrets":[{"id":"fake-id","ns":"demo","provider":"github-pat","status":"active","bindings":{"hosts":["github.com"],"username":"x-access-token","allow_resolve":true}}]}`))
		case "/v1/resolve":
			_, _ = w.Write([]byte(`{"value":"` + sentinel + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("SWSV_URL", srv.URL)
	t.Setenv("SWSV_TOKEN", "fake-client-token")
	t.Setenv("SWSV_NS", "demo")
	out, _, e := captureCommandIO(t, "protocol=https\nhost=github.com\n\n", func() error { return GitCredential([]string{"get"}) })
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out, "username=x-access-token") || !strings.Contains(out, "password="+sentinel) {
		t.Fatalf("credential protocol response incorrect: %q", out)
	}
}
func TestRedactorEncodedVariant(t *testing.T) {
	sentinel := "SENTINEL-VALUE-7f3a9c"
	var b strings.Builder
	r := NewRedactor(&b, []string{sentinel})
	_, _ = r.Write([]byte("encoded=" + url.QueryEscape(sentinel)))
	_ = r.Flush()
	if strings.Contains(b.String(), sentinel) || strings.Contains(b.String(), url.QueryEscape(sentinel)) {
		t.Fatal("encoded value was not redacted")
	}
}

func TestGitCredentialUsesResolveUsernameFromRealVaultService(t *testing.T) {
	d := t.TempDir()
	st, err := store.Open(filepath.Join(d, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := vaultcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	const token = "fake-git-credential-client-token"
	digest := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('demo','demo',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('cli-test','demo','cli-test',?,?,?)`, digest[:], "secrets:list,secrets:write,resolve", now); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(config.Config{DataDir: d, ListenAddr: "127.0.0.1:0"}, st, key).Handler())
	defer srv.Close()
	t.Setenv("SWSV_URL", srv.URL)
	t.Setenv("SWSV_TOKEN", token)
	t.Setenv("SWSV_NS", "demo")

	create := func(label, host, username, value string) string {
		t.Helper()
		bindings := map[string]any{"hosts": []string{host}, "allow_resolve": true}
		if username != "" {
			bindings["username"] = username
		}
		body, err := json.Marshal(map[string]any{"ns": "demo", "label": label, "provider": "gitea-token", "type": "token", "value": value, "bindings": bindings})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/secrets", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var metadata struct {
			ID       string `json:"id"`
			Bindings struct {
				Username string `json:"username"`
			} `json:"bindings"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s status=%d", label, resp.StatusCode)
		}
		if username != "" && metadata.Bindings.Username == username {
			t.Fatalf("create response leaked unmasked username %q", username)
		}
		return metadata.ID
	}
	const rawUser = "fake-gitea-user-42"
	create("with-username", "gitea.example.test", rawUser, "FAKE-GITEA-TOKEN-42")
	create("without-username", "gitea-empty.example.test", "", "FAKE-GITEA-TOKEN-EMPTY")

	listReq, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/secrets?ns=demo", nil)
	if err != nil {
		t.Fatal(err)
	}
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	listBytes, err := io.ReadAll(listResp.Body)
	_ = listResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if listResp.StatusCode != http.StatusOK || strings.Contains(string(listBytes), rawUser) || !strings.Contains(string(listBytes), "f****************2") {
		t.Fatalf("list username masking failed: status=%d body=%s", listResp.StatusCode, listBytes)
	}

	for _, tc := range []struct{ host, username, password string }{
		{"gitea.example.test", rawUser, "FAKE-GITEA-TOKEN-42"},
		{"gitea-empty.example.test", "x-access-token", "FAKE-GITEA-TOKEN-EMPTY"},
	} {
		out, _, err := captureCommandIO(t, "protocol=https\nhost="+tc.host+"\n\n", func() error { return GitCredential([]string{"get"}) })
		if err != nil {
			t.Fatalf("git-credential get for %s: %v", tc.host, err)
		}
		if !strings.Contains(out, "username="+tc.username+"\n") || !strings.Contains(out, "password="+tc.password+"\n") {
			t.Fatalf("git-credential output for %s incorrect: %q", tc.host, out)
		}
	}
}
