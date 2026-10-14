package cli

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
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
