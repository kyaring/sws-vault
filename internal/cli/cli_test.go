package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactorHandlesSplitAndEncodedValues(t *testing.T) {
	sentinel := "SENTINEL-VALUE-7f3a9c"
	var out bytes.Buffer
	r := NewRedactor(&out, []string{sentinel})
	r.Write([]byte("prefix SENTINEL-VALUE-7"))
	r.Write([]byte("f3a9c suffix"))
	if e := r.Flush(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), sentinel) || !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("redaction failed: %q", out.String())
	}
}
func TestEnvFilePermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "env")
	if e := os.WriteFile(p, []byte("SWSV_TOKEN=fake-token\nSWSV_URL=http://127.0.0.1:9531\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, _, e := LoadConfig([]string{"--env-file", p}); e == nil {
		t.Fatal("world-readable env file accepted")
	}
}

func TestEnvFileExact0600Accepted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "env")
	if e := os.WriteFile(p, []byte("SWSV_TOKEN=fake-token-only\nSWSV_URL=http://127.0.0.1:9531\nSWSV_NS=demo\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, args, e := LoadConfig([]string{"--env-file", p})
	if e != nil {
		t.Fatal(e)
	}
	if c.Token != "fake-token-only" || c.URL != "http://127.0.0.1:9531" || len(args) != 0 {
		t.Fatal("env file values were not loaded")
	}
}
