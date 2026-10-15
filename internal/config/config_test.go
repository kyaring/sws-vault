package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAndDataDirOverride(t *testing.T) {
	for _, k := range []string{"SWSV_CONFIG", "SWSV_DATA_DIR", "SWSV_DB_PATH", "SWSV_MASTER_KEY_PATH", "SWSV_LISTEN", "SWSV_PUBLIC_BASE_URL", "SWSV_TRUSTED_PROXY_CIDRS"} {
		t.Setenv(k, "")
	}
	c, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	if c.DBPath != "/var/lib/sws-vault/vault.db" || c.MasterKeyPath != "/etc/sws-vault/master.key" || c.ListenAddr != "127.0.0.1:9531" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	d := filepath.Join(t.TempDir(), "vault-data")
	t.Setenv("SWSV_DATA_DIR", d)
	c, e = Load()
	if e != nil {
		t.Fatal(e)
	}
	if c.DBPath != filepath.Join(d, "vault.db") || c.MasterKeyPath != filepath.Join(d, "master.key") {
		t.Fatalf("data dir override failed: %+v", c)
	}
}
func TestConfigFileAndEnvOverride(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	if e := os.WriteFile(p, []byte("SWSV_LISTEN=127.0.0.1:9999\nSWSV_PUBLIC_BASE_URL=https://vault.example.invalid/\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SWSV_CONFIG", p)
	t.Setenv("SWSV_LISTEN", "127.0.0.1:8888")
	c, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	if c.ListenAddr != "127.0.0.1:8888" || c.PublicBaseURL != "https://vault.example.invalid" {
		t.Fatalf("config precedence failed: %+v", c)
	}
}
