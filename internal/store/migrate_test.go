package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestMigrationIsIdempotentAndCreatesUnassignedNamespace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	var n, version int
	if err := s.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name='_unassigned'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("unassigned namespace rows=%d, want 1", n)
	}
	if err := s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("schema version=%d, want 2", version)
	}
}

func TestMigrationAddsTOTPColumnsWithoutDowngradingExistingAdmin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version(version) VALUES(1); CREATE TABLE admins(id INTEGER PRIMARY KEY CHECK(id=1),password_hash BLOB NOT NULL,password_salt BLOB NOT NULL,totp_secret BLOB NOT NULL,created_at TEXT NOT NULL); INSERT INTO admins(id,password_hash,password_salt,totp_secret,created_at) VALUES(1,X'01',X'02',X'03','2026-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var enrolled, mustChange int
	var secret, pending []byte
	var expires string
	if err := s.DB.QueryRow(`SELECT totp_enrolled,must_change_password,totp_secret,pending_totp_secret,pending_totp_expires FROM admins WHERE id=1`).Scan(&enrolled, &mustChange, &secret, &pending, &expires); err != nil {
		t.Fatal(err)
	}
	if enrolled != 1 || mustChange != 0 || string(secret) != string([]byte{3}) || len(pending) != 0 || expires != "" {
		t.Fatalf("legacy admin migration changed state: enrolled=%d must_change=%d secret=%v pending=%v expires=%q", enrolled, mustChange, secret, pending, expires)
	}
}
