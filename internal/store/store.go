package store

import (
	"database/sql"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
)

type Store struct {
	DB   *sql.DB
	Path string
}

func Open(path string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); e != nil {
		db.Close()
		return nil, e
	}
	s := &Store{db, path}
	if e = s.Migrate(); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Migrate() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS namespaces(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,created_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,ns TEXT NOT NULL REFERENCES namespaces(name),name TEXT NOT NULL,token_hash BLOB NOT NULL UNIQUE,scopes TEXT NOT NULL,cidrs TEXT NOT NULL DEFAULT '',expires_at TEXT NOT NULL DEFAULT '',disabled INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,ns TEXT NOT NULL REFERENCES namespaces(name),label TEXT NOT NULL,provider TEXT NOT NULL,type TEXT NOT NULL,ciphertext BLOB NOT NULL,dek_wrapped BLOB NOT NULL,key_version INTEGER NOT NULL,preview TEXT NOT NULL,fingerprint TEXT NOT NULL,bindings TEXT NOT NULL,allowed_clients TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'active',created_at TEXT NOT NULL,rotated_at TEXT NOT NULL,last_used_at TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS intents(token_hash BLOB PRIMARY KEY,ns TEXT NOT NULL,label TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,ns TEXT NOT NULL DEFAULT '',secret_id TEXT NOT NULL DEFAULT '',action TEXT NOT NULL,target_host TEXT NOT NULL DEFAULT '',result TEXT NOT NULL,source_ip TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY CHECK(id=1),password_hash BLOB NOT NULL,password_salt BLOB NOT NULL,totp_secret BLOB NOT NULL,created_at TEXT NOT NULL);`)
	return e
}
