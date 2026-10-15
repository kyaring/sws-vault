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
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);CREATE TABLE IF NOT EXISTS namespaces(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,created_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,ns TEXT NOT NULL REFERENCES namespaces(name),name TEXT NOT NULL,token_hash BLOB NOT NULL UNIQUE,scopes TEXT NOT NULL,cidrs TEXT NOT NULL DEFAULT '',expires_at TEXT NOT NULL DEFAULT '',disabled INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,ns TEXT NOT NULL REFERENCES namespaces(name),label TEXT NOT NULL,provider TEXT NOT NULL,type TEXT NOT NULL,username TEXT NOT NULL DEFAULT '',ciphertext BLOB NOT NULL,dek_wrapped BLOB NOT NULL,key_version INTEGER NOT NULL,preview TEXT NOT NULL,fingerprint TEXT NOT NULL,bindings TEXT NOT NULL,allowed_clients TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'active',created_at TEXT NOT NULL,rotated_at TEXT NOT NULL,last_used_at TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS intents(token_hash BLOB PRIMARY KEY,ns TEXT NOT NULL,label TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,ns TEXT NOT NULL DEFAULT '',secret_id TEXT NOT NULL DEFAULT '',action TEXT NOT NULL,target_host TEXT NOT NULL DEFAULT '',result TEXT NOT NULL,source_ip TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY CHECK(id=1),password_hash BLOB NOT NULL,password_salt BLOB NOT NULL,totp_secret BLOB NOT NULL,created_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS sessions(token_hash BLOB PRIMARY KEY,csrf_hash BLOB NOT NULL,created_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,expires_at TEXT NOT NULL);`)
	if e != nil {
		return e
	}
	// Idempotent additive migration for browser-based TOTP enrollment.
	cols := map[string]bool{}
	rows, err := s.DB.Query(`PRAGMA table_info(admins)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for name, ddl := range map[string]string{
		"totp_enrolled":        `ALTER TABLE admins ADD COLUMN totp_enrolled INTEGER NOT NULL DEFAULT 1`,
		"must_change_password": `ALTER TABLE admins ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`,
		"pending_totp_secret":  `ALTER TABLE admins ADD COLUMN pending_totp_secret BLOB`,
		"pending_totp_expires": `ALTER TABLE admins ADD COLUMN pending_totp_expires TEXT NOT NULL DEFAULT ''`,
	} {
		if !cols[name] {
			if _, err := s.DB.Exec(ddl); err != nil {
				return err
			}
		}
	}
	if err := addColumnsIfMissing(s.DB, "namespaces", [][2]string{
		{"description", `ALTER TABLE namespaces ADD COLUMN description TEXT NOT NULL DEFAULT ''`},
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(s.DB, "clients", [][2]string{
		{"note", `ALTER TABLE clients ADD COLUMN note TEXT NOT NULL DEFAULT ''`},
	}); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`UPDATE schema_version SET version=2 WHERE version<2; INSERT INTO namespaces(id,name,created_at) VALUES('_unassigned','_unassigned',strftime('%Y-%m-%dT%H:%M:%SZ','now')) ON CONFLICT(name) DO NOTHING`); err != nil {
		return err
	}
	return nil
}

// addColumnsIfMissing 幂等地补齐列：只在 PRAGMA table_info 里没有该列时才 ALTER。
// 旧库升级后原有行不变（新列取 DEFAULT），重复执行不报错。
func addColumnsIfMissing(db *sql.DB, table string, columns [][2]string) error {
	present := map[string]bool{}
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		present[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, column := range columns {
		if present[column[0]] {
			continue
		}
		if _, err := db.Exec(column[1]); err != nil {
			return err
		}
	}
	return nil
}
