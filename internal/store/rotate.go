package store

import (
	"database/sql"
	"fmt"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
)

// RotateKEK creates a new versioned master key and transactionally re-wraps every DEK.
// Old key files are intentionally retained so interrupted migrations remain recoverable.
func (s *Store) RotateKEK(r *vaultcrypto.Keyring, dir string) error {
	if _, err := r.Rotate(dir); err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id,ns,dek_wrapped,key_version FROM secrets`)
	if err != nil {
		return err
	}
	type row struct {
		id, ns  string
		wrapped []byte
		version uint32
	}
	var all []row
	for rows.Next() {
		var v row
		if err = rows.Scan(&v.id, &v.ns, &v.wrapped, &v.version); err != nil {
			rows.Close()
			return err
		}
		all = append(all, v)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, v := range all {
		aad := []byte(v.ns + "/" + v.id + "/dek")
		dek, e := r.Unwrap(v.version, v.wrapped, aad)
		if e != nil {
			return fmt.Errorf("unwrap DEK for %s: %w", v.id, e)
		}
		wrapped, e := r.Wrap(r.Current, dek, aad)
		for i := range dek {
			dek[i] = 0
		}
		if e != nil {
			return e
		}
		if _, e = tx.Exec(`UPDATE secrets SET dek_wrapped=?,key_version=? WHERE id=?`, wrapped, r.Current, v.id); e != nil {
			return e
		}
	}
	return tx.Commit()
}

var _ *sql.DB
