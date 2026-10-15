package store

import (
	"fmt"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
)

func (s *Store) RotateKEK(r *vaultcrypto.Keyring, dir string) error {
	if _, e := r.Rotate(dir); e != nil {
		return e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.Query(`SELECT id,ns,type,ciphertext,dek_wrapped,key_version FROM secrets`)
	if e != nil {
		return e
	}
	type row struct {
		id, ns, typ string
		ct, wrapped []byte
		version     uint32
	}
	var all []row
	for rows.Next() {
		var v row
		if e = rows.Scan(&v.id, &v.ns, &v.typ, &v.ct, &v.wrapped, &v.version); e != nil {
			rows.Close()
			return e
		}
		all = append(all, v)
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return e
	}
	rows.Close()
	for _, v := range all {
		dek, e := r.Unwrap(v.version, v.wrapped, vaultcrypto.DEKAAD(v.ns, v.id, v.version))
		if e != nil {
			return fmt.Errorf("unwrap DEK for %s: %w", v.id, e)
		}
		plain, e := vaultcrypto.Open(dek, v.ct, vaultcrypto.SecretAAD(v.ns, v.id, v.typ, v.version))
		if e != nil {
			for i := range dek {
				dek[i] = 0
			}
			return fmt.Errorf("decrypt secret for %s: %w", v.id, e)
		}
		newCT, e := vaultcrypto.Seal(dek, plain, vaultcrypto.SecretAAD(v.ns, v.id, v.typ, r.Current))
		fpKey, fe := vaultcrypto.DeriveKey(r.Keys[r.Current], "fingerprint")
		if fe != nil {
			for i := range plain {
				plain[i] = 0
			}
			for i := range dek {
				dek[i] = 0
			}
			return fe
		}
		fp := vaultcrypto.Fingerprint(fpKey, plain)
		for i := range fpKey {
			fpKey[i] = 0
		}
		for i := range plain {
			plain[i] = 0
		}
		if e != nil {
			for i := range dek {
				dek[i] = 0
			}
			return e
		}
		newWrapped, e := r.Wrap(r.Current, dek, vaultcrypto.DEKAAD(v.ns, v.id, r.Current))
		for i := range dek {
			dek[i] = 0
		}
		if e != nil {
			return e
		}
		if _, e = tx.Exec(`UPDATE secrets SET ciphertext=?,dek_wrapped=?,key_version=?,fingerprint=? WHERE id=?`, newCT, newWrapped, r.Current, fp, v.id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
