package vaultcrypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Keyring struct {
	Current  uint32
	Keys     map[uint32][]byte
	BasePath string
}

func LoadKeyring(dir string) (*Keyring, error) {
	return LoadKeyringAt(filepath.Join(dir, "master.key"))
}
func LoadKeyringAt(base string) (*Keyring, error) {
	r := &Keyring{Keys: map[uint32][]byte{}, BasePath: base}
	dir := filepath.Dir(base)
	bn := filepath.Base(base)
	paths := []string{base}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	for _, ent := range entries {
		n := ent.Name()
		prefix := bn + ".v"
		if strings.HasPrefix(n, prefix) {
			v, er := strconv.ParseUint(strings.TrimPrefix(n, prefix), 10, 32)
			if er == nil && v > 1 {
				paths = append(paths, filepath.Join(dir, n))
			}
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		v := uint32(1)
		if p != base {
			u, er := strconv.ParseUint(strings.TrimPrefix(filepath.Base(p), bn+".v"), 10, 32)
			if er != nil || u < 2 {
				continue
			}
			v = uint32(u)
		}
		st, er := os.Stat(p)
		if er != nil {
			return nil, er
		}
		if st.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("key file permissions must be 0600: %s", filepath.Base(p))
		}
		raw, er := os.ReadFile(p)
		if er != nil {
			return nil, er
		}
		k, er := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if er != nil || len(k) != KeySize {
			return nil, fmt.Errorf("invalid key file: %s", filepath.Base(p))
		}
		r.Keys[v] = k
		if v > r.Current {
			r.Current = v
		}
	}
	if r.Current == 0 {
		return nil, errors.New("no master key found")
	}
	return r, nil
}
func (r *Keyring) Rotate(dir string) (uint32, error) {
	if r == nil || r.Current == 0 {
		return 0, errors.New("keyring unavailable")
	}
	next := r.Current + 1
	k, e := NewKey()
	if e != nil {
		return 0, e
	}
	base := r.BasePath
	if base == "" {
		base = filepath.Join(dir, "master.key")
	}
	p := fmt.Sprintf("%s.v%d", base, next)
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		wipe(k)
		return 0, e
	}
	_, we := f.Write([]byte(base64.RawStdEncoding.EncodeToString(k) + "\n"))
	ce := f.Close()
	if we != nil || ce != nil {
		os.Remove(p)
		wipe(k)
		if we != nil {
			return 0, we
		}
		return 0, ce
	}
	r.Keys[next] = k
	r.Current = next
	return next, nil
}
func (r *Keyring) Wrap(version uint32, dek, aad []byte) ([]byte, error) {
	k := r.Keys[version]
	derived, e := DeriveKey(k, "kek-wrap")
	if e != nil {
		return nil, e
	}
	defer wipe(derived)
	return Seal(derived, dek, aad)
}
func (r *Keyring) Unwrap(version uint32, wrapped, aad []byte) ([]byte, error) {
	k := r.Keys[version]
	derived, e := DeriveKey(k, "kek-wrap")
	if e != nil {
		return nil, e
	}
	defer wipe(derived)
	return Open(derived, wrapped, aad)
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
