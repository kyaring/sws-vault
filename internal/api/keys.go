package api

import vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"

func (s *Server) wrapDEK(ns, id string, version uint32, dek []byte) ([]byte, error) {
	k, e := vaultcrypto.DeriveKey(s.Keys[version], "kek-wrap")
	if e != nil {
		return nil, e
	}
	defer wipe(k)
	return vaultcrypto.Seal(k, dek, vaultcrypto.DEKAAD(ns, id, version))
}
func (s *Server) unwrapDEK(ns, id string, version uint32, wrapped []byte) ([]byte, error) {
	k, e := vaultcrypto.DeriveKey(s.Keys[version], "kek-wrap")
	if e != nil {
		return nil, e
	}
	defer wipe(k)
	return vaultcrypto.Open(k, wrapped, vaultcrypto.DEKAAD(ns, id, version))
}
func (s *Server) fingerprint(value []byte) (string, error) {
	k, e := vaultcrypto.DeriveKey(s.Keys[s.Current], "fingerprint")
	if e != nil {
		return "", e
	}
	defer wipe(k)
	return vaultcrypto.Fingerprint(k, value), nil
}
