package vaultcrypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

func DeriveKey(master []byte, purpose string) ([]byte, error) {
	if len(master) != KeySize || purpose == "" {
		return nil, errors.New("invalid key derivation input")
	}
	return hkdf.Key(sha256.New, master, nil, "sws-vault/v1/"+purpose, KeySize)
}
func SecretAAD(ns, id, typ string, version uint32) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%d", ns, id, typ, version))
}
func DEKAAD(ns, id string, version uint32) []byte {
	return []byte(fmt.Sprintf("%s|%s|dek|%d", ns, id, version))
}
