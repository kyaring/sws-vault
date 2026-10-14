package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

const KeySize = 32

func Random(n int) ([]byte, error) {
	if n < 1 || n > 1<<20 {
		return nil, errors.New("invalid random length")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(rand.Reader, b)
	return b, e
}
func NewKey() ([]byte, error) { return Random(KeySize) }
func Seal(key, plain, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key length")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n, e := Random(g.NonceSize())
	if e != nil {
		return nil, e
	}
	return append(n, g.Seal(nil, n, plain, aad)...), nil
}
func Open(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key length")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(ciphertext) < g.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return g.Open(nil, ciphertext[:g.NonceSize()], ciphertext[g.NonceSize():], aad)
}
func Fingerprint(key, value []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("sws-vault/fingerprint/v1\x00"))
	m.Write(value)
	return hex(m.Sum(nil)[:6])
}
func hex(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, len(b)*2)
	for i, v := range b {
		o[2*i] = h[v>>4]
		o[2*i+1] = h[v&15]
	}
	return string(o)
}
func Encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
