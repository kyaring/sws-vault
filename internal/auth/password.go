package auth

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

const PasswordIterations = 600000

func HashPassword(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, PasswordIterations, 32)
}
