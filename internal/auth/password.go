package auth

import "golang.org/x/crypto/argon2"

const Argon2Time uint32 = 3
const Argon2Memory uint32 = 64 * 1024
const Argon2Threads uint8 = 2
const PasswordKeyLen uint32 = 32

func HashPassword(password string, salt []byte) ([]byte, error) {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, PasswordKeyLen), nil
}
