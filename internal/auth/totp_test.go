package auth

import (
	"testing"
	"time"
)

func TestTOTPReplayRejected(t *testing.T) {
	secret := []byte("fake test secret only")
	now := time.Unix(1800000000, 0)
	code := GenerateTOTP(secret, now)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok = VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
}
