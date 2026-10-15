package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func GenerateTOTP(secret []byte, at time.Time) string {
	step := uint64(at.Unix() / 30)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], step)
	m := hmac.New(sha1.New, secret)
	m.Write(b[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 15
	n := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", n)
}
func VerifyTOTP(secret []byte, code string, at time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	center := at.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		step := center + d
		if step <= lastStep {
			continue
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(step))
		m := hmac.New(sha1.New, secret)
		m.Write(b[:])
		sum := m.Sum(nil)
		off := sum[len(sum)-1] & 15
		n := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
		if code == fmt.Sprintf("%06d", n) {
			return step, true
		}
	}
	return 0, false
}
func NewTOTPSecret() ([]byte, string, error) {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		return nil, "", e
	}
	return b, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
