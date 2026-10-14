package config

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	DataDir, ListenAddr, PublicBaseURL string
	TrustedProxyCIDRs                  []string
}

func Load() (Config, error) {
	d := strings.TrimSpace(os.Getenv("SWSV_DATA_DIR"))
	if d == "" {
		d = "./data"
	}
	a := strings.TrimSpace(os.Getenv("SWSV_LISTEN"))
	if a == "" {
		a = "127.0.0.1:9531"
	}
	b := strings.TrimRight(strings.TrimSpace(os.Getenv("SWSV_PUBLIC_BASE_URL")), "/")
	var p []string
	for _, v := range strings.Split(os.Getenv("SWSV_TRUSTED_PROXY_CIDRS"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			p = append(p, v)
		}
	}
	if strings.Contains(d, "\x00") || d == "." {
		return Config{}, errors.New("invalid data directory")
	}
	return Config{d, a, b, p}, nil
}
