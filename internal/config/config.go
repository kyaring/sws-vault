package config

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DataDir, DBPath, MasterKeyPath, ListenAddr, PublicBaseURL string
	TrustedProxyCIDRs                                         []string
	RateLimitPerMinute                                        int
}

func Load() (Config, error) {
	v := map[string]string{"SWSV_DATA_DIR": "/var/lib/sws-vault", "SWSV_DB_PATH": "/var/lib/sws-vault/vault.db", "SWSV_MASTER_KEY_PATH": "/etc/sws-vault/master.key", "SWSV_LISTEN": "127.0.0.1:9531", "SWSV_PUBLIC_BASE_URL": "", "SWSV_TRUSTED_PROXY_CIDRS": "", "SWSV_RATE_LIMIT_PER_MINUTE": "60"}
	cfg := strings.TrimSpace(os.Getenv("SWSV_CONFIG"))
	if cfg != "" {
		f, e := os.Open(cfg)
		if e != nil {
			return Config{}, e
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, x, ok := strings.Cut(line, "=")
			if !ok {
				f.Close()
				return Config{}, errors.New("invalid config line")
			}
			k = strings.TrimSpace(k)
			if _, ok = v[k]; ok {
				v[k] = strings.TrimSpace(x)
			}
		}
		e = sc.Err()
		f.Close()
		if e != nil {
			return Config{}, e
		}
	}
	for k := range v {
		if x, ok := os.LookupEnv(k); ok && (strings.TrimSpace(x) != "" || k == "SWSV_PUBLIC_BASE_URL") {
			v[k] = strings.TrimSpace(x)
		}
	}
	d := v["SWSV_DATA_DIR"]
	db := v["SWSV_DB_PATH"]
	master := v["SWSV_MASTER_KEY_PATH"]
	if d != "/var/lib/sws-vault" {
		if db == "/var/lib/sws-vault/vault.db" {
			db = d + "/vault.db"
		}
		if master == "/etc/sws-vault/master.key" {
			master = d + "/master.key"
		}
	}
	if db == "" {
		db = d + "/vault.db"
	}
	if d == "" || db == "" || master == "" || strings.ContainsAny(d+db+master, "\x00") {
		return Config{}, errors.New("invalid paths")
	}
	limit, e := strconv.Atoi(v["SWSV_RATE_LIMIT_PER_MINUTE"])
	if e != nil || limit < 1 || limit > 10000 {
		return Config{}, errors.New("invalid rate limit")
	}
	var proxies []string
	for _, p := range strings.Split(v["SWSV_TRUSTED_PROXY_CIDRS"], ",") {
		if p = strings.TrimSpace(p); p != "" {
			proxies = append(proxies, p)
		}
	}
	return Config{DataDir: d, DBPath: db, MasterKeyPath: master, ListenAddr: v["SWSV_LISTEN"], PublicBaseURL: strings.TrimRight(v["SWSV_PUBLIC_BASE_URL"], "/"), TrustedProxyCIDRs: proxies, RateLimitPerMinute: limit}, nil
}
