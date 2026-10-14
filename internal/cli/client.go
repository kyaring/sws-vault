package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct{ URL, Token, Namespace string }

func LoadConfig(args []string) (Config, []string, error) {
	values := map[string]string{"SWSV_URL": os.Getenv("SWSV_URL"), "SWSV_TOKEN": os.Getenv("SWSV_TOKEN"), "SWSV_NS": os.Getenv("SWSV_NS")}
	out := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--env-file" {
			if i+1 >= len(args) {
				return Config{}, nil, errors.New("--env-file requires a path")
			}
			p := args[i+1]
			i++
			st, e := os.Stat(p)
			if e != nil {
				return Config{}, nil, e
			}
			if st.Mode().Perm() != 0600 {
				return Config{}, nil, errors.New("env file permissions must be 0600 or stricter")
			}
			b, e := os.ReadFile(p)
			if e != nil {
				return Config{}, nil, e
			}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					return Config{}, nil, errors.New("invalid env file")
				}
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				if k == "SWSV_URL" || k == "SWSV_TOKEN" || k == "SWSV_NS" {
					values[k] = v
				}
			}
		} else {
			out = append(out, args[i])
		}
	}
	c := Config{URL: strings.TrimRight(values["SWSV_URL"], "/"), Token: values["SWSV_TOKEN"], Namespace: values["SWSV_NS"]}
	if c.URL == "" {
		c.URL = "http://127.0.0.1:9531"
	}
	if c.Token == "" {
		return Config{}, nil, errors.New("SWSV_TOKEN is required")
	}
	if c.Namespace == "" {
		c.Namespace = "default"
	}
	return c, out, nil
}
func (c Config) Request(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return 0, nil, e
		}
		rd = bytes.NewReader(b)
	}
	req, e := http.NewRequest(method, c.URL+path, rd)
	if e != nil {
		return 0, nil, e
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cl := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := cl.Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, b, e
}
func (c Config) Resolve(ref string) (string, error) {
	status, b, e := c.Request("POST", "/v1/resolve", map[string]string{"secret": ref})
	if e != nil {
		return "", e
	}
	if status != 200 {
		return "", fmt.Errorf("resolve failed with HTTP %d", status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if e = json.Unmarshal(b, &out); e != nil {
		return "", errors.New("invalid resolve response")
	}
	return out.Value, nil
}
