package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type credentialMeta struct {
	ID       string `json:"id"`
	NS       string `json:"ns"`
	Provider string `json:"provider"`
	Bindings struct {
		Hosts        []string `json:"hosts"`
		Username     string   `json:"username"`
		AllowResolve bool     `json:"allow_resolve"`
	} `json:"bindings"`
	Status string `json:"status"`
}

func GitCredential(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: git-credential get|store|erase")
	}
	if args[0] == "store" || args[0] == "erase" {
		return nil
	}
	if args[0] != "get" {
		return errors.New("unknown git credential operation")
	}
	c, _, e := LoadConfig(args[1:])
	if e != nil {
		return e
	}
	input := map[string]string{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			input[k] = v
		}
	}
	if e = sc.Err(); e != nil {
		return e
	}
	host := input["host"]
	if host == "" {
		return nil
	}
	status, b, e := c.Request("GET", "/v1/secrets?ns="+c.Namespace, nil)
	if e != nil {
		return e
	}
	if status != 200 {
		return fmt.Errorf("credential list failed with HTTP %d", status)
	}
	var result struct {
		Secrets []credentialMeta `json:"secrets"`
	}
	if json.Unmarshal(b, &result) != nil {
		return errors.New("invalid metadata response")
	}
	for _, m := range result.Secrets {
		if m.Status != "active" || !m.Bindings.AllowResolve || (m.Provider != "github-pat" && m.Provider != "gitea-token") {
			continue
		}
		matched := false
		for _, h := range m.Bindings.Hosts {
			if strings.EqualFold(h, host) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		v, e := c.Resolve("vault:" + m.NS + "/" + m.ID)
		if e != nil {
			return e
		}
		user := m.Bindings.Username
		if user == "" {
			user = "x-access-token"
		}
		fmt.Fprintf(os.Stdout, "username=%s\npassword=%s\n\n", user, v)
		return nil
	}
	return nil
}
