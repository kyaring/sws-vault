package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func Capture(args []string) error {
	c, args, e := LoadConfig(args)
	if e != nil {
		return e
	}
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	ns := fs.String("ns", c.Namespace, "namespace")
	label := fs.String("label", "", "label")
	prov := fs.String("provider", "generic", "provider")
	username := fs.String("username", "", "username")
	if e = fs.Parse(args); e != nil {
		return e
	}
	if *ns == "" || *label == "" {
		return errors.New("--ns and --label are required")
	}
	v, e := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
	if e != nil {
		return e
	}
	if len(v) == 0 || len(v) > 1<<20 {
		return errors.New("stdin value is empty or too large")
	}
	body := map[string]any{"ns": *ns, "label": *label, "provider": *prov, "type": "token", "value": strings.TrimSuffix(string(v), "\n"), "username": *username}
	for i := range v {
		v[i] = 0
	}
	status, b, e := c.Request("POST", "/v1/secrets", body)
	if e != nil {
		return e
	}
	if status != 201 {
		return fmt.Errorf("capture failed with HTTP %d", status)
	}
	var result struct {
		ID      string `json:"id"`
		Preview string `json:"preview"`
	}
	if json.Unmarshal(b, &result) != nil {
		return errors.New("invalid metadata response")
	}
	fmt.Printf("id=%s preview=%s\n", result.ID, result.Preview)
	return nil
}
