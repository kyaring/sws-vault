package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kyaring/sws-vault/internal/api"
	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
)

var commit = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "swsvault:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: swsvault <serve|keygen|admin|client|run|capture|git-credential|version>")
	}
	switch args[0] {
	case "version":
		fmt.Println(commit)
		return nil
	case "keygen":
		return keygen(args[1:])
	case "serve":
		return serve()
	case "admin":
		return admin(args[1:])
	case "client":
		return client(args[1:])
	case "capture":
		return errors.New("capture not yet available")
	case "run":
		return errors.New("run not yet available")
	case "git-credential":
		if len(args) > 1 && (args[1] == "store" || args[1] == "erase") {
			return nil
		}
		return errors.New("credential lookup not yet available")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("out", "master.key", "key file path")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if _, e := os.Lstat(*path); e == nil {
		return errors.New("key file already exists")
	}
	k, e := vaultcrypto.NewKey()
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(*path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, we := f.Write([]byte(base64.RawStdEncoding.EncodeToString(k) + "\n"))
	ce := f.Close()
	for i := range k {
		k[i] = 0
	}
	if we != nil {
		return we
	}
	return ce
}
func serve() error {
	c, e := config.Load()
	if e != nil {
		return e
	}
	if e = os.MkdirAll(c.DataDir, 0700); e != nil {
		return e
	}
	p := filepath.Join(c.DataDir, "master.key")
	st, e := os.Stat(p)
	if e != nil {
		return fmt.Errorf("master key unavailable: %w", e)
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("master key permissions must be 0600 or stricter")
	}
	ring, e := vaultcrypto.LoadKeyring(c.DataDir)
	if e != nil {
		return e
	}
	s, e := store.Open(filepath.Join(c.DataDir, "vault.db"))
	if e != nil {
		return e
	}
	defer s.Close()
	return api.NewWithKeyring(c, s, ring).Serve()
}
func admin(args []string) error {
	if len(args) == 0 || (args[0] != "init" && args[0] != "reset-totp") {
		return errors.New("usage: admin init|reset-totp")
	}
	return adminInit()
}
func adminInit() error {
	r := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "密码（至少 12 字符）: ")
	a, e := readLine(r)
	if e != nil {
		return e
	}
	fmt.Fprint(os.Stderr, "再次输入密码: ")
	b, e := readLine(r)
	if e != nil {
		return e
	}
	if len(a) < 12 || a != b {
		return errors.New("密码不匹配或长度不足")
	}
	secret := make([]byte, 20)
	if _, e = rand.Read(secret); e != nil {
		return e
	}
	return errors.New("admin bootstrap not yet available")
}
func readLine(r *bufio.Reader) (string, error) {
	s, e := r.ReadString('\n')
	if e != nil && e != io.EOF {
		return "", e
	}
	return strings.TrimSpace(s), nil
}
func client(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: client create --ns X --name Y --scopes secrets:list,fetch")
	}
	if os.Geteuid() != 0 {
		return errors.New("client create is restricted to root")
	}
	fs := flag.NewFlagSet("client create", flag.ContinueOnError)
	ns := fs.String("ns", "", "namespace")
	name := fs.String("name", "", "client name")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	cidrs := fs.String("cidrs", "", "optional CIDR allowlist")
	expires := fs.String("expires", "", "optional RFC3339 expiry")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if *ns == "" || *name == "" || *scopes == "" {
		return errors.New("ns, name, and scopes are required")
	}
	allowed := map[string]bool{"secrets:list": true, "secrets:write": true, "fetch": true, "resolve": true, "intents:create": true}
	for _, v := range strings.Split(*scopes, ",") {
		if !allowed[strings.TrimSpace(v)] {
			return fmt.Errorf("invalid scope %q", v)
		}
	}
	if *expires != "" {
		if _, e := time.Parse(time.RFC3339, *expires); e != nil {
			return errors.New("expiry must be RFC3339")
		}
	}
	c, e := config.Load()
	if e != nil {
		return e
	}
	db, e := sql.Open("sqlite", filepath.Join(c.DataDir, "vault.db"))
	if e != nil {
		return e
	}
	defer db.Close()
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		return e
	}
	token := "swsv_" + base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	idb := make([]byte, 16)
	if _, e = rand.Read(idb); e != nil {
		return e
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, e = db.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, hex.EncodeToString(idb), *ns, now); e != nil {
		return e
	}
	_, e = db.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,cidrs,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, hex.EncodeToString(idb), *ns, *name, h[:], *scopes, *cidrs, *expires, now)
	if e != nil {
		return e
	}
	fmt.Println(token)
	for i := range raw {
		raw[i] = 0
	}
	return nil
}
