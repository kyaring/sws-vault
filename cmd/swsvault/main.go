package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	if len(args) > 0 && args[0] == "create" {
		return errors.New("client create not yet available")
	}
	return errors.New("usage: client create")
}
