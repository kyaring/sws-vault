package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/kyaring/sws-vault/internal/auth"
	"io"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/kyaring/sws-vault/internal/api"
	vaultcli "github.com/kyaring/sws-vault/internal/cli"
	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
)

var commit = "dev"
var serveServer = func(s *api.Server) error { return s.Serve() }

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "swsvault:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	var ce error
	args, ce = extractConfigFlag(args)
	if ce != nil {
		return ce
	}
	if len(args) == 0 {
		return errors.New("usage: swsvault <serve|keygen|admin|client|run|capture|git-credential|version>")
	}
	switch args[0] {
	case "version":
		fmt.Println(versionText())
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
		return vaultcli.Capture(args[1:])
	case "run":
		return vaultcli.Run(args[1:])
	case "git-credential":
		return vaultcli.GitCredential(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("out", "", "key file path")
	if e := fs.Parse(args); e != nil {
		return e
	}
	c, e := config.Load()
	if e != nil {
		return e
	}
	if *path == "" {
		*path = c.MasterKeyPath
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
	p := c.MasterKeyPath
	st, e := os.Stat(p)
	if e != nil {
		return fmt.Errorf("master key unavailable: %w", e)
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("master key permissions must be 0600 or stricter")
	}
	ring, e := vaultcrypto.LoadKeyringAt(c.MasterKeyPath)
	if e != nil {
		return e
	}
	s, e := store.Open(c.DBPath)
	if e != nil {
		return e
	}
	defer s.Close()
	return serveServer(api.NewWithKeyring(c, s, ring))
}
func admin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: admin init|reset-totp|rotate-kek")
	}
	switch args[0] {
	case "init":
		return adminInit(false)
	case "reset-totp":
		return adminInit(true)
	case "rotate-kek":
		return adminRotateKEK()
	default:
		return errors.New("usage: admin init|reset-totp|rotate-kek")
	}
}
func adminInit(reset bool) error {
	c, e := config.Load()
	if e != nil {
		return e
	}
	st, e := store.Open(c.DBPath)
	if e != nil {
		return e
	}
	defer st.Close()
	var oldHash, oldSalt []byte
	found := st.DB.QueryRow(`SELECT password_hash,password_salt FROM admins WHERE id=1`).Scan(&oldHash, &oldSalt) == nil
	if found && !reset {
		return errors.New("admin already initialized")
	}
	if !found && reset {
		return errors.New("admin not initialized")
	}
	r := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "管理员密码（至少 12 字符）: ")
	a, e := readPassword(r)
	if e != nil {
		return e
	}
	if reset {
		got, e := auth.HashPassword(a, oldSalt)
		if e != nil || subtle.ConstantTimeCompare(got, oldHash) != 1 {
			return errors.New("密码验证失败")
		}
	} else {
		fmt.Fprint(os.Stderr, "再次输入密码: ")
		b, e := readPassword(r)
		if e != nil {
			return e
		}
		if len(a) < 12 || a != b {
			return errors.New("密码不匹配或长度不足")
		}
	}
	secret, encoded, e := auth.NewTOTPSecret()
	if e != nil {
		return e
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if reset {
		_, e = st.DB.Exec(`UPDATE admins SET totp_secret=? WHERE id=1`, secret)
	} else {
		salt := make([]byte, 16)
		if _, e = rand.Read(salt); e != nil {
			return e
		}
		hash, e := auth.HashPassword(a, salt)
		if e != nil {
			return e
		}
		_, e = st.DB.Exec(`INSERT INTO admins(id,password_hash,password_salt,totp_secret,created_at) VALUES(1,?,?,?,?)`, hash, salt, secret, now)
	}
	if e != nil {
		return e
	}
	_, _ = st.DB.Exec(`CREATE TABLE IF NOT EXISTS admin_state(id INTEGER PRIMARY KEY CHECK(id=1),failed_count INTEGER NOT NULL DEFAULT 0,locked_until TEXT NOT NULL DEFAULT '',last_totp_step INTEGER NOT NULL DEFAULT -1)`)
	action := "admin-init"
	if reset {
		action = "totp-reset"
	}
	_, _ = st.DB.Exec(`INSERT INTO audit(at,actor,action,result,source_ip) VALUES(?,?,?,?,?)`, now, "admin", action, "ok", "local")
	if reset {
		_, _ = st.DB.Exec(`UPDATE admin_state SET failed_count=0,locked_until='',last_totp_step=-1 WHERE id=1`)
	}
	fmt.Fprintln(os.Stdout, "otpauth://totp/"+url.QueryEscape("SWS Vault:admin")+"?secret="+encoded+"&issuer=SWS%20Vault&digits=6&period=30")
	for i := range secret {
		secret[i] = 0
	}
	return nil
}
func readPassword(r *bufio.Reader) (string, error) {
	st, e := os.Stdin.Stat()
	terminal := e == nil && st.Mode()&os.ModeCharDevice != 0
	if terminal {
		if e = toggleEcho(false); e != nil {
			return "", e
		}
		defer toggleEcho(true)
	}
	v, e := readLine(r)
	if terminal {
		fmt.Fprintln(os.Stderr)
	}
	return v, e
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
	db, e := sql.Open("sqlite", c.DBPath)
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
	_, _ = db.Exec(`INSERT INTO audit(at,actor,ns,action,result,source_ip) VALUES(?,?,?,?,?,?)`, now, "admin", *ns, "client-create", "ok", "local")
	fmt.Println(token)
	for i := range raw {
		raw[i] = 0
	}
	return nil
}

func toggleEcho(on bool) error {
	mode := "-echo"
	if on {
		mode = "echo"
	}
	cmd := exec.Command("stty", mode)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
func versionText() string {
	if commit != "dev" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, v := range info.Settings {
			if v.Key == "vcs.revision" && v.Value != "" {
				return v.Value
			}
		}
	}
	return commit
}

func adminRotateKEK() error {
	if os.Geteuid() != 0 {
		return errors.New("rotate-kek is restricted to root")
	}
	c, e := config.Load()
	if e != nil {
		return e
	}
	ring, e := vaultcrypto.LoadKeyringAt(c.MasterKeyPath)
	if e != nil {
		return e
	}
	st, e := store.Open(c.DBPath)
	if e != nil {
		return e
	}
	defer st.Close()
	if e = st.RotateKEK(ring, filepath.Dir(c.MasterKeyPath)); e != nil {
		return e
	}
	_, _ = st.DB.Exec(`INSERT INTO audit(at,actor,action,result,source_ip) VALUES(?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), "admin", "key-rotate", "ok", "local")
	fmt.Printf("master key version rotated to %d\n", ring.Current)
	return nil
}

func extractConfigFlag(args []string) ([]string, error) {
	out := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			out = append(out, args[i:]...)
			break
		}
		if args[i] == "--config" {
			if i+1 >= len(args) {
				return nil, errors.New("--config requires a path")
			}
			if e := os.Setenv("SWSV_CONFIG", args[i+1]); e != nil {
				return nil, e
			}
			i++
			continue
		}
		if strings.HasPrefix(args[i], "--config=") {
			if e := os.Setenv("SWSV_CONFIG", strings.TrimPrefix(args[i], "--config=")); e != nil {
				return nil, e
			}
			continue
		}
		out = append(out, args[i])
	}
	return out, nil
}

func validIdentifier(v string) bool {
	if len(v) < 1 || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
