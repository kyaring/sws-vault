package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	vaultcli "github.com/kyaring/sws-vault/internal/cli"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func adminPageRequest(s *Server, cookie, method, path string, values url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader("")
	if values != nil {
		body = strings.NewReader(values.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	if values != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: cookie})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestUnassignedSecretIsInvisibleAndCannotResolve(t *testing.T) {
	s, st, token, _ := testServer(t, "secrets:list,resolve,secrets:write")
	m, err := s.save(SecretRequest{NS: unassignedNS, Label: "unassigned-fake", Provider: "generic", Type: "token", Value: "SWSV-UNASSIGNED-SENTINEL", Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	code, list := request(t, s, token, http.MethodGet, "/v1/secrets?ns=ns1", "")
	if code != 200 || strings.Contains(list, m.ID) || strings.Contains(list, "unassigned-fake") {
		t.Fatalf("unassigned appeared in list: %d %s", code, list)
	}
	body, _ := json.Marshal(map[string]string{"secret": "vault:_unassigned/" + m.ID})
	code, out := request(t, s, token, http.MethodPost, "/v1/resolve", string(body))
	if code != 404 || strings.Contains(out, "SWSV-UNASSIGNED-SENTINEL") {
		t.Fatalf("unassigned resolve status=%d body=%s", code, out)
	}
	bodyMissing, _ := json.Marshal(map[string]string{"secret": "vault:ns1/nonexistent-id"})
	missingCode, missingOut := request(t, s, token, http.MethodPost, "/v1/resolve", string(bodyMissing))
	if missingCode != 404 || out != missingOut {
		t.Fatalf("unassigned/nonexistent response mismatch: %d %q vs %d %q", code, out, missingCode, missingOut)
	}
	var ns string
	if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, m.ID).Scan(&ns); err != nil || ns != unassignedNS {
		t.Fatalf("namespace=%q err=%v", ns, err)
	}
}
func TestQuickProjectCreatesClientAndMovesOnlySelectedSecrets(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	const sentinel = "SWSV-QUICK-PROJECT-SECRET-SENTINEL"
	selected, err := s.save(SecretRequest{NS: unassignedNS, Label: "selected-fake", Provider: "generic", Type: "token", Value: sentinel, Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	unselected, err := s.save(SecretRequest{NS: unassignedNS, Label: "not-selected-fake", Provider: "generic", Type: "token", Value: "SWSV-UNSELECTED-SENTINEL", Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "quick-project-session", "quick-project-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{"csrf": {csrf}, "project": {"quick-project"}, "client": {"quick-client"}, "secret": {selected.ID}})
	if w.Code != 200 {
		t.Fatalf("quick project status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token result cache-control=%q", w.Header().Get("Cache-Control"))
	}
	if strings.Contains(w.Body.String(), sentinel) || strings.Contains(w.Body.String(), "SWSV-UNSELECTED-SENTINEL") {
		t.Fatal("project result leaked a secret value")
	}
	matches := tokenPattern.FindAllString(w.Body.String(), -1)
	if len(matches) < 1 {
		t.Fatal("one-time token/config not present")
	}
	clientToken := matches[0]
	if strings.Count(w.Body.String(), clientToken) < 2 {
		t.Fatal("token missing from copyable configuration examples")
	}
	var clientNS, clientID string
	var stored []byte
	if err := st.DB.QueryRow(`SELECT ns,id,token_hash FROM clients WHERE name='quick-client'`).Scan(&clientNS, &clientID, &stored); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(clientToken))
	if clientNS != "quick-project" || string(stored) != string(sum[:]) {
		t.Fatalf("client not correctly created: ns=%q", clientNS)
	}
	var selectedNS, unselectedNSGot string
	if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, selected.ID).Scan(&selectedNS); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, unselected.ID).Scan(&unselectedNSGot); err != nil {
		t.Fatal(err)
	}
	if selectedNS != "quick-project" || unselectedNSGot != unassignedNS {
		t.Fatalf("selected=%q unselected=%q", selectedNS, unselectedNSGot)
	}
	body, _ := json.Marshal(map[string]string{"secret": "vault:quick-project/" + selected.ID})
	code, out := requestWithToken(t, s, clientToken, http.MethodPost, "/v1/resolve", string(body))
	if code != 200 || !strings.Contains(out, sentinel) {
		t.Fatalf("selected secret cannot resolve: %d %s", code, out)
	}
	body, _ = json.Marshal(map[string]string{"secret": "vault:quick-project/" + unselected.ID})
	code, out = requestWithToken(t, s, clientToken, http.MethodPost, "/v1/resolve", string(body))
	if code != 404 || strings.Contains(out, "SWSV-UNSELECTED-SENTINEL") {
		t.Fatalf("unselected secret accessible: %d %s", code, out)
	}
	fetchBody, _ := json.Marshal(map[string]any{"secret": "vault:_unassigned/" + unselected.ID, "method": "GET", "url": "https://github.com/"})
	code, out = requestWithToken(t, s, clientToken, http.MethodPost, "/v1/fetch", string(fetchBody))
	if code != 404 || strings.Contains(out, "SWSV-UNSELECTED-SENTINEL") {
		t.Fatalf("outbound fetch exposed unassigned secret: %d %s", code, out)
	}
	second, err := s.save(SecretRequest{NS: unassignedNS, Label: "second-fake", Provider: "generic", Type: "token", Value: "SWSV-SECOND-SECRET", Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{"csrf": {csrf}, "project": {"quick-project"}, "client": {"quick-client-2"}, "secret": {second.ID}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "追加接入") {
		t.Fatalf("existing project should append: %d %s", w.Code, w.Body.String())
	}
	var clientCount int
	if err := st.DB.QueryRow(`SELECT count(*) FROM clients WHERE ns='quick-project'`).Scan(&clientCount); err != nil {
		t.Fatal(err)
	}
	if clientCount != 2 {
		t.Fatalf("project client count=%d", clientCount)
	}
	var auditCount int
	if err := st.DB.QueryRow(`SELECT count(*) FROM audit WHERE actor='admin' AND action='project-client-create' AND ns='quick-project' AND result='ok'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("admin project audit count=%d", auditCount)
	}
	body, _ = json.Marshal(map[string]string{"secret": "vault:quick-project/" + selected.ID})
	code, out = requestWithToken(t, s, clientToken, http.MethodPost, "/v1/resolve", string(body))
	if code != 200 || !strings.Contains(out, sentinel) {
		t.Fatalf("existing client was changed by append: %d %s", code, out)
	}
}

var tokenPattern = regexp.MustCompile(`swsv_[A-Za-z0-9_-]{43}`)

func requestWithToken(t *testing.T, s *Server, token, method, path, body string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}
func TestRenderedPanelHasNoForbiddenLegacyWords(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	secret, err := s.save(SecretRequest{NS: "ns1", Label: "panel-word-secret", Provider: "generic", Type: "token", Value: "FAKE-PANEL-WORD-SECRET", Bindings: Binding{AllowResolve: true, Headers: map[string]string{"Authorization": "Bearer {v}"}}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := "panel-word-session"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: "panel-word-csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	for _, path := range []string{"/admin/", "/admin/advanced", "/admin/advanced/secrets", "/admin/namespaces", "/admin/clients", "/admin/audit", "/admin/intents/new", "/admin/secrets/new", "/admin/secrets/" + secret.ID + "/bindings", "/admin/secrets/" + secret.ID + "/rotate"} {
		w := adminPageRequest(s, cookie, http.MethodGet, path, nil)
		if w.Code != 200 {
			t.Fatalf("%s status=%d", path, w.Code)
		}
		body := strings.ToLower(w.Body.String())
		visible := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(body, " ")
		for _, bad := range []string{"命名空间", "namespace", "绑定"} {
			if strings.Contains(visible, bad) {
				t.Fatalf("%s contains forbidden visible UI text %q: %s", path, bad, visible)
			}
		}
		if regexp.MustCompile(`(?i)\bns\b`).MatchString(visible) {
			t.Fatalf("%s contains visible NS label: %s", path, visible)
		}
	}
}

func TestRunAndGitCredentialCannotUseUnassignedSecrets(t *testing.T) {
	s, _, token, _ := testServer(t, "secrets:list,resolve")
	m, err := s.save(SecretRequest{NS: unassignedNS, Label: "git-unassigned", Provider: "github-pat", Type: "token", Value: "SWSV-GIT-UNASSIGNED-SENTINEL", Bindings: Binding{Hosts: []string{"api.github.com"}, AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.Handler())
	defer httpServer.Close()
	t.Setenv("SWSV_URL", httpServer.URL)
	t.Setenv("SWSV_TOKEN", token)
	t.Setenv("SWSV_NS", "ns1")
	err = vaultcli.Run([]string{"--env", "VALUE=vault:_unassigned/" + m.ID, "--", "/bin/echo", "SWSV-GIT-UNASSIGNED-SENTINEL"})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "404") {
		t.Fatalf("run resolved unassigned secret, err=%v", err)
	}
	unassignedRunErr := err
	err = vaultcli.Run([]string{"--env", "VALUE=vault:ns1/nonexistent-id", "--", "/bin/echo", "should-not-run"})
	if err == nil || err.Error() != unassignedRunErr.Error() {
		t.Fatalf("run error differs from nonexistent: unassigned=%v nonexistent=%v", unassignedRunErr, err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	_, _ = inW.Write([]byte("protocol=https\nhost=api.github.com\n\n"))
	_ = inW.Close()
	outR, outW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	os.Stdin = inR
	os.Stdout = outW
	credErr := vaultcli.GitCredential([]string{"get"})
	_ = outW.Close()
	os.Stdin = oldIn
	os.Stdout = oldOut
	output, _ := io.ReadAll(outR)
	_ = inR.Close()
	_ = outR.Close()
	if credErr != nil {
		t.Fatal(credErr)
	}
	if strings.Contains(string(output), "SWSV-GIT-UNASSIGNED-SENTINEL") || strings.Contains(string(output), "password=") {
		t.Fatalf("git-credential exposed unassigned secret: %q", output)
	}
}

func TestQuickCreateResultNeverEchoesSecret(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	const sentinel = "SWSV-QUICK-CREATE-DO-NOT-ECHO"
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	cookie, csrf := "quick-create-session", "quick-create-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	get := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/new", nil)
	if get.Code != 200 {
		t.Fatalf("form status=%d", get.Code)
	}
	post := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", url.Values{"csrf": {csrf}, "provider": {"github-pat"}, "label": {"quick-create-fake"}, "value": {sentinel}, "project": {"ns1"}})
	if post.Code != 200 || strings.Contains(post.Body.String(), sentinel) {
		t.Fatalf("quick create result leaked value or failed: status=%d body=%s", post.Code, post.Body.String())
	}
	if !strings.Contains(logs.String(), "admin secret stored") {
		t.Fatalf("self-check: expected admin store log, got %q", logs.String())
	}
	if strings.Contains(logs.String(), sentinel) {
		t.Fatalf("quick create log leaked secret value: %s", logs.String())
	}
	var auditText string
	if err := s.S.DB.QueryRow(`SELECT group_concat(actor||ns||secret_id||action||result) FROM audit`).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditText, sentinel) {
		t.Fatal("quick create audit leaked secret value")
	}
}
