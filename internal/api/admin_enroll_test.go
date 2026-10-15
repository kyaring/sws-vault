package api

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kyaring/sws-vault/internal/auth"
)

const enrollPassword = "fake-enroll-password-123"

func testBoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func enrollmentFixture(t *testing.T, enrolled, mustChange bool) (*Server, string, string, []byte) {
	t.Helper()
	s, st, _, _ := testServer(t, "secrets:list")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(enrollPassword, salt)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte{}
	if enrolled {
		secret, _, err = auth.NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = st.DB.Exec(`INSERT INTO admins(id,password_hash,password_salt,totp_secret,created_at,totp_enrolled,must_change_password) VALUES(1,?,?,?, ?,?,?)`, hash, salt, secret, time.Now().UTC().Format(time.RFC3339), testBoolInt(enrolled), testBoolInt(mustChange))
	if err != nil {
		t.Fatal(err)
	}
	cookie := "enroll-session-" + t.Name()
	csrf := "enroll-csrf-" + t.Name()
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now(), enrollOnly: !enrolled, mustChange: mustChange}
	sessions.Unlock()
	return s, cookie, csrf, secret
}
func enrollRequest(s *Server, cookie, method, path string, values url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader = strings.NewReader("")
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
func pendingFor(t *testing.T, s *Server) []byte {
	t.Helper()
	var b []byte
	if err := s.S.DB.QueryRow(`SELECT pending_totp_secret FROM admins WHERE id=1`).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnenrolledAdminRedirectsEveryNonEnrollmentPage(t *testing.T) {
	s, cookie, _, _ := enrollmentFixture(t, false, false)
	for _, path := range []string{"/admin/secrets", "/admin/assets/admin.css"} {
		w := enrollRequest(s, cookie, http.MethodGet, path, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/totp/enroll" {
			t.Fatalf("%s status=%d location=%q", path, w.Code, w.Header().Get("Location"))
		}
	}
}
func TestWrongAndExpiredPendingTOTPFail(t *testing.T) {
	s, cookie, csrf, _ := enrollmentFixture(t, false, false)
	w := enrollRequest(s, cookie, http.MethodGet, "/admin/totp/enroll", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("enrollment page status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enrollment page cache-control=%q", w.Header().Get("Cache-Control"))
	}
	visible := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(strings.ToLower(w.Body.String()), " ")
	for _, bad := range []string{"命名空间", "namespace", "绑定"} {
		if strings.Contains(visible, bad) {
			t.Fatalf("enrollment page contains forbidden UI text %q", bad)
		}
	}
	secret := pendingFor(t, s)
	correct := auth.GenerateTOTP(secret, time.Now())
	wrong := "0" + correct[1:]
	if wrong == correct {
		wrong = "1" + correct[1:]
	}
	w = enrollRequest(s, cookie, http.MethodPost, "/admin/totp/enroll", url.Values{"csrf": {csrf}, "code": {wrong}})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status=%d", w.Code)
	}
	_, err := s.S.DB.Exec(`UPDATE admins SET pending_totp_expires=? WHERE id=1`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	w = enrollRequest(s, cookie, http.MethodPost, "/admin/totp/enroll", url.Values{"csrf": {csrf}, "code": {correct}})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired code status=%d", w.Code)
	}
}
func TestTOTPEnrollmentCompletesAndNeverRevealsSecretAgain(t *testing.T) {
	s, cookie, csrf, _ := enrollmentFixture(t, false, false)
	w := enrollRequest(s, cookie, http.MethodGet, "/admin/totp/enroll", nil)
	if w.Code != 200 {
		t.Fatalf("GET status=%d", w.Code)
	}
	secret := pendingFor(t, s)
	manualKeyMatch := regexp.MustCompile(`<code>([^<]+)</code>`).FindStringSubmatch(w.Body.String())
	if len(manualKeyMatch) != 2 || manualKeyMatch[1] == "" {
		t.Fatal("pending enrollment page omitted the manual base32 key")
	}
	manualKey := manualKeyMatch[1]
	code := auth.GenerateTOTP(secret, time.Now())
	otherSession := "other-enroll-only-session"
	sessions.Lock()
	sessions.m[otherSession] = adminSession{csrf: "other-csrf", created: time.Now(), last: time.Now(), enrollOnly: true}
	sessions.Unlock()
	w = enrollRequest(s, cookie, http.MethodPost, "/admin/totp/enroll", url.Values{"csrf": {csrf}, "code": {code}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/login" {
		t.Fatalf("POST status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	other := enrollRequest(s, otherSession, http.MethodGet, "/admin/", nil)
	if other.Code != http.StatusSeeOther || other.Header().Get("Location") != "/admin/login" {
		t.Fatalf("other enroll_only session not revoked: %d %q", other.Code, other.Header().Get("Location"))
	}
	var enrolled int
	var pending []byte
	if err := s.S.DB.QueryRow(`SELECT totp_enrolled,pending_totp_secret FROM admins WHERE id=1`).Scan(&enrolled, &pending); err != nil {
		t.Fatal(err)
	}
	if enrolled != 1 || len(pending) != 0 {
		t.Fatalf("enrolled=%d pending-bytes=%d", enrolled, len(pending))
	}
	var auditCount int
	if err := s.S.DB.QueryRow(`SELECT count(*) FROM audit WHERE action='totp-enrolled' AND result='ok'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("totp-enrolled audit count=%d", auditCount)
	}
	fresh := "fully-enrolled-session"
	sessions.Lock()
	sessions.m[fresh] = adminSession{csrf: "fully-enrolled-csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	w = enrollRequest(s, fresh, http.MethodGet, "/admin/totp/enroll", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "Secret") || strings.Contains(w.Body.String(), "data:image") || strings.Contains(w.Body.String(), "otpauth://") {
		t.Fatalf("enrolled page leaked enrollment material: %d", w.Code)
	}
	for _, forbidden := range []string{"<code", "<svg", manualKey} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("enrolled page contains %q after TOTP confirmation", forbidden)
		}
	}
}
func TestMustChangePasswordPrecedesEnrollment(t *testing.T) {
	s, cookie, _, _ := enrollmentFixture(t, false, true)
	w := enrollRequest(s, cookie, http.MethodGet, "/admin/totp/enroll", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/password" {
		t.Fatalf("enrollment bypassed password change: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = enrollRequest(s, cookie, http.MethodGet, "/admin/password", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "新密码") {
		t.Fatalf("password page status=%d", w.Code)
	}
}
func TestEnrolledAdminCannotLoginWithPasswordOnly(t *testing.T) {
	s, _, _, _ := enrollmentFixture(t, true, false)
	get := httptest.NewRecorder()
	s.Handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if !strings.Contains(get.Body.String(), "name=\"totp\"") {
		t.Fatal("enrolled login page omitted TOTP input")
	}
	csrfMatch := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(get.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("login CSRF missing")
	}
	var csrfCookie *http.Cookie
	for _, c := range get.Result().Cookies() {
		if c.Name == "sv_login_csrf" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("login CSRF cookie missing")
	}
	v := url.Values{"csrf": {csrfMatch[1]}, "password": {enrollPassword}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("password-only login status=%d", w.Code)
	}
}
func TestTOTPEnrollmentPageFallsBackToManualSecretWhenQRFails(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	w := httptest.NewRecorder()
	s.renderTOTPEnrollmentPage(w, "fake-csrf", "FAKE-TOTP-SECRET", "", true)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "二维码生成失败") || !strings.Contains(body, "FAKE-TOTP-SECRET") || strings.Contains(body, "<svg") {
		t.Fatalf("QR fallback page status=%d body=%q", w.Code, body)
	}
}

func TestQRProvisioningSVGIsInline(t *testing.T) {
	got, err := qrSVG("otpauth://totp/SWS%20Vault:admin?secret=JBSWY3DPEHPK3PXP&issuer=SWS%20Vault&digits=6&period=30")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "<svg ") || strings.Contains(got, "http://") && !strings.Contains(got, "xmlns=") {
		t.Fatal("QR is not inline SVG")
	}
}

func TestUnenrolledAdminPasswordOnlyLoginCreatesRestrictedSession(t *testing.T) {
	s, _, _, _ := enrollmentFixture(t, false, false)
	get := httptest.NewRecorder()
	s.Handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if strings.Contains(get.Body.String(), `name="totp"`) {
		t.Fatal("unenrolled login should not ask for TOTP yet")
	}
	csrfMatch := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(get.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("login CSRF missing")
	}
	var csrfCookie *http.Cookie
	for _, c := range get.Result().Cookies() {
		if c.Name == "sv_login_csrf" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("login CSRF cookie missing")
	}
	v := url.Values{"csrf": {csrfMatch[1]}, "password": {enrollPassword}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/totp/enroll" {
		t.Fatalf("password-only enrollment login: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	var adminCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "sws_admin" {
			adminCookie = c
		}
	}
	if adminCookie == nil {
		t.Fatal("enrollment session cookie missing")
	}
	sessions.Lock()
	sess, ok := sessions.m[adminCookie.Value]
	sessions.Unlock()
	if !ok || !sess.enrollOnly {
		t.Fatal("password-only login did not create enroll_only session")
	}
	// The same session cannot escape through the login page.
	w = enrollRequest(s, adminCookie.Value, http.MethodGet, "/admin/login", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/totp/enroll" {
		t.Fatalf("enroll-only session escaped to login: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestInitialPasswordChangeIsAuditedAndRequired(t *testing.T) {
	s, cookie, csrf, _ := enrollmentFixture(t, false, true)
	newPassword := "fake-new-admin-password-456"
	w := enrollRequest(s, cookie, http.MethodPost, "/admin/password", url.Values{"csrf": {csrf}, "current": {enrollPassword}, "password": {newPassword}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/totp/enroll" {
		t.Fatalf("password change status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	var mustChange int
	if err := s.S.DB.QueryRow(`SELECT must_change_password FROM admins WHERE id=1`).Scan(&mustChange); err != nil {
		t.Fatal(err)
	}
	if mustChange != 0 {
		t.Fatal("must_change_password remained set")
	}
	var n int
	if err := s.S.DB.QueryRow(`SELECT count(*) FROM audit WHERE action='password-changed' AND result='ok'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("password-changed audit count=%d", n)
	}
}

func TestTOTPEnrollmentFailuresTriggerExistingLockout(t *testing.T) {
	s, cookie, csrf, _ := enrollmentFixture(t, false, false)
	w := enrollRequest(s, cookie, http.MethodGet, "/admin/totp/enroll", nil)
	if w.Code != 200 {
		t.Fatalf("enroll page status=%d", w.Code)
	}
	secret := pendingFor(t, s)
	correct := auth.GenerateTOTP(secret, time.Now())
	wrong := "0" + correct[1:]
	if wrong == correct {
		wrong = "1" + correct[1:]
	}
	for i := 0; i < 5; i++ {
		w = enrollRequest(s, cookie, http.MethodPost, "/admin/totp/enroll", url.Values{"csrf": {csrf}, "code": {wrong}})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status=%d", i+1, w.Code)
		}
	}
	w = enrollRequest(s, cookie, http.MethodPost, "/admin/totp/enroll", url.Values{"csrf": {csrf}, "code": {wrong}})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked enrollment attempt status=%d", w.Code)
	}
}
