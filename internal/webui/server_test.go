package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/challengeadmin"
	"github.com/it-nsk/antiddos/internal/configservice"
	"github.com/it-nsk/antiddos/internal/storage"
	"github.com/it-nsk/antiddos/internal/webauth"
	"github.com/it-nsk/antiddos/internal/webcontrol"
)

type testBackend struct {
	config *configservice.Service
	stats  *storage.Reader
}

func configserviceStringSlice(values ...string) *[]string { return &values }

func (b *testBackend) Dashboard(ctx context.Context, from, to time.Time, before int64, limit int) (storage.Dashboard, error) {
	return b.stats.Dashboard(ctx, from, to, before, limit)
}
func (b *testBackend) ChallengeStatus(context.Context) (challengeadmin.Status, error) {
	return challengeadmin.Status{Health: "ready", MetricsHealth: "ready"}, nil
}
func (b *testBackend) SoftBlocks(ctx context.Context, limit int) ([]storage.SoftBlockLease, error) {
	return b.stats.ActiveSoftBlocks(ctx, time.Now(), limit)
}
func (b *testBackend) ChallengeMetrics(context.Context, time.Time, time.Time, int) ([]challengeadmin.Metric, error) {
	return []challengeadmin.Metric{{Site: "main", Reason: "issued", Count: 3}}, nil
}

func TestChallengeAPIRequiresSessionAndAllowsViewer(t *testing.T) {
	s := fixtureServer(t)
	if w := request(s, "GET", "/api/challenge/metrics", "", nil, "", ""); w.Code != 401 {
		t.Fatalf("anonymous status %d", w.Code)
	}
	viewer, _ := loginAs(t, s, "viewer")
	for _, path := range []string{"/api/challenge/status", "/api/challenge/metrics", "/api/soft-blocks"} {
		w := request(s, "GET", path, "", viewer, "", "")
		if w.Code != 200 {
			t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
	if w := request(s, "GET", "/api/challenge/metrics?from=0&to=9999999&limit=1001", "", viewer, "", ""); w.Code != 400 {
		t.Fatalf("invalid query status=%d", w.Code)
	}
}

func TestSoftBlockCookieTTLAdminOnly(t *testing.T) {
	s := fixtureServer(t)
	backend := s.backend.(*testBackend)
	data := `{"log_sources":{"web":{"path":"/tmp/web.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":"/tmp/stats.sqlite","block_mode":"soft_block","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"rules":[{"id":"home","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`
	if err := os.WriteFile(backend.config.Path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	doc, err := backend.config.Read()
	if err != nil {
		t.Fatal(err)
	}
	update, _ := json.Marshal(map[string]any{"revision": doc.Revision, "cookie_ttl": "45m"})
	viewer, viewerSession := loginAs(t, s, "viewer")
	if w := request(s, "PUT", "/api/config/rules", string(update), viewer, viewerSession.CSRF, s.origin.String()); w.Code != 403 {
		t.Fatalf("viewer status=%d", w.Code)
	}
	admin, adminSession := loginAs(t, s, "admin")
	if w := request(s, "PUT", "/api/config/rules", string(update), admin, adminSession.CSRF, s.origin.String()); w.Code != 200 || !strings.Contains(w.Body.String(), `"cookie_ttl":"45m"`) {
		t.Fatalf("admin status=%d body=%s", w.Code, w.Body.String())
	}
}
func (b *testBackend) Config(context.Context) (webcontrol.ConfigState, error) {
	document, err := b.config.Read()
	if err != nil {
		return webcontrol.ConfigState{}, err
	}
	restart := false
	return webcontrol.ConfigState{Config: document, DaemonAvailable: true, RestartRequired: &restart}, nil
}
func (b *testBackend) SaveRules(_ context.Context, update configservice.Update) (webcontrol.ConfigState, error) {
	document, err := b.config.Save(update)
	if err != nil {
		status := 400
		if errors.Is(err, configservice.ErrConflict) {
			status = 409
		}
		return webcontrol.ConfigState{}, &webcontrol.RemoteError{Status: status, Message: err.Error()}
	}
	restart := true
	return webcontrol.ConfigState{Config: document, DaemonAvailable: true, RestartRequired: &restart}, nil
}

func fixtureServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "stats.sqlite")
	b, _ := json.Marshal(map[string]any{"log_file": "/tmp/access.log", "database_path": dbPath})
	os.WriteFile(path, b, 0600)
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	stats, err := storage.OpenReader(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stats.Close() })
	auth, err := webauth.Open(filepath.Join(dir, "users.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auth.Close() })
	for _, role := range []string{"admin", "viewer"} {
		if err := auth.Add(context.Background(), role, "long-enough-password", role); err != nil {
			t.Fatal(err)
		}
	}
	backend := &testBackend{config: &configservice.Service{Path: path}, stats: stats}
	s, err := New(Options{Listen: "127.0.0.1:8080", Origin: "http://127.0.0.1:8080"}, auth, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request(s *Server, method, path, body string, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func loginAs(t *testing.T, s *Server, username string) (*http.Cookie, webauth.Session) {
	t.Helper()
	w := request(s, "POST", "/api/login", `{"username":"`+username+`","password":"long-enough-password"}`, nil, "", s.origin.String())
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var session webauth.Session
	json.Unmarshal(w.Body.Bytes(), &session)
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	return c, session
}
func TestWebAuthenticationRolesAndWhitelist(t *testing.T) {
	s := fixtureServer(t)
	if w := request(s, "GET", "/api/dashboard", "", nil, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	viewer, vs := loginAs(t, s, "viewer")
	for _, path := range []string{"/api/session", "/api/dashboard", "/api/config"} {
		if w := request(s, "GET", path, "", viewer, "", ""); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	if w := request(s, "GET", "/api/users", "", viewer, "", ""); w.Code != 403 {
		t.Fatal("viewer sees users")
	}
	d, _ := s.backend.(*testBackend).config.Read()
	regex := "^/admin$"
	update := configservice.Update{
		Revision:  d.Revision,
		IgnoreIPs: configserviceStringSlice("192.0.2.1", "2001:db8::/32"),
		Rules:     map[string]configservice.RuleUpdate{"homepage": {PathRegex: &regex}},
	}
	body, _ := json.Marshal(update)
	if w := request(s, "PUT", "/api/config/rules", string(body), viewer, vs.CSRF, s.origin.String()); w.Code != 403 {
		t.Fatal("viewer changed config")
	}
	admin, as := loginAs(t, s, "admin")
	for _, headers := range [][2]string{{"", s.origin.String()}, {as.CSRF, "http://evil.test"}, {as.CSRF, ""}} {
		if w := request(s, "PUT", "/api/config/rules", string(body), admin, headers[0], headers[1]); w.Code != 403 {
			t.Fatal("CSRF bypass")
		}
	}
	if w := request(s, "PUT", "/api/config/rules", string(body), admin, as.CSRF, s.origin.String()); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(s, "PUT", "/api/config/rules", string(body), admin, as.CSRF, s.origin.String()); w.Code != 409 {
		t.Fatal("lost update allowed")
	}
	d, _ = s.backend.(*testBackend).config.Read()
	update.Revision = d.Revision
	update.IgnoreIPs = configserviceStringSlice("not-an-ip")
	body, _ = json.Marshal(update)
	if w := request(s, "PUT", "/api/config/rules", string(body), admin, as.CSRF, s.origin.String()); w.Code != 400 {
		t.Fatal("invalid IP accepted")
	}
	w := request(s, "GET", "/api/users", "", admin, "", "")
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte("password")) {
		t.Fatal("users response", w.Body.String())
	}
	if w := request(s, "POST", "/api/logout", "{}", admin, as.CSRF, s.origin.String()); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(s, "GET", "/api/session", "", admin, "", ""); w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}
func TestHostOriginAndLoginThrottling(t *testing.T) {
	s := fixtureServer(t)
	r := httptest.NewRequest("GET", "http://evil.test/api/session", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("Host not checked")
	}
	for i := 0; i < 10; i++ {
		if !s.throttle("user:admin", 10, time.Now()) {
			t.Fatal("unexpected throttle")
		}
	}
	w = request(s, "POST", "/api/login", `{"username":"admin","password":"long-enough-password"}`, nil, "", s.origin.String())
	if w.Code != 429 {
		t.Fatal("login not throttled", w.Code)
	}
	w = request(s, "POST", "/api/login", `{}`, nil, "", "http://evil.test")
	if w.Code != 403 {
		t.Fatal("login CSRF")
	}
}
func TestSecureOriginAndOptions(t *testing.T) {
	for _, o := range []Options{{Listen: "0.0.0.0:8080", Origin: "http://127.0.0.1:8080"}, {Listen: "127.0.0.1:8080", Origin: "http://example.org"}, {Listen: "127.0.0.1:8080", Origin: "https://example.org/path"}} {
		if ValidateOptions(o) == nil {
			t.Fatal("unsafe options accepted")
		}
	}
	s := fixtureServer(t)
	s.origin.Scheme = "https"
	c, _ := loginAs(t, s, "admin")
	if !c.Secure {
		t.Fatal("HTTPS cookie not Secure")
	}
}

func TestMissingDaemonSocketReturnsUnavailableWithoutLosingSession(t *testing.T) {
	s := fixtureServer(t)
	cookie, session := loginAs(t, s, "admin")
	s.backend = webcontrol.NewClient(filepath.Join(t.TempDir(), "missing.sock"))
	for _, path := range []string{"/api/dashboard", "/api/config"} {
		w := request(s, "GET", path, "", cookie, "", "")
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "missing.sock") {
			t.Fatalf("%s: status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
	w := request(s, "PUT", "/api/config/rules", `{}`, cookie, session.CSRF, s.origin.String())
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("save while daemon unavailable: %d %s", w.Code, w.Body.String())
	}
	if w := request(s, "GET", "/api/session", "", cookie, "", ""); w.Code != http.StatusOK {
		t.Fatalf("daemon outage revoked independent web session: %d", w.Code)
	}
}
