package challenge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/softfeed"
)

func checkService(t *testing.T, now time.Time, decisions []softfeed.Decision) *Service {
	t.Helper()
	snapshot := softfeed.Snapshot{Protocol: 1, Epoch: "check-test", Revision: 1, Mode: "soft_block", ConfigRevision: "cfg1", CookieTTL: "30m", Sites: []softfeed.Site{{ID: "main", Hosts: []string{"example.test"}}}, Decisions: decisions}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	state := softfeed.NewState()
	if err := state.ApplyJSON(raw, now); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(state, Options{ProviderSecret: []byte("0123456789abcdef0123456789abcdef"), CookieKeys: Keyring{Current: Key{ID: "k1", Secret: []byte("abcdef0123456789abcdef0123456789")}}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func checkRequest(service *Service, method, uri, clientIP string, now time.Time, cookie string) *httptest.ResponseRecorder {
	service.clock = func() time.Time { return now }
	request := httptest.NewRequest(method, "http://checker/__antiddos_check", nil)
	request.Header.Set("X-AntiDDoS-Host", "example.test")
	request.Header.Set("X-AntiDDoS-Authority", "example.test")
	request.Header.Set("X-AntiDDoS-Scheme", "https")
	request.Header.Set("X-AntiDDoS-IP", clientIP)
	request.Header.Set("X-AntiDDoS-URI", uri)
	request.Header.Set("X-AntiDDoS-Method", method)
	if cookie != "" {
		request.AddCookie(&http.Cookie{Name: PassCookieName, Value: cookie})
	}
	response := httptest.NewRecorder()
	service.CheckHandler().ServeHTTP(response, request)
	return response
}

func TestCheckChallengesOnlyActiveDecisionWithoutValidPassCookie(t *testing.T) {
	now := time.Now().UTC()
	service := checkService(t, now, []softfeed.Decision{{SiteID: "main", RuleID: "r1", SourceID: "access", IP: "192.0.2.25", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}})
	response := checkRequest(service, http.MethodGet, "/private?q=1", "192.0.2.25", now, "")
	if response.Code != http.StatusForbidden || response.Header().Get("X-AntiDDoS-Decision") != "challenge" {
		t.Fatalf("decision response status=%d headers=%v", response.Code, response.Header())
	}
	pass, err := IssuePassCookie(service.cookieKeys, "main", "example.test", 30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	response = checkRequest(service, http.MethodGet, "/private?q=1", "192.0.2.25", now, pass)
	if response.Code != http.StatusNoContent {
		t.Fatalf("pass cookie status=%d headers=%v", response.Code, response.Header())
	}
	response = checkRequest(service, http.MethodGet, "/private", "192.0.2.26", now, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("unlisted client status=%d", response.Code)
	}
}

func TestCheckFailsOpenForStaleOrUnsupportedMethodAndMarksBadMetadata(t *testing.T) {
	now := time.Now().UTC()
	service := checkService(t, now, []softfeed.Decision{{SiteID: "main", RuleID: "r1", SourceID: "access", IP: "192.0.2.25", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}})
	for _, test := range []struct {
		name   string
		method string
		at     time.Time
		want   int
	}{
		{name: "stale feed", method: http.MethodGet, at: now.Add(softfeed.StaleAfter + time.Second), want: http.StatusNoContent},
		{name: "unsupported method bypass", method: http.MethodPost, at: now, want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := checkRequest(service, test.method, "/private", "192.0.2.25", test.at, "")
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d", response.Code, test.want)
			}
		})
	}
	request := httptest.NewRequest(http.MethodGet, "http://checker/__antiddos_check", nil)
	request.Header.Set("X-AntiDDoS-Host", "bad host")
	response := httptest.NewRecorder()
	service.CheckHandler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("X-AntiDDoS-Decision") != "integration_error" {
		t.Fatalf("bad metadata status=%d headers=%v", response.Code, response.Header())
	}
	request = httptest.NewRequest(http.MethodGet, "http://checker/__antiddos_check", nil)
	request.Header.Set("X-AntiDDoS-Host", "example.test")
	request.Header.Set("X-AntiDDoS-Authority", "attacker.test")
	request.Header.Set("X-AntiDDoS-Scheme", "https")
	request.Header.Set("X-AntiDDoS-IP", "192.0.2.25")
	request.Header.Set("X-AntiDDoS-URI", "/private")
	response = httptest.NewRecorder()
	service.CheckHandler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("X-AntiDDoS-Decision") != "integration_error" {
		t.Fatalf("mismatched authority status=%d headers=%v", response.Code, response.Header())
	}
}

func TestCheckFailsOpenBeforeFirstFeedSnapshot(t *testing.T) {
	service := checkService(t, time.Now(), []softfeed.Decision{})
	service.state = softfeed.NewState()
	response := checkRequest(service, http.MethodGet, "/private", "192.0.2.25", time.Now(), "")
	if response.Code != http.StatusNoContent || response.Header().Get("X-AntiDDoS-Reason") != "no_snapshot" {
		t.Fatalf("starting feed status=%d headers=%v", response.Code, response.Header())
	}
}

func TestCheckRejectsAuthorizationOrRequestBody(t *testing.T) {
	service := checkService(t, time.Now(), []softfeed.Decision{})
	for _, test := range []struct {
		name          string
		body          string
		authorization string
	}{
		{name: "authorization", authorization: "Bearer must-not-reach-checker"},
		{name: "request body", body: "must-not-reach-checker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://checker/__antiddos_check", strings.NewReader(test.body))
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			service.CheckHandler().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || response.Header().Get("X-AntiDDoS-Decision") != "integration_error" {
				t.Fatalf("status=%d headers=%v", response.Code, response.Header())
			}
		})
	}
}

func TestCheckRejectsNonCanonicalIPAndExpiredLease(t *testing.T) {
	now := time.Now().UTC()
	service := checkService(t, now, []softfeed.Decision{{SiteID: "main", RuleID: "r1", SourceID: "access", IP: "192.0.2.25", CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Second)}})
	for _, ip := range []string{"192.0.2.25", "::ffff:192.0.2.25"} {
		response := checkRequest(service, http.MethodGet, "/private", ip, now, "")
		if response.Code != http.StatusNoContent {
			t.Errorf("IP %q status=%d want=204", ip, response.Code)
		}
	}
	response := checkRequest(service, http.MethodGet, "/private", "not-an-ip", now, "")
	if response.Code != http.StatusForbidden || response.Header().Get("X-AntiDDoS-Decision") != "integration_error" {
		t.Fatalf("invalid IP status=%d headers=%v", response.Code, response.Header())
	}
	if !netip.MustParseAddr("192.0.2.25").IsValid() {
		t.Fatal("test IP invalid")
	}
}
