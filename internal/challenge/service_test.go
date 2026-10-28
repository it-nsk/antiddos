package challenge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"github.com/it-nsk/antiddos/internal/softfeed"
)

func testState(t *testing.T, now time.Time) *softfeed.State {
	t.Helper()
	snapshot := softfeed.Snapshot{Protocol: 1, Epoch: "test-epoch", Revision: 1, Mode: "soft_block", ConfigRevision: "cfg1", CookieTTL: "30m", Sites: []softfeed.Site{{ID: "main", Hosts: []string{"example.test"}}}, Decisions: []softfeed.Decision{}}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	state := softfeed.NewState()
	if err := state.ApplyJSON(raw, now); err != nil {
		t.Fatal(err)
	}
	return state
}
func testService(t *testing.T, now time.Time) *Service {
	t.Helper()
	service, err := NewService(testState(t, now), Options{ProviderSecret: []byte("0123456789abcdef0123456789abcdef"), CookieKeys: Keyring{Current: Key{ID: "k1", Secret: []byte("abcdef0123456789abcdef0123456789")}}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func solveTask(t testing.TB, task Task) string {
	t.Helper()
	solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: task.Challenge, DeriveKey: altcha.DeriveKeyPBKDF2(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(altcha.Payload{Challenge: task.Challenge, Solution: *solution})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(payload)
}

func TestTaskVerifyIsBoundToSessionSiteHostAndOneUse(t *testing.T) {
	now := time.Now().UTC()
	service := testService(t, now)
	session, err := service.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	task, err := service.CreateTask("example.test", netip.MustParseAddr("192.0.2.1"), session, "/private?q=1", now)
	if err != nil {
		t.Fatal(err)
	}
	if task.Challenge.Parameters.Algorithm != "PBKDF2/SHA-256" || task.Challenge.Parameters.Cost != ChallengeCost || task.Challenge.Parameters.KeyLength != 32 {
		t.Fatalf("unexpected challenge profile: %+v", task.Challenge.Parameters)
	}
	payload := solveTask(t, task)
	request := VerifyRequest{TaskID: task.ID, SessionID: session, SiteID: task.SiteID, Host: "example.test", Authority: "example.test", Scheme: "https", Origin: "https://example.test", CSRF: task.CSRF, Payload: payload}
	if _, err := service.Verify(context.Background(), request, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), request, now.Add(2*time.Second)); err == nil {
		t.Fatal("replayed task issued another pass cookie")
	}
}

func TestRefreshReusesTaskForSameSessionWithoutSharingAcrossSessions(t *testing.T) {
	now := time.Now().UTC()
	service := testService(t, now)
	ip := netip.MustParseAddr("192.0.2.7")
	session, _ := service.NewSession()
	first, err := service.CreateTask("example.test", ip, session, "/safe", now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		current, err := service.CreateTask("example.test", ip, session, "/safe", now.Add(time.Duration(i+1)*time.Second))
		if err != nil || current.ID != first.ID || current.CSRF != first.CSRF {
			t.Fatalf("refresh task=%+v err=%v", current, err)
		}
	}
	other, _ := service.NewSession()
	otherTask, err := service.CreateTask("example.test", ip, other, "/safe", now.Add(4*time.Second))
	if err != nil || otherTask.ID == first.ID {
		t.Fatalf("different session task=%+v err=%v", otherTask, err)
	}
	request := VerifyRequest{TaskID: first.ID, SessionID: session, SiteID: first.SiteID, Host: first.Host, Authority: first.Host, Scheme: "https", Origin: "https://" + first.Host, CSRF: first.CSRF, Payload: solveTask(t, first)}
	if _, err := service.Verify(context.Background(), request, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	service.state = testState(t, now.Add(time.Minute))
	newTask, err := service.CreateTask("example.test", ip, session, "/safe", now.Add(time.Minute))
	if err != nil || newTask.ID == first.ID {
		t.Fatalf("consumed task reused: task=%+v err=%v", newTask, err)
	}
}

func TestTaskRejectsCrossSessionHostOriginCSRFAndTamperedParameters(t *testing.T) {
	now := time.Now().UTC()
	for _, mutate := range []func(*VerifyRequest){func(r *VerifyRequest) { r.SessionID = "other" }, func(r *VerifyRequest) { r.Host = "other.test" }, func(r *VerifyRequest) { r.Origin = "https://evil.test" }, func(r *VerifyRequest) { r.CSRF = "wrong" }} {
		service := testService(t, now)
		session, _ := service.NewSession()
		task, err := service.CreateTask("example.test", netip.MustParseAddr("192.0.2.2"), session, "/safe", now)
		if err != nil {
			t.Fatal(err)
		}
		request := VerifyRequest{TaskID: task.ID, SessionID: session, SiteID: task.SiteID, Host: "example.test", Authority: "example.test", Scheme: "https", Origin: "https://example.test", CSRF: task.CSRF, Payload: solveTask(t, task)}
		mutate(&request)
		if _, err := service.Verify(context.Background(), request, now.Add(time.Second)); err == nil {
			t.Fatal("accepted invalid task binding")
		}
	}
	service := testService(t, now)
	session, _ := service.NewSession()
	task, err := service.CreateTask("example.test", netip.MustParseAddr("192.0.2.3"), session, "/safe", now)
	if err != nil {
		t.Fatal(err)
	}
	tampered := task.Challenge
	tampered.Parameters.Cost++
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: task.Challenge, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(altcha.Payload{Challenge: tampered, Solution: *sol})
	request := VerifyRequest{TaskID: task.ID, SessionID: session, SiteID: task.SiteID, Host: "example.test", Authority: "example.test", Scheme: "https", Origin: "https://example.test", CSRF: task.CSRF, Payload: base64.StdEncoding.EncodeToString(raw)}
	if _, err := service.Verify(context.Background(), request, now.Add(time.Second)); err == nil {
		t.Fatal("accepted client-selected work cost")
	}
}

func TestOneOfParallelVerifyRequestsConsumesTask(t *testing.T) {
	now := time.Now().UTC()
	service := testService(t, now)
	session, _ := service.NewSession()
	task, err := service.CreateTask("example.test", netip.MustParseAddr("192.0.2.4"), session, "/safe", now)
	if err != nil {
		t.Fatal(err)
	}
	payload := solveTask(t, task)
	request := VerifyRequest{TaskID: task.ID, SessionID: session, SiteID: task.SiteID, Host: "example.test", Authority: "example.test", Scheme: "https", Origin: "https://example.test", CSRF: task.CSRF, Payload: payload}
	var wg sync.WaitGroup
	wg.Add(2)
	success := 0
	var mu sync.Mutex
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := service.Verify(context.Background(), request, now.Add(time.Second)); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("successful parallel verifies=%d, want 1", success)
	}
}

func TestReturnURLRejectsExternalAndEncodedBypassForms(t *testing.T) {
	for _, value := range []string{"//evil.test/x", "https://evil.test/", "/%2f%2fevil.test", "/%252f%252fevil.test", "/%5c%5cevil", "/\\evil", "/safe%0d%0aLocation:%20https://evil.test"} {
		if _, err := ValidateReturnURL(value); err == nil {
			t.Errorf("accepted return URL %q", value)
		}
	}
	for _, value := range []string{"/", "/safe?q=1", "/путь?x=%D1%8F"} {
		if _, err := ValidateReturnURL(value); err != nil {
			t.Errorf("rejected local return URL %q: %v", value, err)
		}
	}
}

func TestOriginRequiresExactAuthorityIncludingPort(t *testing.T) {
	if !verifyOrigin("https", "example.test:8443", "https://example.test:8443") {
		t.Fatal("rejected matching non-default port")
	}
	for _, origin := range []string{"https://example.test", "https://example.test:9443", "https://evil.test:8443", "https://example.test:bad", "https://example.test:70000"} {
		if verifyOrigin("https", "example.test:8443", origin) {
			t.Errorf("accepted mismatched Origin authority %q", origin)
		}
	}
}

func TestPassCookieBindsSiteHostTTLAndKeyRotation(t *testing.T) {
	now := time.Now().UTC()
	current := Key{ID: "new", Secret: []byte("0123456789abcdef0123456789abcdef")}
	old := Key{ID: "old", Secret: []byte("abcdef0123456789abcdef0123456789"), AcceptUntil: now.Add(time.Hour)}
	ring := Keyring{Current: current, Previous: []Key{old}}
	token, err := IssuePassCookie(ring, "main", "example.test", 30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassCookie(ring, token, "main", "example.test", 30*time.Minute, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		site, host string
		ttl        time.Duration
		at         time.Time
	}{{"other", "example.test", 30 * time.Minute, now.Add(time.Minute)}, {"main", "other.test", 30 * time.Minute, now.Add(time.Minute)}, {"main", "example.test", time.Minute, now.Add(2 * time.Minute)}, {"main", "example.test", 30 * time.Minute, now.Add(31 * time.Minute)}} {
		if err := VerifyPassCookie(ring, token, test.site, test.host, test.ttl, test.at); err == nil {
			t.Errorf("accepted invalid cookie params %+v", test)
		}
	}
	oldToken, err := IssuePassCookie(Keyring{Current: old}, "main", "example.test", 30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassCookie(ring, oldToken, "main", "example.test", 30*time.Minute, now.Add(2*time.Hour)); err == nil {
		t.Fatal("accepted rotated key after grace period")
	}
}

func TestTaskExpiryAndMalformedPayload(t *testing.T) {
	now := time.Now().UTC()
	service := testService(t, now)
	session, _ := service.NewSession()
	task, err := service.CreateTask("example.test", netip.MustParseAddr("192.0.2.5"), session, "/safe", now)
	if err != nil {
		t.Fatal(err)
	}
	request := VerifyRequest{TaskID: task.ID, SessionID: session, SiteID: task.SiteID, Host: "example.test", Authority: "example.test", Scheme: "https", Origin: "https://example.test", CSRF: task.CSRF, Payload: base64.StdEncoding.EncodeToString([]byte("{}"))}
	if _, err := service.Verify(context.Background(), request, now.Add(3*time.Minute)); err == nil {
		t.Fatal("accepted expired task")
	}
	if _, err := service.Verify(context.Background(), VerifyRequest{TaskID: task.ID, SessionID: session, SiteID: task.SiteID, Host: "example.test", Authority: "example.test", Scheme: "https", Origin: "https://example.test", CSRF: task.CSRF, Payload: string(make([]byte, MaxFormBytes+1))}, now.Add(time.Second)); err == nil {
		t.Fatal("accepted oversize payload")
	}
}

func BenchmarkVerifyPayload(b *testing.B) {
	now := time.Now().UTC()
	snapshot := softfeed.Snapshot{Protocol: 1, Epoch: "bench", Revision: 1, Mode: "soft_block", ConfigRevision: "cfg", CookieTTL: "30m", Sites: []softfeed.Site{{ID: "main", Hosts: []string{"example.test"}}}, Decisions: []softfeed.Decision{}}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		b.Fatal(err)
	}
	state := softfeed.NewState()
	if err := state.ApplyJSON(raw, now); err != nil {
		b.Fatal(err)
	}
	service, err := NewService(state, Options{ProviderSecret: []byte("0123456789abcdef0123456789abcdef"), CookieKeys: Keyring{Current: Key{ID: "k1", Secret: []byte("abcdef0123456789abcdef0123456789")}}})
	if err != nil {
		b.Fatal(err)
	}
	session, err := service.NewSession()
	if err != nil {
		b.Fatal(err)
	}
	task, err := service.CreateTask("example.test", netip.MustParseAddr("192.0.2.10"), session, "/", now)
	if err != nil {
		b.Fatal(err)
	}
	payload := solveTask(b, task)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, err := service.verifyPayload(task, payload, now); err != nil || !ok {
			b.Fatalf("verify payload ok=%v err=%v", ok, err)
		}
	}
}
