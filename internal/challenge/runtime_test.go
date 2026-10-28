package challenge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/softfeed"
)

type mutableFeed struct {
	mu       sync.RWMutex
	snapshot softfeed.Snapshot
}

func (feed *mutableFeed) FeedSnapshot(epoch string, now time.Time) softfeed.Snapshot {
	feed.mu.RLock()
	defer feed.mu.RUnlock()
	copy := feed.snapshot
	copy.Epoch = epoch
	copy.Decisions = append([]softfeed.Decision(nil), copy.Decisions...)
	return copy
}
func (feed *mutableFeed) set(decisions []softfeed.Decision) {
	feed.mu.Lock()
	defer feed.mu.Unlock()
	feed.snapshot.Revision++
	feed.snapshot.Decisions = decisions
}

func TestRuntimeReadsFeedAnswersCheckAndShutsDownSockets(t *testing.T) {
	dir := t.TempDir()
	feedPath, checkPath, adminPath, credentialPath := filepath.Join(dir, "feed", "feed.sock"), filepath.Join(dir, "check", "check.sock"), filepath.Join(dir, "admin", "admin.sock"), filepath.Join(dir, "keys.json")
	now := time.Now().UTC()
	feed := &mutableFeed{snapshot: softfeed.Snapshot{Protocol: 1, Epoch: "runtime", Revision: 1, Mode: "soft_block", ConfigRevision: "cfg1", CookieTTL: "30m", Sites: []softfeed.Site{{ID: "main", Hosts: []string{"example.test"}}}, Decisions: []softfeed.Decision{}}}
	feedCtx, stopFeed := context.WithCancel(context.Background())
	feedDone := make(chan error, 1)
	go func() { feedDone <- softfeed.Serve(feedCtx, feedPath, feed, "runtime-epoch") }()
	waitForPath(t, feedPath)
	feedStopped := false
	defer func() {
		if !feedStopped {
			stopFeed()
			select {
			case err := <-feedDone:
				if err != nil {
					t.Errorf("stop feed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("feed server did not stop")
			}
		}
	}()
	credentialData := map[string]any{"provider_secret": base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")), "current": map[string]string{"id": "k1", "secret": base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))}, "previous": []any{}}
	raw, _ := json.Marshal(credentialData)
	if err := os.WriteFile(credentialPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RuntimeOptions{FeedSocketPath: feedPath, CheckSocketPath: checkPath, AdminSocketPath: adminPath, CredentialPath: credentialPath, CheckSocketGroupID: os.Getgid(), AdminSocketGroupID: os.Getgid()}, nil)
	}()
	waitForPath(t, checkPath)
	waitForPath(t, adminPath)
	check := func() int {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", checkPath)
		}}
		client := &http.Client{Transport: transport, Timeout: time.Second}
		defer transport.CloseIdleConnections()
		request, _ := http.NewRequest(http.MethodGet, "http://checker/__antiddos_check", nil)
		request.Header.Set("X-AntiDDoS-Host", "example.test")
		request.Header.Set("X-AntiDDoS-Authority", "example.test")
		request.Header.Set("X-AntiDDoS-Scheme", "https")
		request.Header.Set("X-AntiDDoS-IP", "192.0.2.25")
		request.Header.Set("X-AntiDDoS-URI", "/private")
		request.Header.Set("X-AntiDDoS-Method", "GET")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("check socket request: %v", err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	deadline := time.Now().Add(3 * time.Second)
	for check() != http.StatusNoContent && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if status := check(); status != http.StatusNoContent {
		t.Fatalf("initial check status=%d", status)
	}
	feed.set([]softfeed.Decision{{SiteID: "main", RuleID: "r1", SourceID: "access", IP: "192.0.2.25", CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}})
	deadline = time.Now().Add(3 * time.Second)
	for check() != http.StatusForbidden && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if status := check(); status != http.StatusForbidden {
		t.Fatalf("decision check status=%d", status)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", checkPath)
	}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	challengeRequest, _ := http.NewRequest(http.MethodGet, "http://checker/__antiddos/challenge", nil)
	challengeRequest.Header.Set("X-AntiDDoS-Host", "example.test")
	challengeRequest.Header.Set("X-AntiDDoS-Authority", "example.test")
	challengeRequest.Header.Set("X-AntiDDoS-Scheme", "https")
	challengeRequest.Header.Set("X-AntiDDoS-IP", "192.0.2.25")
	challengeRequest.Header.Set("X-AntiDDoS-URI", "/private?q=runtime")
	challengeResponse, err := client.Do(challengeRequest)
	if err != nil {
		t.Fatalf("challenge route over UDS: %v", err)
	}
	if challengeResponse.StatusCode != http.StatusOK || len(challengeResponse.Cookies()) != 1 || challengeResponse.Cookies()[0].Name != SessionCookieName || !challengeResponse.Cookies()[0].Secure {
		challengeResponse.Body.Close()
		t.Fatalf("challenge response status=%d cookies=%+v", challengeResponse.StatusCode, challengeResponse.Cookies())
	}
	challengeResponse.Body.Close()
	transport.CloseIdleConnections()
	adminTransport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", adminPath)
	}}
	adminClient := &http.Client{Transport: adminTransport, Timeout: time.Second}
	adminResponse, err := adminClient.Get("http://checker/v1/status")
	if err != nil {
		t.Fatalf("admin status over UDS: %v", err)
	}
	if adminResponse.StatusCode != http.StatusOK {
		t.Fatalf("admin status=%d", adminResponse.StatusCode)
	}
	adminResponse.Body.Close()
	adminTransport.CloseIdleConnections()
	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("stop challenge runtime: %v", err)
	}
	stopFeed()
	if err := <-feedDone; err != nil {
		t.Fatalf("stop feed: %v", err)
	}
	feedStopped = true
	if _, err := os.Lstat(checkPath); !os.IsNotExist(err) {
		t.Fatalf("challenge socket remains: %v", err)
	}
	if _, err := os.Lstat(adminPath); !os.IsNotExist(err) {
		t.Fatalf("admin socket remains: %v", err)
	}
	if _, err := os.Lstat(feedPath); !os.IsNotExist(err) {
		t.Fatalf("feed socket remains: %v", err)
	}
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s was not created", path)
}

func TestCheckHandlerDeadline(t *testing.T) {
	handler := boundedCheckHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	response := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/__antiddos_check", nil))
	if response.Code != http.StatusServiceUnavailable || time.Since(started) > time.Second {
		t.Fatalf("status=%d elapsed=%s", response.Code, time.Since(started))
	}
}
