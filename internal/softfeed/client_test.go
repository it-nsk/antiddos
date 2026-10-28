package softfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type staticSource struct{ snapshot Snapshot }

func (source staticSource) FeedSnapshot(epoch string, _ time.Time) Snapshot {
	result := source.snapshot
	result.Epoch = epoch
	return result
}

type notifyingSource struct {
	mu       sync.RWMutex
	snapshot Snapshot
	changed  chan struct{}
}

func (source *notifyingSource) FeedSnapshot(epoch string, _ time.Time) Snapshot {
	source.mu.RLock()
	defer source.mu.RUnlock()
	result := source.snapshot
	result.Epoch = epoch
	return result
}

func (source *notifyingSource) WaitForRevision(ctx context.Context, revision uint64) {
	source.mu.RLock()
	if source.snapshot.Revision != revision {
		source.mu.RUnlock()
		return
	}
	changed := source.changed
	source.mu.RUnlock()
	select {
	case <-ctx.Done():
	case <-changed:
	}
}

func (source *notifyingSource) advance() {
	source.mu.Lock()
	source.snapshot.Revision++
	close(source.changed)
	source.changed = make(chan struct{})
	source.mu.Unlock()
}

func sampleSnapshot() Snapshot {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	return Snapshot{Protocol: 1, Epoch: "epoch-a", Revision: 1, Mode: "soft_block", ConfigRevision: "cfg-1", CookieTTL: "30m", Sites: []Site{{ID: "one", Hosts: []string{"one.test"}}, {ID: "two", Hosts: []string{"two.test"}}}, Decisions: []Decision{{SiteID: "one", RuleID: "home", SourceID: "web", IP: "192.0.2.1", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}}}
}
func responseBytes(t *testing.T, snapshot Snapshot) []byte {
	t.Helper()
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func fullResponse(t *testing.T, s Snapshot) []byte { t.Helper(); return responseBytes(t, s) }

func TestStateStartingSnapshotLookupAndExpiry(t *testing.T) {
	state := NewState()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if got := state.Check("one", netip.MustParseAddr("192.0.2.1"), now); got.State != "starting" || got.Challenge {
		t.Fatalf("starting=%+v", got)
	}
	if err := state.ApplyJSON(fullResponse(t, sampleSnapshot()), now); err != nil {
		t.Fatal(err)
	}
	if got := state.Check("one", netip.MustParseAddr("192.0.2.1"), now); !got.Challenge || got.State != "ready" {
		t.Fatalf("active=%+v", got)
	}
	if got := state.Check("two", netip.MustParseAddr("192.0.2.1"), now); got.Challenge {
		t.Fatalf("cross-site decision=%+v", got)
	}
	if got := state.Check("one", netip.MustParseAddr("192.0.2.1"), now.Add(time.Minute)); got.Challenge {
		t.Fatalf("expired decision=%+v", got)
	}
}

func TestHybridSnapshotWithoutSoftSitesIsReadyButDisabled(t *testing.T) {
	state := NewState()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	snapshot := Snapshot{Protocol: 1, Epoch: "epoch-a", Revision: 1, Mode: "hybrid", ConfigRevision: "cfg-1", Sites: []Site{}, Decisions: []Decision{}}
	if err := state.ApplyJSON(fullResponse(t, snapshot), now); err != nil {
		t.Fatal(err)
	}
	if got := state.Check("missing", netip.MustParseAddr("192.0.2.1"), now); got.Challenge || got.State != "ready" || got.Reason != "mode_disabled" {
		t.Fatalf("dry-only hybrid check = %+v", got)
	}
}

func TestInvalidPartialSnapshotDoesNotSwapOrRefreshHeartbeat(t *testing.T) {
	state := NewState()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := state.ApplyJSON(fullResponse(t, sampleSnapshot()), now); err != nil {
		t.Fatal(err)
	}
	bad := sampleSnapshot()
	bad.Revision = 2
	bad.Decisions[0].IP = "not-an-ip"
	if err := state.ApplyJSON(fullResponse(t, bad), now.Add(4*time.Second)); err == nil {
		t.Fatal("accepted invalid partial snapshot")
	}
	current, _ := state.Current()
	if current.Revision != 1 || state.Health(now.Add(6*time.Second)) != "degraded" {
		t.Fatalf("invalid response changed state/heartbeat: revision=%d health=%s", current.Revision, state.Health(now.Add(6*time.Second)))
	}
}

func TestUnchangedRequiresKnownExactVersionAndFullNewEpoch(t *testing.T) {
	state := NewState()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	unchanged, _ := json.Marshal(Response{Protocol: 1, Epoch: "epoch-a", Revision: 1, Unchanged: true})
	if err := state.ApplyJSON(unchanged, now); err == nil {
		t.Fatal("accepted unchanged before full snapshot")
	}
	if err := state.ApplyJSON(fullResponse(t, sampleSnapshot()), now); err != nil {
		t.Fatal(err)
	}
	wrong, _ := json.Marshal(Response{Protocol: 1, Epoch: "epoch-b", Revision: 1, Unchanged: true})
	if err := state.ApplyJSON(wrong, now.Add(10*time.Second)); err == nil {
		t.Fatal("accepted unknown epoch unchanged")
	}
	if state.Health(now.Add(10*time.Second)) != "degraded" {
		t.Fatal("invalid unchanged response refreshed heartbeat")
	}
	next := sampleSnapshot()
	next.Epoch = "epoch-b"
	next.Revision = 0
	if err := state.ApplyJSON(fullResponse(t, next), now.Add(11*time.Second)); err != nil {
		t.Fatal(err)
	}
	if state.Health(now.Add(11*time.Second)) != "ready" {
		t.Fatal("full new epoch did not restore feed")
	}
}

func TestUnchangedRejectsNullSnapshotFieldsWithoutRefreshing(t *testing.T) {
	state := NewState()
	now := time.Now()
	if err := state.ApplyJSON(fullResponse(t, sampleSnapshot()), now); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyJSON([]byte(`{"protocol":1,"epoch":"epoch-a","revision":1,"unchanged":true,"decisions":null}`), now.Add(4*time.Second)); err == nil {
		t.Fatal("accepted explicit null decisions")
	}
	if state.Health(now.Add(6*time.Second)) != "degraded" {
		t.Fatal("invalid unchanged response refreshed feed heartbeat")
	}
}

func TestSnapshotRejectsOversizeDuplicateHostsAndDecisionKeys(t *testing.T) {
	state := NewState()
	now := time.Now()
	if err := state.ApplyJSON(make([]byte, MaxSnapshotBytes+1), now); err == nil {
		t.Fatal("accepted oversize body")
	}
	for _, mutate := range []func(*Snapshot){func(s *Snapshot) { s.Sites[1].Hosts = []string{"one.test"} }, func(s *Snapshot) { s.Decisions = append(s.Decisions, s.Decisions[0]) }} {
		s := sampleSnapshot()
		s.Revision++
		mutate(&s)
		if err := state.ApplyJSON(fullResponse(t, s), now); err == nil {
			t.Fatal("accepted invalid snapshot")
		}
	}
}

func TestDisabledAndStaleStatesFailOpen(t *testing.T) {
	state := NewState()
	now := time.Now()
	s := sampleSnapshot()
	s.Mode = "dry_run"
	s.CookieTTL = ""
	if err := state.ApplyJSON(fullResponse(t, s), now); err != nil {
		t.Fatal(err)
	}
	if got := state.Check("one", netip.MustParseAddr("192.0.2.1"), now); got.Challenge || got.Reason != "mode_disabled" {
		t.Fatalf("disabled=%+v", got)
	}
	s.Mode = "soft_block"
	s.CookieTTL = "30m"
	s.Revision++
	if err := state.ApplyJSON(fullResponse(t, s), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := state.Check("one", netip.MustParseAddr("192.0.2.1"), now.Add(7*time.Second)); got.Challenge || got.State != "degraded" {
		t.Fatalf("stale=%+v", got)
	}
}

func TestHybridSnapshotEnforcesSoftDecisions(t *testing.T) {
	state := NewState()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	snapshot := sampleSnapshot()
	snapshot.Mode = "hybrid"
	if err := state.ApplyJSON(fullResponse(t, snapshot), now); err != nil {
		t.Fatal(err)
	}
	if got := state.Check("one", netip.MustParseAddr("192.0.2.1"), now); !got.Challenge || got.Reason != "decision_active" {
		t.Fatalf("hybrid decision=%+v", got)
	}
}

func TestFeedHandlerAndClientExchangeFullThenUnchanged(t *testing.T) {
	snapshot := sampleSnapshot()
	source := staticSource{snapshot: snapshot}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/v1/soft-decisions", nil)
	Server{Source: source, Epoch: "epoch-live"}.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("full response status=%d", recorder.Code)
	}
	state := NewState()
	now := time.Now()
	if err := state.ApplyJSON(recorder.Body.Bytes(), now); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest("GET", "/v1/soft-decisions?epoch=epoch-live&revision=1", nil)
	Server{Source: source, Epoch: "epoch-live"}.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("unchanged status=%d", recorder.Code)
	}
	var unchanged Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &unchanged); err != nil {
		t.Fatal(err)
	}
	if !unchanged.Unchanged || unchanged.Decisions != nil {
		t.Fatalf("unchanged response carried data: %+v", unchanged)
	}
	if err := state.ApplyJSON(recorder.Body.Bytes(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	bad := httptest.NewRecorder()
	Server{Source: source, Epoch: "epoch-live"}.Handler().ServeHTTP(bad, httptest.NewRequest("GET", "/v1/soft-decisions?epoch=bad&revision=NaN", nil))
	if bad.Code != 400 {
		t.Fatalf("invalid query status=%d", bad.Code)
	}
}

func TestFeedLongPollReturnsImmediatelyAfterRevisionChange(t *testing.T) {
	source := &notifyingSource{snapshot: sampleSnapshot(), changed: make(chan struct{})}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/v1/soft-decisions?epoch=epoch-live&revision=1&wait=1", nil)
	done := make(chan struct{})
	go func() {
		Server{Source: source, Epoch: "epoch-live"}.Handler().ServeHTTP(recorder, request)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("long poll returned before revision changed")
	case <-time.After(20 * time.Millisecond):
	}
	source.advance()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("long poll did not wake after revision changed")
	}
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Revision != 2 || response.Unchanged {
		t.Fatalf("long poll response=%+v", response)
	}
}

func TestFullSnapshotWithNoLeasesStillCarriesEmptyArrays(t *testing.T) {
	s := sampleSnapshot()
	s.Decisions = nil
	recorder := httptest.NewRecorder()
	Server{Source: staticSource{snapshot: s}, Epoch: "epoch-empty"}.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/v1/soft-decisions", nil))
	if recorder.Code != 200 {
		t.Fatalf("status=%d", recorder.Code)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["decisions"]) != "[]" || string(decoded["sites"]) == "" {
		t.Fatalf("full response omitted arrays: %s", recorder.Body.String())
	}
	if err := NewState().ApplyJSON(recorder.Body.Bytes(), time.Now()); err != nil {
		t.Fatalf("client rejected empty full snapshot: %v", err)
	}
}

func TestUnixFeedServeAndPollClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.sock")
	snapshot := sampleSnapshot()
	now := time.Now().UTC()
	snapshot.Decisions[0].CreatedAt = now.Add(-time.Minute)
	snapshot.Decisions[0].ExpiresAt = now.Add(time.Minute)
	source := staticSource{snapshot: snapshot}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, source, "epoch-socket") }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			select {
			case err := <-done:
				t.Fatalf("feed socket did not start: %v", err)
			default:
				t.Fatal("feed socket did not start")
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	client := Client{SocketPath: path, State: NewState()}
	if err := client.PollOnce(context.Background()); err != nil {
		cancel()
		t.Fatal(err)
	}
	if got := client.State.Check("one", netip.MustParseAddr("192.0.2.1"), time.Now()); !got.Challenge {
		cancel()
		t.Fatalf("socket snapshot lookup=%+v", got)
	}
	if err := client.PollOnce(context.Background()); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("feed server did not stop")
	}
}

func BenchmarkSnapshotLookup(b *testing.B) {
	for _, count := range []int{1, 10000, 50000} {
		b.Run(fmt.Sprintf("leases_%d", count), func(b *testing.B) {
			s := sampleSnapshot()
			s.Decisions = make([]Decision, 0, count)
			now := time.Now().UTC()
			for i := 0; i < count; i++ {
				ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
				s.Decisions = append(s.Decisions, Decision{SiteID: "one", RuleID: fmt.Sprintf("r%d", i), SourceID: "web", IP: ip, CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)})
			}
			state := NewState()
			raw, err := json.Marshal(s)
			if err != nil {
				b.Fatal(err)
			}
			if err := state.ApplyJSON(raw, now); err != nil {
				b.Fatal(err)
			}
			target := netip.MustParseAddr(s.Decisions[len(s.Decisions)-1].IP)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !state.Check("one", target, now).Challenge {
					b.Fatal("lookup missed lease")
				}
			}
		})
	}
}
