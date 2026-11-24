package blockmanager

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/storage"
)

type testAction struct {
	apply        []action.BlockRequest
	remove       []netip.Addr
	applyStatus  action.Status
	removeStatus action.Status
}
type readableAction struct {
	testAction
	blocks         []action.ManagedBlock
	err            error
	includeApplied bool
}

func (a *readableAction) ReadManagedBlocks(context.Context) ([]action.ManagedBlock, error) {
	blocks := append([]action.ManagedBlock(nil), a.blocks...)
	if a.includeApplied {
		for _, request := range a.apply {
			blocks = append(blocks, action.ManagedBlock{IP: request.IP, ExpiresAt: request.ExpiresAt})
		}
	}
	return blocks, a.err
}

func (a *testAction) Apply(_ context.Context, request action.BlockRequest) action.Result {
	a.apply = append(a.apply, request)
	status := a.applyStatus
	if status == "" {
		status = action.StatusApplied
	}
	return action.Result{Status: status, IP: request.IP, ExpiresAt: request.ExpiresAt}
}
func (a *testAction) Remove(_ context.Context, ip netip.Addr) action.Result {
	a.remove = append(a.remove, ip)
	status := a.removeStatus
	if status == "" {
		status = action.StatusRemoved
	}
	return action.Result{Status: status, IP: ip}
}

func newTestManager(t *testing.T, actionImpl action.Action) (*Manager, *storage.Store) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "blocks.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	policy, err := blockpolicy.New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(policy, time.Minute, actionImpl, store)
	if err != nil {
		t.Fatal(err)
	}
	return manager, store
}

func TestProcessDoesNotExtendRepeatedDetection(t *testing.T) {
	blockAction := &testAction{}
	manager, store := newTestManager(t, blockAction)
	manager.SetRepeatRules(map[string]RepeatRule{"homepage": {Multiplier: 2, Maximum: 4 * time.Minute}})
	ip := netip.MustParseAddr("192.0.2.10")
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	detection := engine.Detection{RuleID: "homepage", GroupField: engine.GroupByIP, GroupValue: ip.String()}
	first, err := manager.Process(context.Background(), detection, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Process(context.Background(), detection, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != action.StatusApplied || second.Status != action.StatusAlreadyActive {
		t.Fatalf("results = %s, %s", first.Status, second.Status)
	}
	if len(blockAction.apply) != 1 {
		t.Fatalf("Apply calls = %d, want 1", len(blockAction.apply))
	}
	if !blockAction.apply[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("expiry changed: %s", blockAction.apply[0].ExpiresAt)
	}
	level, err := store.BlockStrike(context.Background(), "homepage", ip, now.Add(30*time.Second), 7*24*time.Hour)
	if err != nil || level != 2 {
		t.Fatalf("active repeat recorded another strike: level=%d err=%v", level, err)
	}
	leases, err := store.UnexpiredBlocks(context.Background(), now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || !leases[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("stored leases = %+v", leases)
	}
}

func TestProcessUsesRuleDurationAndPermanentLease(t *testing.T) {
	blockAction := &testAction{}
	manager, _ := newTestManager(t, blockAction)
	manager.SetRuleDurations(map[string]time.Duration{"short": 24 * time.Hour}, map[string]bool{"forever": true})
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for _, detection := range []engine.Detection{
		{RuleID: "short", GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"},
		{RuleID: "forever", GroupField: engine.GroupByIP, GroupValue: "192.0.2.11"},
	} {
		if _, err := manager.Process(context.Background(), detection, now); err != nil {
			t.Fatal(err)
		}
	}
	if !blockAction.apply[0].ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("short expiry = %s", blockAction.apply[0].ExpiresAt)
	}
	if got := blockAction.apply[1].ExpiresAt; got.Year() != 9999 {
		t.Fatalf("permanent expiry = %s", got)
	}
}

func TestProcessProgressiveDurationPersistsAndResets(t *testing.T) {
	backend := &testAction{}
	manager, store := newTestManager(t, backend)
	manager.SetRepeatRules(map[string]RepeatRule{"homepage": {Multiplier: 2, Maximum: 4 * time.Minute}})
	ip := "192.0.2.10"
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	detection := engine.Detection{RuleID: "homepage", GroupField: engine.GroupByIP, GroupValue: ip}
	for _, offset := range []time.Duration{0, time.Minute, 3 * time.Minute} {
		if _, err := manager.Process(context.Background(), detection, now.Add(offset)); err != nil {
			t.Fatal(err)
		}
		if err := manager.Cleanup(context.Background(), now.Add(offset+time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if got := []time.Duration{backend.apply[0].ExpiresAt.Sub(now), backend.apply[1].ExpiresAt.Sub(now.Add(time.Minute)), backend.apply[2].ExpiresAt.Sub(now.Add(3 * time.Minute))}; got[0] != time.Minute || got[1] != 2*time.Minute || got[2] != 4*time.Minute {
		t.Fatalf("durations = %v", got)
	}
	// A recreated manager must continue from SQLite, then the seven-day gap resets it.
	recreated, err := New(manager.policy, time.Minute, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	recreated.SetRepeatRules(map[string]RepeatRule{"homepage": {Multiplier: 2, Maximum: 4 * time.Minute}})
	if _, err := recreated.Process(context.Background(), detection, now.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := backend.apply[len(backend.apply)-1].ExpiresAt.Sub(now.Add(8 * 24 * time.Hour)); got != time.Minute {
		t.Fatalf("reset duration = %s", got)
	}
}

func TestProcessSkipsNonIPGrouping(t *testing.T) {
	blockAction := &testAction{}
	manager, _ := newTestManager(t, blockAction)
	result, err := manager.Process(context.Background(), engine.Detection{RuleID: "ua", GroupField: engine.GroupByUserAgent, GroupValue: "curl"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != action.StatusSkipped || result.Reason != string(blockpolicy.ReasonGroupByNotIP) {
		t.Fatalf("result = %+v", result)
	}
	if len(blockAction.apply) != 0 {
		t.Fatal("non-IP grouping reached action")
	}
}

func TestRestoreUsesOriginalExpiryAndRemovesWhitelistedLease(t *testing.T) {
	blockAction := &testAction{}
	manager, store := newTestManager(t, blockAction)
	now := time.Now().Truncate(time.Second)
	blocked := netip.MustParseAddr("192.0.2.10")
	whitelisted := netip.MustParseAddr("2001:db8::10")
	if err := store.RecordBlock(context.Background(), blocked, "homepage", now.Add(-time.Minute), now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordBlock(context.Background(), whitelisted, "homepage", now.Add(-time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), func(ip netip.Addr, ruleID string) bool {
		return ip == whitelisted && ruleID == "homepage"
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(blockAction.apply) != 1 || !blockAction.apply[0].ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("restored actions = %+v", blockAction.apply)
	}
	if len(blockAction.remove) != 1 || blockAction.remove[0] != whitelisted {
		t.Fatalf("removed = %v", blockAction.remove)
	}
	if len(manager.Active()) != 1 {
		t.Fatalf("active state = %+v", manager.Active())
	}
	leases, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].IP != blocked {
		t.Fatalf("stored leases = %+v", leases)
	}
}

func TestUnblockRemovesFirewallAndLease(t *testing.T) {
	blockAction := &testAction{}
	manager, store := newTestManager(t, blockAction)
	ip := netip.MustParseAddr("192.0.2.10")
	now := time.Now()
	if err := store.RecordBlock(context.Background(), ip, "homepage", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	manager.active[ip] = blockpolicy.ActiveBlock{IP: ip, ExpiresAt: now.Add(time.Minute)}
	result := manager.Unblock(context.Background(), ip)
	if result.Status != action.StatusRemoved {
		t.Fatalf("result = %+v", result)
	}
	if len(manager.Active()) != 0 || len(blockAction.remove) != 1 {
		t.Fatalf("active=%v removed=%v", manager.Active(), blockAction.remove)
	}
	leases, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Fatalf("lease remains: %+v", leases)
	}
}

func TestCleanupRemovesExpiredMemoryAndStorageState(t *testing.T) {
	manager, store := newTestManager(t, &testAction{})
	ip := netip.MustParseAddr("192.0.2.10")
	now := time.Now().Truncate(time.Second)
	if err := store.RecordBlock(context.Background(), ip, "homepage", now.Add(-time.Minute), now); err != nil {
		t.Fatal(err)
	}
	manager.active[ip] = blockpolicy.ActiveBlock{IP: ip, ExpiresAt: now}
	if err := manager.Cleanup(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(manager.Active()) != 0 {
		t.Fatalf("active = %+v", manager.Active())
	}
	leases, err := store.UnexpiredBlocks(context.Background(), now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Fatalf("expired lease remains: %+v", leases)
	}
}

func TestCleanupRebuildsActiveMapAfterLargeExpiryBurst(t *testing.T) {
	manager, _ := newTestManager(t, &testAction{})
	now := time.Now().Truncate(time.Second)
	for index := 0; index < minimumActiveMapShrinkSize+1; index++ {
		ip := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		manager.active[ip] = blockpolicy.ActiveBlock{IP: ip, ExpiresAt: now}
	}
	manager.activePeak = len(manager.active)

	if err := manager.Cleanup(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(manager.active) != 0 {
		t.Fatalf("active entries = %d, want 0", len(manager.active))
	}
	if manager.mapRebuilds != 1 || manager.activePeak != 0 {
		t.Fatalf("map rebuilds = %d, peak = %d; want one rebuild and reset peak", manager.mapRebuilds, manager.activePeak)
	}
}

func TestReconcileImportsFirewallAndRemovesAbsentSQLite(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	present := netip.MustParseAddr("192.0.2.8")
	absent := netip.MustParseAddr("192.0.2.9")
	backend := &readableAction{blocks: []action.ManagedBlock{{IP: present, ExpiresAt: now.Add(time.Minute)}}}
	manager, store := newTestManager(t, backend)
	if err := store.RecordBlock(context.Background(), absent, "detected-rule", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.Removed != 1 {
		t.Fatalf("result=%+v", result)
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IP != present || rows[0].Origin != "external" || rows[0].RuleID != "external-firewall" {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestReconcileReadFailureLeavesSQLiteUntouched(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.9")
	backend := &readableAction{err: errors.New("cannot read managed set")}
	manager, store := newTestManager(t, backend)
	if err := store.RecordBlock(context.Background(), ip, "detected-rule", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), now); err == nil {
		t.Fatal("expected read error")
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
}

func TestRemoveWhitelistedRemovesFirewallAndSQLiteLease(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.20")
	backend := &readableAction{}
	manager, store := newTestManager(t, backend)
	if err := store.RecordBlock(context.Background(), ip, "homepage", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	manager.active[ip] = blockpolicy.ActiveBlock{IP: ip, ExpiresAt: now.Add(time.Minute)}
	if err := manager.RemoveWhitelisted(context.Background(), func(got netip.Addr, ruleID string) bool {
		return got == ip && ruleID == "homepage"
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(backend.remove) != 1 || backend.remove[0] != ip {
		t.Fatalf("removed=%v", backend.remove)
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil || len(rows) != 0 || len(manager.Active()) != 0 {
		t.Fatalf("rows=%+v active=%+v err=%v", rows, manager.Active(), err)
	}
}

func TestSynchronizeAppliesSQLiteOnlyLeaseAndImportsFirewallLease(t *testing.T) {
	now := time.Now()
	fromDB := netip.MustParseAddr("192.0.2.21")
	fromFirewall := netip.MustParseAddr("192.0.2.22")
	backend := &readableAction{blocks: []action.ManagedBlock{{IP: fromFirewall, ExpiresAt: now.Add(time.Minute)}}, includeApplied: true}
	manager, store := newTestManager(t, backend)
	if err := store.RecordBlock(context.Background(), fromDB, "homepage", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Synchronize(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(backend.apply) != 1 || backend.apply[0].IP != fromDB {
		t.Fatalf("applied=%+v", backend.apply)
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
}

func TestSynchronizeDoesNotRestoreExternalOrWhitelistedLease(t *testing.T) {
	now := time.Now()
	external := netip.MustParseAddr("192.0.2.31")
	ignored := netip.MustParseAddr("192.0.2.32")
	backend := &readableAction{}
	manager, store := newTestManager(t, backend)
	if _, _, err := store.ReconcileFirewallBlocks(context.Background(), now, []storage.FirewallBlock{{IP: external, ExpiresAt: now.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordBlock(context.Background(), ignored, "homepage", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	manager.SetWhitelist(func(ip netip.Addr, _ string) bool { return ip == ignored })
	if err := manager.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(backend.apply) != 0 {
		t.Fatalf("unexpected firewall applications: %+v", backend.apply)
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil || len(rows) != 0 {
		t.Fatalf("stale SQLite leases: %+v, %v", rows, err)
	}
}

func TestNewWhitelistPreventsDetectionBeforeRestart(t *testing.T) {
	backend := &testAction{}
	manager, _ := newTestManager(t, backend)
	ip := netip.MustParseAddr("192.0.2.44")
	manager.SetWhitelist(func(got netip.Addr, rule string) bool { return got == ip && rule == "homepage" })
	result, err := manager.Process(context.Background(), engine.Detection{RuleID: "homepage", GroupField: engine.GroupByIP, GroupValue: ip.String()}, time.Now())
	if err != nil || result.Status != action.StatusSkipped || len(backend.apply) != 0 {
		t.Fatalf("result=%+v applies=%+v err=%v", result, backend.apply, err)
	}
}

func TestReconcileReplacesExpiredSQLiteLeaseStillPresentInFirewall(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("192.0.2.10")
	backend := &readableAction{blocks: []action.ManagedBlock{{IP: ip, ExpiresAt: now.Add(time.Minute)}}}
	manager, store := newTestManager(t, backend)
	if err := store.RecordBlock(context.Background(), ip, "old-rule", now.Add(-2*time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil || len(rows) != 1 || rows[0].Origin != "external" || rows[0].RuleID != "external-firewall" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
}
