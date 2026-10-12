package blockmanager

import (
	"context"
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
	leases, err := store.UnexpiredBlocks(context.Background(), now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || !leases[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("stored leases = %+v", leases)
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
	if err := manager.Restore(context.Background(), func(ip netip.Addr) bool { return ip == whitelisted }, nil); err != nil {
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
