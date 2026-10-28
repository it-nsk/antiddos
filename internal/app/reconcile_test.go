package app

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/blockmanager"
	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/request"
	"github.com/it-nsk/antiddos/internal/storage"
)

type recordingAction struct {
	applyRequests []action.BlockRequest
	removedIPs    []netip.Addr
	applyStatus   action.Status
	removeStatus  action.Status
}

func (actionRecorder *recordingAction) Apply(_ context.Context, request action.BlockRequest) action.Result {
	actionRecorder.applyRequests = append(actionRecorder.applyRequests, request)
	return action.Result{Status: actionRecorder.applyStatus, IP: request.IP, ExpiresAt: request.ExpiresAt}
}

func (actionRecorder *recordingAction) Remove(_ context.Context, ip netip.Addr) action.Result {
	actionRecorder.removedIPs = append(actionRecorder.removedIPs, ip)
	return action.Result{Status: actionRecorder.removeStatus, IP: ip}
}

func TestReconcileRestoresRemainingLeaseAndRemovesWhitelistedIPs(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	expiresAt := now.Add(time.Minute)
	ignoredIPs := []netip.Addr{
		netip.MustParseAddr("198.51.100.42"),
		netip.MustParseAddr("2001:db8::42"),
	}
	for _, ip := range append(ignoredIPs, netip.MustParseAddr("203.0.113.7")) {
		if err := store.RecordBlock(context.Background(), ip, "homepage", now, expiresAt); err != nil {
			t.Fatal(err)
		}
	}
	ruleEngine, err := engine.NewWithOptions([]engine.Rule{{
		ID: "homepage", PathRegex: "^/$", Window: 5 * time.Second, Threshold: 5, GroupBy: engine.GroupByIP,
	}}, engine.Options{IgnoreIPs: []string{"198.51.100.0/24", "2001:db8::/32"}})
	if err != nil {
		t.Fatal(err)
	}
	blockAction := &recordingAction{applyStatus: action.StatusApplied, removeStatus: action.StatusRemoved}
	policy, err := blockpolicy.New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := blockmanager.New(policy, time.Minute, blockAction, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), func(ip netip.Addr, ruleID string) bool { return ruleEngine.IsIgnoredForRule(ip, ruleID) }, nil); err != nil {
		t.Fatal(err)
	}
	if len(blockAction.removedIPs) != 2 {
		t.Fatalf("removed IPs = %v, want both whitelisted leases", blockAction.removedIPs)
	}
	if len(blockAction.applyRequests) != 1 || blockAction.applyRequests[0].IP.String() != "203.0.113.7" {
		t.Fatalf("restored requests = %+v", blockAction.applyRequests)
	}
	if !blockAction.applyRequests[0].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("restored expiry = %s, want original %s", blockAction.applyRequests[0].ExpiresAt, expiresAt)
	}
	active := manager.Active()
	if len(active) != 1 || !active[netip.MustParseAddr("203.0.113.7")].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("active policy leases = %+v", active)
	}
	remaining, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].IP.String() != "203.0.113.7" {
		t.Fatalf("persisted leases after reconciliation = %+v", remaining)
	}
	if ruleEngine.IsIgnored(request.Event{IP: ignoredIPs[0]}) != true {
		t.Fatal("CIDR whitelist did not match lease IP")
	}
}

func TestReconcileDisabledNFTablesRemovesPersistedLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	store, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	ip := netip.MustParseAddr("192.0.2.44")
	if err := store.RecordBlock(context.Background(), ip, "old-firewall", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingAction{removeStatus: action.StatusRemoved}
	cfg := config.Config{DatabasePath: path, BlockDuration: time.Minute, BlockMode: config.BlockModeHybrid, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "observe", Action: config.RuleActionDryRun}}}}
	if err := ReconcileDisabledNFTables(context.Background(), cfg, recorder, nil); err != nil {
		t.Fatal(err)
	}
	if len(recorder.removedIPs) != 1 || recorder.removedIPs[0] != ip {
		t.Fatalf("removed IPs = %v, want %s", recorder.removedIPs, ip)
	}
	reader, err := storage.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	blocks, err := reader.ActiveBlocks(context.Background(), now, 10)
	if err != nil || len(blocks) != 0 {
		t.Fatalf("remaining blocks = %+v, %v", blocks, err)
	}
}
