package softblock

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/softfeed"
	"github.com/it-nsk/antiddos/internal/storage"
)

func TestProcessUsesSiteRuleIPKeyAndDoesNotExtend(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, err := blockpolicy.New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(policy, store, 100)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Config{BlockMode: config.BlockModeSoftBlock, SoftBlock: config.SoftBlockConfig{Sites: []config.SiteConfig{{ID: "main", LogSources: []string{"web"}}}}, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "r", LogSource: "web"}, {ID: "r2", LogSource: "web"}}}}
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	detection := engine.Detection{SiteID: "main", RuleID: "r", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: "::ffff:192.0.2.5"}
	first, err := manager.Process(context.Background(), detection, now)
	if err != nil || first != OutcomeCreated {
		t.Fatalf("first=%s err=%v", first, err)
	}
	second, err := manager.Process(context.Background(), detection, now.Add(30*time.Second))
	if err != nil || second != OutcomeAlreadyActive {
		t.Fatalf("repeat=%s err=%v", second, err)
	}
	leases, err := manager.Snapshot(now.Add(30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].IP.String() != "192.0.2.5" || !leases[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("snapshot=%+v", leases)
	}
	detection.RuleID = "r2"
	if outcome, err := manager.Process(context.Background(), detection, now.Add(30*time.Second)); err != nil || outcome != OutcomeCreated {
		t.Fatalf("independent rule outcome=%s err=%v", outcome, err)
	}
}

func TestManagerFeedSnapshotPublishesSettingsAndDecisionsConsistently(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, _ := blockpolicy.New(time.Minute)
	manager, _ := New(policy, store, 100)
	now := time.Now().UTC()
	cfg := config.Config{BlockMode: config.BlockModeSoftBlock, SoftBlock: config.SoftBlockConfig{CookieTTL: 30 * time.Minute, Sites: []config.SiteConfig{{ID: "main", Hosts: []string{"example.test"}, LogSources: []string{"web"}}}}, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "r", LogSource: "web"}}}}
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetConfigRevision("cfg-42"); err != nil {
		t.Fatal(err)
	}
	d := engine.Detection{SiteID: "main", RuleID: "r", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"}
	if outcome, err := manager.Process(context.Background(), d, now); err != nil || outcome != OutcomeCreated {
		t.Fatalf("process=%s %v", outcome, err)
	}
	snapshot := manager.FeedSnapshot("epoch-test", now)
	if snapshot.ConfigRevision != "cfg-42" || snapshot.CookieTTL != "30m0s" || len(snapshot.Sites) != 1 || len(snapshot.Decisions) != 1 {
		t.Fatalf("feed snapshot=%+v", snapshot)
	}
	raw, err := softfeed.BuildSnapshotJSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	state := softfeed.NewState()
	if err := state.ApplyJSON(raw, now); err != nil {
		t.Fatal(err)
	}
	if got := state.Check("main", netip.MustParseAddr("192.0.2.10"), now); !got.Challenge {
		t.Fatalf("published decision unavailable to feed client: %+v", got)
	}
}

func TestHybridManagerAcceptsOnlySoftBlockRules(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, _ := blockpolicy.New(time.Minute)
	manager, _ := New(policy, store, 100)
	now := time.Now().UTC()
	cfg := config.Config{
		BlockMode: config.BlockModeHybrid,
		SoftBlock: config.SoftBlockConfig{CookieTTL: 30 * time.Minute, Sites: []config.SiteConfig{{ID: "main", Hosts: []string{"example.test"}, LogSources: []string{"web"}}}},
		Engine: config.EngineConfig{Rules: []config.RuleConfig{
			{ID: "captcha", Action: config.RuleActionSoftBlock, LogSource: "web"},
			{ID: "firewall", Action: config.RuleActionNFTables, LogSource: "web"},
		}},
	}
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	soft := engine.Detection{SiteID: "main", RuleID: "captcha", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"}
	if outcome, err := manager.Process(context.Background(), soft, now); err != nil || outcome != OutcomeCreated {
		t.Fatalf("soft outcome=%s err=%v", outcome, err)
	}
	firewall := soft
	firewall.RuleID = "firewall"
	if outcome, err := manager.Process(context.Background(), firewall, now); err != nil || outcome != OutcomeSkipped {
		t.Fatalf("firewall outcome=%s err=%v", outcome, err)
	}
	snapshot := manager.FeedSnapshot("hybrid-epoch", now)
	if snapshot.Mode != config.BlockModeHybrid || len(snapshot.Decisions) != 1 || snapshot.Decisions[0].RuleID != "captcha" {
		t.Fatalf("hybrid feed=%+v", snapshot)
	}
}

func TestRevokeScopesBySiteRuleAndIP(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, _ := blockpolicy.New(time.Minute)
	manager, _ := New(policy, store, 100)
	now := time.Now().UTC()
	cfg := config.Config{BlockMode: config.BlockModeSoftBlock, SoftBlock: config.SoftBlockConfig{Sites: []config.SiteConfig{{ID: "main", LogSources: []string{"web"}}, {ID: "other", LogSources: []string{"web2"}}}}, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "a", LogSource: "web"}, {ID: "b", LogSource: "web"}, {ID: "c", LogSource: "web2"}}}}
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range []engine.Detection{{SiteID: "main", RuleID: "a", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: "192.0.2.1"}, {SiteID: "main", RuleID: "b", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: "192.0.2.1"}, {SiteID: "other", RuleID: "c", LogSource: "web2", GroupField: engine.GroupByIP, GroupValue: "192.0.2.1"}} {
		if _, err := manager.Process(context.Background(), d, now); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := manager.Revoke(context.Background(), Selector{SiteID: "main", RuleID: "a", IP: netip.MustParseAddr("192.0.2.1")}, now)
	if err != nil || removed != 1 {
		t.Fatalf("revoke=%d err=%v", removed, err)
	}
	leases, _ := manager.Snapshot(now)
	if len(leases) != 2 {
		t.Fatalf("after scoped revoke: %+v", leases)
	}
	removed, err = manager.Revoke(context.Background(), Selector{}, now)
	if err != nil || removed != 2 {
		t.Fatalf("global revoke=%d err=%v", removed, err)
	}
}

func TestRestoreWhitelistAndModeDisableCancelLeases(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	for _, item := range []struct{ ip, rule string }{{"192.0.2.1", "r"}, {"192.0.2.1", "r2"}, {"192.0.2.2", "r"}} {
		if err := store.CreateSoftBlockLease(context.Background(), storage.SoftBlockLease{SiteID: "main", RuleID: item.rule, SourceID: "web", IP: netip.MustParseAddr(item.ip), CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	policy, _ := blockpolicy.New(time.Minute)
	manager, _ := New(policy, store, 100)
	cfg := config.Config{BlockMode: config.BlockModeSoftBlock, SoftBlock: config.SoftBlockConfig{Sites: []config.SiteConfig{{ID: "main", LogSources: []string{"web"}}}}, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "r", LogSource: "web"}, {ID: "r2", LogSource: "web"}}}}
	if err := manager.Restore(context.Background(), cfg, now, func(ip netip.Addr, rule string) bool { return ip.String() == "192.0.2.1" && rule == "r" }); err != nil {
		t.Fatal(err)
	}
	leases, _ := manager.Snapshot(now)
	if len(leases) != 2 || !(leases[0].IP.String() == "192.0.2.1" && leases[0].RuleID == "r2" || leases[1].IP.String() == "192.0.2.1" && leases[1].RuleID == "r2") {
		t.Fatalf("whitelist restore=%+v", leases)
	}
	cfg.BlockMode = config.BlockModeDryRun
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	leases, _ = manager.Snapshot(now)
	persisted, err := store.SoftBlockDecisions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 || len(persisted) != 0 {
		t.Fatalf("mode disable left decisions: memory=%+v persisted=%+v", leases, persisted)
	}
}

func TestProcessDatabaseErrorDoesNotPublishInMemoryDecision(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, _ := blockpolicy.New(time.Minute)
	manager, _ := New(policy, store, 100)
	now := time.Now().UTC()
	cfg := config.Config{BlockMode: config.BlockModeSoftBlock, SoftBlock: config.SoftBlockConfig{Sites: []config.SiteConfig{{ID: "main", LogSources: []string{"web"}}}}, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "r", LogSource: "web"}}}}
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	d := engine.Detection{SiteID: "main", RuleID: "r", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: "192.0.2.8"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if outcome, err := manager.Process(ctx, d, now); err == nil || outcome != OutcomeFailed {
		t.Fatalf("cancelled SQL outcome=%s err=%v", outcome, err)
	}
	leases, _ := manager.Snapshot(now)
	if len(leases) != 0 {
		t.Fatalf("failed SQL published memory state: %+v", leases)
	}
}

func TestRestoreDropsExpiredAndIncompatibleLeases(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, lease := range []storage.SoftBlockLease{
		{SiteID: "main", RuleID: "r", SourceID: "web", IP: netip.MustParseAddr("192.0.2.1"), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		{SiteID: "gone", RuleID: "r", SourceID: "web", IP: netip.MustParseAddr("192.0.2.2"), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		{SiteID: "main", RuleID: "r", SourceID: "web", IP: netip.MustParseAddr("192.0.2.3"), CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now},
	} {
		if err := store.CreateSoftBlockLease(context.Background(), lease); err != nil {
			t.Fatal(err)
		}
	}
	policy, _ := blockpolicy.New(time.Minute)
	manager, _ := New(policy, store, 100)
	cfg := config.Config{BlockMode: config.BlockModeSoftBlock, SoftBlock: config.SoftBlockConfig{Sites: []config.SiteConfig{{ID: "main", LogSources: []string{"web"}}}}, Engine: config.EngineConfig{Rules: []config.RuleConfig{{ID: "r", LogSource: "web"}}}}
	if err := manager.Restore(context.Background(), cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	leases, err := manager.Snapshot(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].IP.String() != "192.0.2.1" {
		t.Fatalf("restored=%+v", leases)
	}
}

func TestSoftBlockLeaseMigrationLeavesLegacyFirewallTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	store, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateSoftBlockLease(context.Background(), storage.SoftBlockLease{SiteID: "s", RuleID: "r", SourceID: "web", IP: netip.MustParseAddr("2001:db8::1"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.RecordBlock(context.Background(), netip.MustParseAddr("203.0.113.8"), "legacy", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rows, err := store.UnexpiredBlocks(context.Background(), now)
	if err != nil || len(rows) != 1 || rows[0].RuleID != "legacy" {
		t.Fatalf("legacy firewall rows=%+v err=%v", rows, err)
	}
}
