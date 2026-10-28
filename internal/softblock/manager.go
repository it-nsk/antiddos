// Package softblock manages short-lived challenge decisions independently of
// the firewall block manager.
package softblock

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/softfeed"
	"github.com/it-nsk/antiddos/internal/storage"
)

type Outcome string

const (
	OutcomeCreated       Outcome = "created"
	OutcomeAlreadyActive Outcome = "already_active"
	OutcomeSkipped       Outcome = "skipped"
	OutcomeRevoked       Outcome = "revoked"
	OutcomeFailed        Outcome = "failed"
)

type Selector struct {
	SiteID, RuleID string
	IP             netip.Addr
}

type Manager struct {
	mu             sync.Mutex
	policy         *blockpolicy.Policy
	store          *storage.Store
	capacity       int
	active         map[storage.SoftBlockKey]storage.SoftBlockLease
	sourceSite     map[string]string
	ruleSource     map[string]string
	revision       uint64
	config         config.Config
	configRevision string
	changed        chan struct{}
}

func New(policy *blockpolicy.Policy, store *storage.Store, capacity int) (*Manager, error) {
	if policy == nil || store == nil {
		return nil, fmt.Errorf("soft-block manager requires policy and storage")
	}
	if capacity < 1 || capacity > 50000 {
		return nil, fmt.Errorf("soft-block capacity must be between 1 and 50000")
	}
	return &Manager{policy: policy, store: store, capacity: capacity, active: map[storage.SoftBlockKey]storage.SoftBlockLease{}, sourceSite: map[string]string{}, ruleSource: map[string]string{}, changed: make(chan struct{})}, nil
}

func (manager *Manager) Configure(cfg config.Config) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.configureLocked(cfg)
}

func (manager *Manager) configureLocked(cfg config.Config) error {
	if !config.UsesSoftBlock(cfg) {
		manager.sourceSite = map[string]string{}
		manager.ruleSource = map[string]string{}
		manager.config = cfg
		return nil
	}
	sites := map[string]bool{}
	sourceSite := map[string]string{}
	for _, site := range cfg.SoftBlock.Sites {
		sites[site.ID] = true
		for _, source := range site.LogSources {
			if _, ok := sourceSite[source]; ok {
				return fmt.Errorf("source %q belongs to multiple soft-block sites", source)
			}
			sourceSite[source] = site.ID
		}
	}
	ruleSource := map[string]string{}
	for _, rule := range cfg.Engine.Rules {
		if config.EffectiveRuleAction(cfg.BlockMode, rule) != config.RuleActionSoftBlock {
			continue
		}
		site, ok := sourceSite[rule.LogSource]
		if !ok {
			return fmt.Errorf("rule %q uses source without soft-block site", rule.ID)
		}
		if !sites[site] {
			return fmt.Errorf("rule %q has invalid site", rule.ID)
		}
		ruleSource[rule.ID] = rule.LogSource
	}
	manager.sourceSite = sourceSite
	manager.ruleSource = ruleSource
	manager.config = cfg
	return nil
}

func (manager *Manager) SetConfigRevision(revision string) error {
	if revision == "" || len(revision) > 128 {
		return fmt.Errorf("invalid config revision")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.configRevision = revision
	manager.bumpRevisionLocked()
	return nil
}

// FeedSnapshot copies settings and leases under one lock, so readers never
// combine site/cookie settings from one revision with decisions from another.
func (manager *Manager) FeedSnapshot(epoch string, now time.Time) softfeed.Snapshot {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	snapshot := softfeed.Snapshot{Protocol: 1, Epoch: epoch, Revision: manager.revision, Mode: manager.config.BlockMode, ConfigRevision: manager.configRevision, CookieTTL: manager.config.SoftBlock.CookieTTL.String(), Sites: []softfeed.Site{}, Decisions: []softfeed.Decision{}}
	if !config.UsesSoftBlock(manager.config) {
		snapshot.CookieTTL = ""
	}
	for _, site := range manager.config.SoftBlock.Sites {
		snapshot.Sites = append(snapshot.Sites, softfeed.Site{ID: site.ID, Hosts: append([]string(nil), site.Hosts...)})
	}
	for _, lease := range manager.active {
		if lease.ExpiresAt.After(now) {
			snapshot.Decisions = append(snapshot.Decisions, softfeed.Decision{SiteID: lease.SiteID, RuleID: lease.RuleID, SourceID: lease.SourceID, IP: lease.IP.String(), CreatedAt: lease.CreatedAt, ExpiresAt: lease.ExpiresAt})
		}
	}
	sort.Slice(snapshot.Sites, func(i, j int) bool { return snapshot.Sites[i].ID < snapshot.Sites[j].ID })
	sort.Slice(snapshot.Decisions, func(i, j int) bool {
		a, b := snapshot.Decisions[i], snapshot.Decisions[j]
		if a.SiteID != b.SiteID {
			return a.SiteID < b.SiteID
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.IP < b.IP
	})
	return snapshot
}

func (manager *Manager) WaitForRevision(ctx context.Context, revision uint64) {
	manager.mu.Lock()
	if manager.revision != revision {
		manager.mu.Unlock()
		return
	}
	changed := manager.changed
	manager.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-changed:
	}
}

func (manager *Manager) bumpRevisionLocked() {
	manager.revision++
	close(manager.changed)
	manager.changed = make(chan struct{})
}

func (manager *Manager) Process(ctx context.Context, detection engine.Detection, now time.Time) (Outcome, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for key, lease := range manager.active {
		if !lease.ExpiresAt.After(now) {
			delete(manager.active, key)
		}
	}
	source, ruleOK := manager.ruleSource[detection.RuleID]
	site, siteOK := manager.sourceSite[detection.LogSource]
	if !ruleOK || !siteOK || site != detection.SiteID || source != detection.LogSource {
		return OutcomeSkipped, nil
	}
	if detection.GroupField != engine.GroupByIP {
		return OutcomeSkipped, nil
	}
	address, err := netip.ParseAddr(detection.GroupValue)
	if err != nil || !address.IsValid() || address.Zone() != "" {
		return OutcomeSkipped, nil
	}
	address = address.Unmap()
	key := storage.SoftBlockKey{SiteID: site, RuleID: detection.RuleID, IP: address}
	if lease, ok := manager.active[key]; ok && lease.ExpiresAt.After(now) {
		return OutcomeAlreadyActive, nil
	}
	decision, err := manager.policy.Evaluate(detection, now, nil)
	if err != nil {
		return OutcomeFailed, err
	}
	if decision.Outcome != blockpolicy.OutcomeStartBlock {
		return OutcomeSkipped, nil
	}
	if len(manager.active) >= manager.capacity {
		if _, exists := manager.active[key]; !exists {
			return OutcomeFailed, fmt.Errorf("soft-block decision capacity %d reached", manager.capacity)
		}
	}
	lease := storage.SoftBlockLease{SiteID: site, RuleID: detection.RuleID, SourceID: detection.LogSource, IP: address, CreatedAt: now.UTC(), ExpiresAt: decision.ExpiresAt.UTC()}
	created, err := manager.store.PutSoftBlockLease(ctx, lease)
	if err != nil {
		return OutcomeFailed, err
	}
	if !created {
		return OutcomeAlreadyActive, nil
	}
	manager.active[key] = lease
	manager.bumpRevisionLocked()
	return OutcomeCreated, nil
}

// Restore reconciles persistent leases with the current mode, site/rule/source
// graph, expiry, and caller-provided whitelist policy before publishing them.
func (manager *Manager) Restore(ctx context.Context, cfg config.Config, now time.Time, isWhitelisted func(netip.Addr, string) bool) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.configureLocked(cfg); err != nil {
		return err
	}
	leases, err := manager.store.SoftBlockDecisions(ctx)
	if err != nil {
		return err
	}
	validMode := config.UsesSoftBlock(cfg)
	if !validMode {
		keys := make([]storage.SoftBlockKey, 0, len(leases))
		for _, lease := range leases {
			keys = append(keys, storage.SoftBlockKey{SiteID: lease.SiteID, RuleID: lease.RuleID, IP: lease.IP})
		}
		if _, err := manager.store.DeleteSoftBlockDecisions(ctx, keys, "revoked", "mode_disabled", now); err != nil {
			return fmt.Errorf("cancel soft-block decisions after mode change: %w", err)
		}
		manager.active = map[storage.SoftBlockKey]storage.SoftBlockLease{}
		manager.bumpRevisionLocked()
		return nil
	}
	manager.active = map[storage.SoftBlockKey]storage.SoftBlockLease{}
	for _, lease := range leases {
		key := storage.SoftBlockKey{SiteID: lease.SiteID, RuleID: lease.RuleID, IP: lease.IP.Unmap()}
		_, siteOK := manager.sourceSite[lease.SourceID]
		compatible := siteOK && manager.sourceSite[lease.SourceID] == lease.SiteID && manager.ruleSource[lease.RuleID] == lease.SourceID
		reason := ""
		if !lease.ExpiresAt.After(now) {
			reason = "expired"
		} else if !compatible {
			reason = "configuration_changed"
		} else if isWhitelisted != nil && isWhitelisted(key.IP, lease.RuleID) {
			reason = "whitelisted"
		}
		if reason != "" {
			eventType := "revoked"
			if reason == "expired" {
				eventType = "expired"
			}
			if _, err := manager.store.DeleteSoftBlockDecision(ctx, key, eventType, reason, now); err != nil {
				return fmt.Errorf("discard incompatible soft-block decision: %w", err)
			}
			continue
		}
		if len(manager.active) >= manager.capacity {
			return fmt.Errorf("stored soft-block decisions exceed capacity %d", manager.capacity)
		}
		manager.active[key] = lease
	}
	manager.bumpRevisionLocked()
	return nil
}

func (manager *Manager) Revoke(ctx context.Context, selector Selector, now time.Time) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	keys := make([]storage.SoftBlockKey, 0)
	for key := range manager.active {
		if selector.SiteID != "" && selector.SiteID != key.SiteID {
			continue
		}
		if selector.RuleID != "" && selector.RuleID != key.RuleID {
			continue
		}
		if selector.IP.IsValid() && selector.IP.Unmap() != key.IP {
			continue
		}
		keys = append(keys, key)
	}
	if selector.IP.IsValid() && selector.IP.Zone() != "" {
		return 0, fmt.Errorf("IP selector must not have a zone")
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SiteID != keys[j].SiteID {
			return keys[i].SiteID < keys[j].SiteID
		}
		if keys[i].RuleID != keys[j].RuleID {
			return keys[i].RuleID < keys[j].RuleID
		}
		return keys[i].IP.Compare(keys[j].IP) < 0
	})
	removed, err := manager.store.DeleteSoftBlockDecisions(ctx, keys, "revoked", "operator", now)
	if err != nil {
		return 0, fmt.Errorf("revoke soft-block decisions: %w", err)
	}
	for _, key := range keys {
		delete(manager.active, key)
	}
	if removed > 0 {
		manager.bumpRevisionLocked()
	}
	return removed, nil
}

func (manager *Manager) Cleanup(ctx context.Context, now time.Time) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	removed, err := manager.store.PruneSoftBlockDecisions(ctx, now)
	if err != nil {
		return err
	}
	for key, lease := range manager.active {
		if !lease.ExpiresAt.After(now) {
			delete(manager.active, key)
		}
	}
	if removed > 0 {
		manager.bumpRevisionLocked()
	}
	return nil
}

func (manager *Manager) Snapshot(now time.Time) ([]storage.SoftBlockLease, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	result := make([]storage.SoftBlockLease, 0, len(manager.active))
	for _, lease := range manager.active {
		if lease.ExpiresAt.After(now) {
			result = append(result, lease)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.SiteID != b.SiteID {
			return a.SiteID < b.SiteID
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.IP.Compare(b.IP) < 0
	})
	return result, nil
}

func (manager *Manager) Revision() uint64 {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.revision
}
