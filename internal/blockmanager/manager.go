// Package blockmanager coordinates block policy, firewall actions, and leases.
package blockmanager

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"sync"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/storage"
)

const minimumActiveMapShrinkSize = 4096

// Manager is the sole owner of active block state. Calls are serialized because
// detections, expiry cleanup, and local unblock requests can arrive concurrently.
type Manager struct {
	mu             sync.Mutex
	policy         *blockpolicy.Policy
	duration       time.Duration
	action         action.Action
	store          *storage.Store
	active         map[netip.Addr]blockpolicy.ActiveBlock
	activePeak     int
	mapRebuilds    int
	whitelist      func(netip.Addr, string) bool
	ruleDurations  map[string]time.Duration
	permanentRules map[string]bool
	repeatRules    map[string]RepeatRule
}

type RepeatRule struct {
	Multiplier int
	Maximum    time.Duration
}

// SetRuleDurations installs per-rule lease overrides from the validated
// configuration. A permanent rule is represented by the latest timestamp the
// storage and firewall APIs can safely carry; it remains removable through the
// normal unblock path.
func (manager *Manager) SetRuleDurations(durations map[string]time.Duration, permanent map[string]bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.ruleDurations = maps.Clone(durations)
	manager.permanentRules = maps.Clone(permanent)
}

func (manager *Manager) SetRepeatRules(rules map[string]RepeatRule) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.repeatRules = maps.Clone(rules)
}

type ReconcileResult struct{ Imported, Removed, Active int }

func New(policy *blockpolicy.Policy, duration time.Duration, blockAction action.Action, store *storage.Store) (*Manager, error) {
	if policy == nil || blockAction == nil || store == nil {
		return nil, fmt.Errorf("block manager requires policy, action, and storage")
	}
	if err := blockpolicy.ValidateDuration(duration); err != nil {
		return nil, err
	}
	return &Manager{policy: policy, duration: duration, action: blockAction, store: store, active: make(map[netip.Addr]blockpolicy.ActiveBlock)}, nil
}

// Restore prunes expired leases, removes newly-whitelisted addresses from the
// firewall, and re-applies remaining leases using their original expiry.
func (manager *Manager) Restore(ctx context.Context, isWhitelisted func(netip.Addr, string) bool, report func(action.Result)) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := time.Now()
	if err := manager.store.PruneExpiredBlocks(ctx, now); err != nil {
		return err
	}
	leases, err := manager.store.UnexpiredBlocks(ctx, now)
	if err != nil {
		return fmt.Errorf("load unexpired block records: %w", err)
	}
	var failures []error
	for _, lease := range leases {
		ip := lease.IP.Unmap()
		if isWhitelisted != nil && isWhitelisted(ip, lease.RuleID) {
			result := manager.action.Remove(ctx, ip)
			if report != nil {
				report(result)
			}
			if result.Status != action.StatusRemoved && result.Status != action.StatusAlreadyAbsent {
				failures = append(failures, fmt.Errorf("remove whitelisted IP %s (status %s): %v", ip, result.Status, result.Err))
				continue
			}
			if err := manager.store.DeleteBlock(ctx, ip); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		if !lease.ExpiresAt.After(now.Add(time.Second)) {
			if err := manager.store.DeleteBlock(ctx, ip); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		result := manager.action.Apply(ctx, action.BlockRequest{IP: ip, ExpiresAt: lease.ExpiresAt, RuleID: lease.RuleID})
		if report != nil {
			report(result)
		}
		if result.Status != action.StatusApplied && result.Status != action.StatusAlreadyActive {
			failures = append(failures, fmt.Errorf("restore block for %s (status %s): %v", ip, result.Status, result.Err))
			continue
		}
		manager.rememberActive(blockpolicy.ActiveBlock{IP: ip, ExpiresAt: lease.ExpiresAt})
	}
	if len(failures) != 0 {
		return fmt.Errorf("restore active blocks: %w", errors.Join(failures...))
	}
	return nil
}

// Reconcile makes the managed firewall sets authoritative. Reading completes
// before any SQLite mutation, so a failed firewall read can never erase a
// lease. It never applies or removes firewall elements.
func (manager *Manager) Reconcile(ctx context.Context, now time.Time) (ReconcileResult, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	reader, ok := manager.action.(action.ManagedBlockReader)
	if !ok {
		return ReconcileResult{}, fmt.Errorf("configured action cannot read managed firewall sets")
	}
	firewall, err := reader.ReadManagedBlocks(ctx)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("read managed firewall blocks: %w", err)
	}
	present := make(map[netip.Addr]action.ManagedBlock, len(firewall))
	for _, block := range firewall {
		if !block.IP.IsValid() || !block.ExpiresAt.After(now) {
			continue
		}
		present[block.IP.Unmap()] = block
	}
	snapshot := make([]storage.FirewallBlock, 0, len(present))
	for _, block := range present {
		snapshot = append(snapshot, storage.FirewallBlock{IP: block.IP, ExpiresAt: block.ExpiresAt})
	}
	imported, removed, err := manager.store.ReconcileFirewallBlocks(ctx, now, snapshot)
	if err != nil {
		return ReconcileResult{}, err
	}
	result := ReconcileResult{Imported: imported, Removed: removed, Active: len(present)}
	for ip, block := range present {
		manager.rememberActive(blockpolicy.ActiveBlock{IP: ip, ExpiresAt: block.ExpiresAt})
	}
	for ip := range manager.active {
		if _, ok := present[ip]; !ok {
			delete(manager.active, ip)
		}
	}
	manager.shrinkActiveIfNeeded()
	return result, nil
}

func (manager *Manager) ReconcileFirewall(ctx context.Context) error {
	if err := manager.Synchronize(ctx, time.Now()); err != nil {
		return err
	}
	manager.mu.Lock()
	whitelist := manager.whitelist
	manager.mu.Unlock()
	return manager.RemoveWhitelisted(ctx, whitelist, nil)
}

// SetWhitelist installs the daemon's current explicit whitelist for manual
// two-way synchronization requests.
func (manager *Manager) SetWhitelist(whitelist func(netip.Addr, string) bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.whitelist = whitelist
}

func (manager *Manager) RemoveConfiguredWhitelist(ctx context.Context, report func(action.Result)) error {
	manager.mu.Lock()
	whitelist := manager.whitelist
	manager.mu.Unlock()
	return manager.RemoveWhitelisted(ctx, whitelist, report)
}

// Synchronize is the explicit two-way operation: firewall-only leases are
// imported into SQLite and SQLite-only leases are applied to the managed
// firewall. Background reconciliation intentionally remains firewall-first.
func (manager *Manager) Synchronize(ctx context.Context, now time.Time) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	reader, ok := manager.action.(action.ManagedBlockReader)
	if !ok {
		return fmt.Errorf("configured action cannot read managed firewall sets")
	}
	firewall, err := reader.ReadManagedBlocks(ctx)
	if err != nil {
		return fmt.Errorf("read managed firewall blocks: %w", err)
	}
	present := make(map[netip.Addr]action.ManagedBlock, len(firewall))
	for _, block := range firewall {
		if block.IP.IsValid() && block.ExpiresAt.After(now) {
			present[block.IP.Unmap()] = block
		}
	}
	leases, err := manager.store.UnexpiredBlocks(ctx, now)
	if err != nil {
		return fmt.Errorf("load SQLite blocks for synchronization: %w", err)
	}
	for _, lease := range leases {
		ip := lease.IP.Unmap()
		if _, exists := present[ip]; exists {
			continue
		}
		// An imported lease has no backend/rule identity. Once absent from
		// the firewall it must expire, not resurrect from SQLite.
		if lease.Origin == "external" || (manager.whitelist != nil && manager.whitelist(ip, lease.RuleID)) {
			continue
		}
		result := manager.action.Apply(ctx, action.BlockRequest{IP: ip, ExpiresAt: lease.ExpiresAt, RuleID: lease.RuleID})
		if result.Status != action.StatusApplied && result.Status != action.StatusAlreadyActive && result.Status != action.StatusWouldApply {
			return fmt.Errorf("apply SQLite block %s (status %s): %v", ip, result.Status, result.Err)
		}
	}
	// Read back actual expirations: an existing nft element may retain its
	// earlier timeout even when Apply reports that it is already active.
	firewall, err = reader.ReadManagedBlocks(ctx)
	if err != nil {
		return fmt.Errorf("verify managed firewall blocks: %w", err)
	}
	present = make(map[netip.Addr]action.ManagedBlock, len(firewall))
	for _, block := range firewall {
		if block.IP.IsValid() && block.ExpiresAt.After(now) {
			present[block.IP.Unmap()] = block
		}
	}
	snapshot := make([]storage.FirewallBlock, 0, len(present))
	for _, block := range present {
		snapshot = append(snapshot, storage.FirewallBlock{IP: block.IP, ExpiresAt: block.ExpiresAt})
	}
	if _, _, err := manager.store.ReconcileFirewallBlocks(ctx, now, snapshot); err != nil {
		return err
	}
	for ip, block := range present {
		manager.rememberActive(blockpolicy.ActiveBlock{IP: ip, ExpiresAt: block.ExpiresAt})
	}
	for ip := range manager.active {
		if _, ok := present[ip]; !ok {
			delete(manager.active, ip)
		}
	}
	manager.shrinkActiveIfNeeded()
	return nil
}

// RemoveWhitelisted removes leases for addresses that an explicit current
// whitelist exempts. The caller must reconcile successfully first: firewall
// state normally remains authoritative, while a whitelist is a deliberate
// operator override.
func (manager *Manager) RemoveWhitelisted(ctx context.Context, isWhitelisted func(netip.Addr, string) bool, report func(action.Result)) error {
	if isWhitelisted == nil {
		return nil
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	leases, err := manager.store.UnexpiredBlocks(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("load active blocks for whitelist: %w", err)
	}
	var failures []error
	for _, lease := range leases {
		ip := lease.IP.Unmap()
		if !isWhitelisted(ip, lease.RuleID) {
			continue
		}
		result := manager.action.Remove(ctx, ip)
		if report != nil {
			report(result)
		}
		if result.Status != action.StatusRemoved && result.Status != action.StatusAlreadyAbsent && result.Status != action.StatusWouldRemove {
			failures = append(failures, fmt.Errorf("remove whitelisted IP %s (status %s): %v", ip, result.Status, result.Err))
			continue
		}
		if err := manager.store.DeleteBlock(ctx, ip); err != nil {
			failures = append(failures, err)
			continue
		}
		delete(manager.active, ip)
	}
	manager.shrinkActiveIfNeeded()
	if len(failures) != 0 {
		return fmt.Errorf("remove whitelisted blocks: %w", errors.Join(failures...))
	}
	return nil
}

// Process applies the policy to a detection and performs/persists an eligible block.
func (manager *Manager) Process(ctx context.Context, detection engine.Detection, now time.Time) (action.Result, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if detection.GroupField == engine.GroupByIP && manager.whitelist != nil {
		if ip, err := netip.ParseAddr(detection.GroupValue); err == nil && manager.whitelist(ip.Unmap(), detection.RuleID) {
			return action.Result{Status: action.StatusSkipped, IP: ip.Unmap(), Reason: "address is whitelisted"}, nil
		}
	}
	var current *blockpolicy.ActiveBlock
	if detection.GroupField == engine.GroupByIP {
		if ip, err := netip.ParseAddr(detection.GroupValue); err == nil {
			ip = ip.Unmap()
			if block, ok := manager.active[ip]; ok {
				current = &block
			}
		}
	}
	decision, err := manager.policy.Evaluate(detection, now, current)
	if err != nil {
		return action.Result{Status: action.StatusFailed, Err: err}, nil
	}
	if decision.Outcome == blockpolicy.OutcomeSkip {
		return action.Result{Status: action.StatusSkipped, Reason: string(decision.Reason)}, nil
	}
	if decision.Outcome == blockpolicy.OutcomeKeepExistingBlock {
		return action.Result{Status: action.StatusAlreadyActive, IP: decision.IP, ExpiresAt: decision.ExpiresAt, Reason: string(decision.Reason)}, nil
	}
	if manager.permanentRules[detection.RuleID] {
		decision.ExpiresAt = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	} else if duration, ok := manager.ruleDurations[detection.RuleID]; ok {
		decision.ExpiresAt = now.Add(duration)
	}
	strike := 0
	if repeat, ok := manager.repeatRules[detection.RuleID]; ok && repeat.Multiplier > 1 && repeat.Maximum > 0 {
		level, err := manager.store.BlockStrike(ctx, detection.RuleID, decision.IP, now, 7*24*time.Hour)
		if err != nil {
			return action.Result{Status: action.StatusFailed, IP: decision.IP, Err: err}, err
		}
		base := decision.ExpiresAt.Sub(now)
		for n := 1; n < level && base < repeat.Maximum; n++ {
			// Do not multiply first: a large valid Go duration can overflow
			// before it is capped, turning a block into a negative lease.
			if base > repeat.Maximum/time.Duration(repeat.Multiplier) {
				base = repeat.Maximum
				break
			}
			base *= time.Duration(repeat.Multiplier)
		}
		decision.ExpiresAt = now.Add(base)
		strike = level
	}
	result := manager.action.Apply(ctx, action.BlockRequest{IP: decision.IP, ExpiresAt: decision.ExpiresAt, RuleID: decision.RuleID})
	if result.Status == action.StatusWouldApply || result.Status == action.StatusApplied {
		manager.rememberActive(blockpolicy.ActiveBlock{IP: decision.IP, ExpiresAt: decision.ExpiresAt})
	}
	if result.Status == action.StatusApplied {
		if err := manager.store.RecordBlock(ctx, decision.IP, decision.RuleID, now, decision.ExpiresAt); err != nil {
			return result, fmt.Errorf("persist active block: %w", err)
		}
		if strike > 0 {
			if err := manager.store.RecordBlockStrike(ctx, decision.RuleID, decision.IP, strike, now); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

// Cleanup removes expired in-memory entries and their persisted leases. nftables
// independently expires firewall elements; this is one shared maintenance pass.
func (manager *Manager) Cleanup(ctx context.Context, now time.Time) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for ip, block := range manager.active {
		if !block.ExpiresAt.After(now) {
			delete(manager.active, ip)
		}
	}
	manager.shrinkActiveIfNeeded()
	return manager.store.PruneExpiredBlocks(ctx, now)
}

// RunCleanup owns the single shared expiry ticker for all active leases.
func (manager *Manager) RunCleanup(ctx context.Context, interval time.Duration, reportError func(error)) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := manager.Cleanup(ctx, now); err != nil && reportError != nil {
				reportError(err)
			}
		}
	}
}

// Unblock removes one exact address from firewall and lease state.
func (manager *Manager) Unblock(ctx context.Context, ip netip.Addr) action.Result {
	if !ip.IsValid() {
		return action.Result{Status: action.StatusFailed, IP: ip, Err: fmt.Errorf("invalid IP address")}
	}
	ip = ip.Unmap()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	result := manager.action.Remove(ctx, ip)
	if result.Status != action.StatusRemoved && result.Status != action.StatusAlreadyAbsent && result.Status != action.StatusWouldRemove {
		return result
	}
	delete(manager.active, ip)
	manager.shrinkActiveIfNeeded()
	if err := manager.store.DeleteBlock(ctx, ip); err != nil {
		return action.Result{Status: action.StatusFailed, IP: ip, Err: fmt.Errorf("delete block lease: %w", err)}
	}
	return result
}

func (manager *Manager) rememberActive(block blockpolicy.ActiveBlock) {
	manager.active[block.IP] = block
	if len(manager.active) > manager.activePeak {
		manager.activePeak = len(manager.active)
	}
}

// Go maps keep their backing buckets after deletes. Rebuild only after a large
// spike has mostly expired so the long-running daemon can release that heap.
func (manager *Manager) shrinkActiveIfNeeded() {
	count := len(manager.active)
	if count == 0 {
		if manager.activePeak >= minimumActiveMapShrinkSize {
			manager.active = make(map[netip.Addr]blockpolicy.ActiveBlock)
			manager.mapRebuilds++
		}
		manager.activePeak = 0
		return
	}
	if manager.activePeak < minimumActiveMapShrinkSize || count > manager.activePeak/4 {
		return
	}
	manager.active = maps.Clone(manager.active)
	manager.activePeak = count
	manager.mapRebuilds++
}

// Active returns a copy for diagnostics and tests.
func (manager *Manager) Active() map[netip.Addr]blockpolicy.ActiveBlock {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	copy := make(map[netip.Addr]blockpolicy.ActiveBlock, len(manager.active))
	for ip, block := range manager.active {
		copy[ip] = block
	}
	return copy
}
