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
	mu          sync.Mutex
	policy      *blockpolicy.Policy
	duration    time.Duration
	action      action.Action
	store       *storage.Store
	active      map[netip.Addr]blockpolicy.ActiveBlock
	activePeak  int
	mapRebuilds int
}

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

// Process applies the policy to a detection and performs/persists an eligible block.
func (manager *Manager) Process(ctx context.Context, detection engine.Detection, now time.Time) (action.Result, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
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
	result := manager.action.Apply(ctx, action.BlockRequest{IP: decision.IP, ExpiresAt: decision.ExpiresAt, RuleID: decision.RuleID})
	if result.Status == action.StatusWouldApply || result.Status == action.StatusApplied {
		manager.rememberActive(blockpolicy.ActiveBlock{IP: decision.IP, ExpiresAt: decision.ExpiresAt})
	}
	if result.Status == action.StatusApplied {
		startedAt := decision.ExpiresAt.Add(-manager.duration)
		if err := manager.store.RecordBlock(ctx, decision.IP, decision.RuleID, startedAt, decision.ExpiresAt); err != nil {
			return result, fmt.Errorf("persist active block: %w", err)
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
