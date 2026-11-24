package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"
)

// BlockStrike returns the next escalation level without mutating it. Levels
// expire after resetAfter so stale offenders return to the base duration.
func (store *Store) BlockStrike(ctx context.Context, ruleID string, ip netip.Addr, now time.Time, resetAfter time.Duration) (int, error) {
	var strikes int
	var last int64
	err := store.db.QueryRowContext(ctx, `SELECT strikes,last_blocked_at_unix_ms FROM block_escalations WHERE rule_id=? AND ip=?`, ruleID, ip.Unmap().String()).Scan(&strikes, &last)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read block escalation: %w", err)
	}
	if now.Sub(time.UnixMilli(last)) > resetAfter {
		return 1, nil
	}
	return strikes + 1, nil
}

// RecordBlockStrike persists one successfully applied block.
func (store *Store) RecordBlockStrike(ctx context.Context, ruleID string, ip netip.Addr, strikes int, now time.Time) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO block_escalations(rule_id,ip,strikes,last_blocked_at_unix_ms) VALUES(?,?,?,?) ON CONFLICT(rule_id,ip) DO UPDATE SET strikes=excluded.strikes,last_blocked_at_unix_ms=excluded.last_blocked_at_unix_ms`, ruleID, ip.Unmap().String(), strikes, now.UnixMilli())
	if err != nil {
		return fmt.Errorf("record block escalation: %w", err)
	}
	return nil
}
