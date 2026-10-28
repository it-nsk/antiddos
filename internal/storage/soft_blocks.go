package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"
)

// SoftBlockLease is a server-side challenge decision; it is independent from
// active_blocks and must never be described as a firewall block.
type SoftBlockLease struct {
	SiteID    string     `json:"site_id"`
	RuleID    string     `json:"rule_id"`
	SourceID  string     `json:"source_id"`
	IP        netip.Addr `json:"ip"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
}

type SoftBlockKey struct {
	SiteID, RuleID string
	IP             netip.Addr
}

type SoftBlockEvent struct {
	ID           int64
	Type, Reason string
	Lease        SoftBlockLease
	At           time.Time
}

// ActiveSoftBlocks reads bounded, unexpired challenge decisions without
// presenting them as firewall blocks.
func (reader *Reader) ActiveSoftBlocks(ctx context.Context, now time.Time, limit int) ([]SoftBlockLease, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}
	rows, err := reader.db.QueryContext(ctx, `SELECT site_id,rule_id,source_id,ip,created_at_unix_ms,expires_at_unix_ms FROM soft_block_decisions WHERE expires_at_unix_ms > ? ORDER BY expires_at_unix_ms DESC,site_id,rule_id,ip LIMIT ?`, now.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SoftBlockLease{}
	for rows.Next() {
		var lease SoftBlockLease
		var ip string
		var created, expires int64
		if err := rows.Scan(&lease.SiteID, &lease.RuleID, &lease.SourceID, &ip, &created, &expires); err != nil {
			return nil, err
		}
		lease.IP, err = netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid soft-block IP: %w", err)
		}
		lease.CreatedAt, lease.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
		result = append(result, lease)
	}
	return result, rows.Err()
}

// CreateSoftBlockLease inserts a new decision and its audit row atomically.
func (store *Store) CreateSoftBlockLease(ctx context.Context, lease SoftBlockLease) error {
	_, err := store.PutSoftBlockLease(ctx, lease)
	return err
}

// PutSoftBlockLease preserves an unexpired conflicting key. An expired lease
// may be replaced, with the replacement and its audit event in one transaction.
func (store *Store) PutSoftBlockLease(ctx context.Context, lease SoftBlockLease) (bool, error) {
	if err := validateSoftLease(lease); err != nil {
		return false, err
	}
	lease.IP = lease.IP.Unmap()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin soft-block decision: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO soft_block_decisions(site_id,rule_id,source_id,ip,created_at_unix_ms,expires_at_unix_ms)
		VALUES(?,?,?,?,?,?) ON CONFLICT(site_id,rule_id,ip) DO UPDATE SET source_id=excluded.source_id,created_at_unix_ms=excluded.created_at_unix_ms,expires_at_unix_ms=excluded.expires_at_unix_ms
		WHERE soft_block_decisions.expires_at_unix_ms <= excluded.created_at_unix_ms`, lease.SiteID, lease.RuleID, lease.SourceID, lease.IP.String(), lease.CreatedAt.UnixMilli(), lease.ExpiresAt.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("write soft-block decision: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed == 0 {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit duplicate soft-block decision: %w", err)
		}
		return false, nil
	}
	if err := insertSoftBlockEvent(ctx, tx, "created", "threshold", lease, lease.CreatedAt); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit soft-block decision: %w", err)
	}
	return true, nil
}

func validateSoftLease(lease SoftBlockLease) error {
	if lease.SiteID == "" || lease.RuleID == "" || lease.SourceID == "" {
		return fmt.Errorf("soft-block lease requires site, rule, and source IDs")
	}
	if !lease.IP.IsValid() || lease.IP.Zone() != "" {
		return fmt.Errorf("soft-block lease requires a valid unzoned IP")
	}
	if !lease.ExpiresAt.After(lease.CreatedAt) {
		return fmt.Errorf("soft-block lease expiry must follow creation")
	}
	return nil
}

func insertSoftBlockEvent(ctx context.Context, tx *sql.Tx, eventType, reason string, lease SoftBlockLease, at time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO soft_block_events(event_type,reason,site_id,rule_id,source_id,ip,at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?,?,?)`, eventType, reason, lease.SiteID, lease.RuleID, lease.SourceID, lease.IP.Unmap().String(), at.UnixMilli(), lease.ExpiresAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("write soft-block audit event: %w", err)
	}
	return nil
}

func (store *Store) SoftBlockDecisions(ctx context.Context) ([]SoftBlockLease, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT site_id,rule_id,source_id,ip,created_at_unix_ms,expires_at_unix_ms FROM soft_block_decisions ORDER BY site_id,rule_id,ip`)
	if err != nil {
		return nil, fmt.Errorf("list soft-block decisions: %w", err)
	}
	defer rows.Close()
	var result []SoftBlockLease
	for rows.Next() {
		var lease SoftBlockLease
		var ip string
		var created, expires int64
		if err := rows.Scan(&lease.SiteID, &lease.RuleID, &lease.SourceID, &ip, &created, &expires); err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid IP in soft-block decision: %w", err)
		}
		lease.IP = address
		lease.CreatedAt = time.UnixMilli(created).UTC()
		lease.ExpiresAt = time.UnixMilli(expires).UTC()
		result = append(result, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate soft-block decisions: %w", err)
	}
	return result, nil
}

func (store *Store) DeleteSoftBlockDecision(ctx context.Context, key SoftBlockKey, eventType, reason string, now time.Time) (bool, error) {
	if !key.IP.IsValid() || key.IP.Zone() != "" || key.SiteID == "" || key.RuleID == "" {
		return false, fmt.Errorf("invalid soft-block decision key")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var lease SoftBlockLease
	var ip string
	var created, expires int64
	err = tx.QueryRowContext(ctx, `SELECT site_id,rule_id,source_id,ip,created_at_unix_ms,expires_at_unix_ms FROM soft_block_decisions WHERE site_id=? AND rule_id=? AND ip=?`, key.SiteID, key.RuleID, key.IP.Unmap().String()).Scan(&lease.SiteID, &lease.RuleID, &lease.SourceID, &ip, &created, &expires)
	if err == sql.ErrNoRows {
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	lease.IP, _ = netip.ParseAddr(ip)
	lease.CreatedAt = time.UnixMilli(created).UTC()
	lease.ExpiresAt = time.UnixMilli(expires).UTC()
	if _, err = tx.ExecContext(ctx, `DELETE FROM soft_block_decisions WHERE site_id=? AND rule_id=? AND ip=?`, key.SiteID, key.RuleID, key.IP.Unmap().String()); err != nil {
		return false, err
	}
	if err = insertSoftBlockEvent(ctx, tx, eventType, reason, lease, now); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, fmt.Errorf("commit soft-block decision deletion: %w", err)
	}
	return true, nil
}

// DeleteSoftBlockDecisions performs a cancellation as one SQL transaction so
// failed audit writes cannot leave only part of a selected set revoked.
func (store *Store) DeleteSoftBlockDecisions(ctx context.Context, keys []SoftBlockKey, eventType, reason string, now time.Time) (int, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	deleted := 0
	for _, key := range keys {
		var lease SoftBlockLease
		var ip string
		var created, expires int64
		err := tx.QueryRowContext(ctx, `SELECT site_id,rule_id,source_id,ip,created_at_unix_ms,expires_at_unix_ms FROM soft_block_decisions WHERE site_id=? AND rule_id=? AND ip=?`, key.SiteID, key.RuleID, key.IP.Unmap().String()).Scan(&lease.SiteID, &lease.RuleID, &lease.SourceID, &ip, &created, &expires)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return deleted, err
		}
		lease.IP, _ = netip.ParseAddr(ip)
		lease.CreatedAt = time.UnixMilli(created).UTC()
		lease.ExpiresAt = time.UnixMilli(expires).UTC()
		if _, err = tx.ExecContext(ctx, `DELETE FROM soft_block_decisions WHERE site_id=? AND rule_id=? AND ip=?`, key.SiteID, key.RuleID, key.IP.Unmap().String()); err != nil {
			return deleted, err
		}
		if err = insertSoftBlockEvent(ctx, tx, eventType, reason, lease, now); err != nil {
			return deleted, err
		}
		deleted++
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit soft-block decision cancellation: %w", err)
	}
	return deleted, nil
}

func (store *Store) PruneSoftBlockDecisions(ctx context.Context, now time.Time) (int, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT site_id,rule_id,source_id,ip,created_at_unix_ms,expires_at_unix_ms FROM soft_block_decisions WHERE expires_at_unix_ms<=?`, now.UnixMilli())
	if err != nil {
		return 0, err
	}
	var leases []SoftBlockLease
	for rows.Next() {
		var l SoftBlockLease
		var ip string
		var c, e int64
		if err := rows.Scan(&l.SiteID, &l.RuleID, &l.SourceID, &ip, &c, &e); err != nil {
			rows.Close()
			return 0, err
		}
		l.IP, _ = netip.ParseAddr(ip)
		l.CreatedAt = time.UnixMilli(c).UTC()
		l.ExpiresAt = time.UnixMilli(e).UTC()
		leases = append(leases, l)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM soft_block_decisions WHERE expires_at_unix_ms<=?`, now.UnixMilli()); err != nil {
		return 0, err
	}
	for _, l := range leases {
		if err := insertSoftBlockEvent(ctx, tx, "expired", "ttl", l, now); err != nil {
			return 0, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM soft_block_events WHERE at_unix_ms<?`, now.Add(-7*24*time.Hour).UnixMilli()); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM soft_block_events WHERE id NOT IN (SELECT id FROM soft_block_events ORDER BY id DESC LIMIT 100000)`); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit soft-block cleanup: %w", err)
	}
	return len(leases), nil
}

func (store *Store) SoftBlockEvents(ctx context.Context, limit int) ([]SoftBlockEvent, error) {
	if limit < 1 || limit > 100000 {
		return nil, fmt.Errorf("audit limit must be between 1 and 100000")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT id,event_type,reason,site_id,rule_id,source_id,ip,at_unix_ms,expires_at_unix_ms FROM soft_block_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SoftBlockEvent
	for rows.Next() {
		var e SoftBlockEvent
		var ip string
		var at, expires int64
		if err := rows.Scan(&e.ID, &e.Type, &e.Reason, &e.Lease.SiteID, &e.Lease.RuleID, &e.Lease.SourceID, &ip, &at, &expires); err != nil {
			return nil, err
		}
		e.Lease.IP, err = netip.ParseAddr(ip)
		if err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at).UTC()
		e.Lease.ExpiresAt = time.UnixMilli(expires).UTC()
		result = append(result, e)
	}
	return result, rows.Err()
}
