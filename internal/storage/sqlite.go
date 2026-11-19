// Package storage persists traffic summaries and rule detections in SQLite.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/request"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) { return open(path, 5*time.Second) }

// OpenHistoricalPublisher opens the live database for the brief final history
// publication. It tolerates an ordinary daemon write without requiring the
// daemon to stop or a separate maintenance window.
func OpenHistoricalPublisher(path string) (*Store, error) { return open(path, time.Minute) }

func open(path string, busyTimeout time.Duration) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("SQLite path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create SQLite directory: %w", err)
	}

	u := &url.URL{Scheme: "file", Path: filepath.Clean(path)}
	query := u.Query()
	query.Set("_busy_timeout", fmt.Sprintf("%d", busyTimeout.Milliseconds()))
	u.RawQuery = query.Encode()
	dsn := u.String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &Store{db: db}
	if err := store.configure(context.Background(), busyTimeout); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.createSchema(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	// The daemon owns the database, while the authenticated web process runs
	// in the antiddos supplementary group and may publish reviewed historical
	// results. Group write is required for SQLite WAL/shm creation.
	if err := os.Chmod(path, 0o660); err != nil {
		// The web publisher may be a member of the database owner's group but
		// cannot chmod a file it does not own. Accept that case only when the
		// existing mode already grants owner/group read-write and no access to
		// other users.
		info, statErr := os.Stat(path)
		if statErr != nil {
			db.Close()
			return nil, fmt.Errorf("restrict SQLite database permissions: %w", err)
		}
		mode := info.Mode().Perm()
		if mode&0o660 != 0o660 || mode&0o007 != 0 {
			db.Close()
			return nil, fmt.Errorf("restrict SQLite database permissions: %w", err)
		}
	}
	return store, nil
}

func (store *Store) configure(ctx context.Context, busyTimeout time.Duration) error {
	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("enable SQLite WAL mode: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("SQLite journal mode is %q, want wal", journalMode)
	}
	for _, pragma := range []string{
		"PRAGMA synchronous=FULL",
		fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeout.Milliseconds()),
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := store.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure SQLite with %q: %w", pragma, err)
		}
	}
	return nil
}

func (store *Store) createSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS traffic_samples (
			bucket_start_unix INTEGER PRIMARY KEY,
			interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
			requests INTEGER NOT NULL CHECK (requests >= 0),
			matched_requests INTEGER NOT NULL CHECK (matched_requests >= 0 AND matched_requests <= requests),
			response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
			known_response_byte_rows INTEGER NOT NULL CHECK (known_response_byte_rows >= 0 AND known_response_byte_rows <= requests)
		)`,
		`CREATE TABLE IF NOT EXISTS traffic_samples_by_source (
			source_id TEXT NOT NULL,
			bucket_start_unix INTEGER NOT NULL,
			interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
			requests INTEGER NOT NULL CHECK (requests >= 0),
			matched_requests INTEGER NOT NULL CHECK (matched_requests >= 0 AND matched_requests <= requests),
			response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
			known_response_byte_rows INTEGER NOT NULL CHECK (known_response_byte_rows >= 0 AND known_response_byte_rows <= requests),
			PRIMARY KEY (source_id, bucket_start_unix)
		)`,
		`CREATE TABLE IF NOT EXISTS response_time_samples (source_id TEXT NOT NULL, bucket_start_unix INTEGER NOT NULL, min_ms INTEGER NOT NULL, max_ms INTEGER NOT NULL, total_ms INTEGER NOT NULL, rows INTEGER NOT NULL, PRIMARY KEY(source_id,bucket_start_unix))`,
		`CREATE TABLE IF NOT EXISTS history_response_time_samples (import_id TEXT NOT NULL, source_id TEXT NOT NULL, bucket_start_unix INTEGER NOT NULL, min_ms INTEGER NOT NULL, max_ms INTEGER NOT NULL, total_ms INTEGER NOT NULL, rows INTEGER NOT NULL, PRIMARY KEY(import_id,source_id,bucket_start_unix))`,
		`CREATE TABLE IF NOT EXISTS detections (
			id INTEGER PRIMARY KEY,
			log_source TEXT NOT NULL DEFAULT '',
			event_time_unix_ns INTEGER NOT NULL,
			event_time_text TEXT NOT NULL,
		recorded_at_unix_ms INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		grouping_id TEXT NOT NULL,
		group_values_json TEXT NOT NULL,
		trigger_ip TEXT NOT NULL,
		trigger_user_agent TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT '',
		path TEXT NOT NULL DEFAULT '',
		raw_query TEXT NOT NULL DEFAULT '',
		protocol TEXT NOT NULL DEFAULT '',
		raw_event TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0,
		request_count INTEGER NOT NULL CHECK (request_count > 0),
			window_millis INTEGER NOT NULL CHECK (window_millis > 0),
			threshold INTEGER NOT NULL CHECK (threshold > 0),
			dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1))
		)`,
		`CREATE TABLE IF NOT EXISTS active_blocks (
			ip TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			started_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > started_at_unix_ms)
		)`,
		`CREATE TABLE IF NOT EXISTS soft_block_decisions (
			site_id TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (site_id, rule_id, ip),
			CHECK (expires_at_unix_ms > created_at_unix_ms)
		)`,
		`CREATE INDEX IF NOT EXISTS soft_block_decisions_expiry ON soft_block_decisions(expires_at_unix_ms)`,
		`CREATE TABLE IF NOT EXISTS soft_block_events (
			id INTEGER PRIMARY KEY,
			event_type TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			site_id TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS maintenance_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS history_imports (
			id TEXT PRIMARY KEY,
			source_id TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			first_event_unix_ns INTEGER NOT NULL,
			last_event_unix_ns INTEGER NOT NULL,
			files INTEGER NOT NULL,
			lines INTEGER NOT NULL,
			parsed INTEGER NOT NULL,
			ignored INTEGER NOT NULL,
			malformed INTEGER NOT NULL,
			manifest_json TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS history_detection_provenance (
			import_id TEXT NOT NULL,
			detection_id INTEGER NOT NULL,
			PRIMARY KEY (import_id, detection_id),
			UNIQUE (detection_id),
			FOREIGN KEY (import_id) REFERENCES history_imports(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
			FOREIGN KEY (detection_id) REFERENCES detections(id) ON DELETE RESTRICT
		)`,
		`CREATE TABLE IF NOT EXISTS history_traffic_samples (
			import_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			bucket_start_unix INTEGER NOT NULL,
			interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
			requests INTEGER NOT NULL CHECK (requests >= 0),
			matched_requests INTEGER NOT NULL CHECK (matched_requests >= 0 AND matched_requests <= requests),
			response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
			known_response_byte_rows INTEGER NOT NULL CHECK (known_response_byte_rows >= 0 AND known_response_byte_rows <= requests),
			PRIMARY KEY (import_id, source_id, bucket_start_unix),
			FOREIGN KEY (import_id) REFERENCES history_imports(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
		)`,
		// A historical result records facts about its input separately from any
		// future claim over a shared-history period. This table is deliberately
		// metadata only: no live traffic or detections are changed by it.
		`CREATE TABLE IF NOT EXISTS history_coverage (
			import_id TEXT PRIMARY KEY,
			source_id TEXT NOT NULL,
			observed_from_unix_ns INTEGER NOT NULL,
			observed_to_unix_ns INTEGER NOT NULL,
			has_requested_period INTEGER NOT NULL CHECK (has_requested_period IN (0,1)),
			requested_from_unix_ns INTEGER,
			requested_to_unix_ns INTEGER,
			warmup_from_unix_ns INTEGER,
			warmup_complete INTEGER NOT NULL CHECK (warmup_complete IN (0,1)),
			analysis_config_id TEXT NOT NULL,
			CHECK (observed_to_unix_ns >= observed_from_unix_ns),
			CHECK ((has_requested_period=0 AND requested_from_unix_ns IS NULL AND requested_to_unix_ns IS NULL) OR
			       (has_requested_period=1 AND requested_from_unix_ns IS NOT NULL AND requested_to_unix_ns IS NOT NULL AND requested_to_unix_ns > requested_from_unix_ns)),
			FOREIGN KEY (import_id) REFERENCES history_imports(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
		)`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create SQLite schema: %w", err)
		}
	}
	if err := store.addColumnIfMissing(ctx, "detections", "log_source", `TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{
		{"method", `TEXT NOT NULL DEFAULT ''`},
		{"path", `TEXT NOT NULL DEFAULT ''`},
		{"raw_query", `TEXT NOT NULL DEFAULT ''`},
		{"protocol", `TEXT NOT NULL DEFAULT ''`},
		{"raw_event", `TEXT NOT NULL DEFAULT ''`},
		{"reason", `TEXT NOT NULL DEFAULT ''`},
		{"status", `INTEGER NOT NULL DEFAULT 0`},
	} {
		if err := store.addColumnIfMissing(ctx, "detections", column.name, column.definition); err != nil {
			return err
		}
	}
	if err := store.removeObsoleteColumns(ctx, "traffic_samples", "updated_at_unix_ms"); err != nil {
		return err
	}
	if err := store.renameColumnIfNeeded(ctx, "traffic_samples", "homepage_requests", "matched_requests"); err != nil {
		return err
	}
	if err := store.migrateDetections(ctx); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS detections_event_time_idx ON detections(event_time_unix_ns)`,
		`CREATE INDEX IF NOT EXISTS detections_trigger_ip_time_idx ON detections(trigger_ip, event_time_unix_ns)`,
		`CREATE INDEX IF NOT EXISTS detections_grouping_time_idx ON detections(grouping_id, event_time_unix_ns)`,
		`CREATE INDEX IF NOT EXISTS history_detection_provenance_import_idx ON history_detection_provenance(import_id)`,
		`CREATE INDEX IF NOT EXISTS history_traffic_samples_period_idx ON history_traffic_samples(bucket_start_unix, import_id)`,
		`CREATE INDEX IF NOT EXISTS history_coverage_source_period_idx ON history_coverage(source_id, requested_from_unix_ns, requested_to_unix_ns)`,
	} {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create SQLite index: %w", err)
		}
	}
	return nil
}

func (store *Store) addColumnIfMissing(ctx context.Context, table, column, declaration string) error {
	rows, err := store.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("read %s schema: %w", table, err)
		}
		found = found || name == column
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate %s schema: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s schema: %w", table, err)
	}
	if !found {
		if _, err := store.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+declaration); err != nil {
			return fmt.Errorf("add %s.%s: %w", table, column, err)
		}
	}
	return nil
}

func (store *Store) renameColumnIfNeeded(ctx context.Context, table, oldName, newName string) error {
	rows, err := store.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	var oldFound, newFound bool
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("read %s schema: %w", table, err)
		}
		oldFound = oldFound || name == oldName
		newFound = newFound || name == newName
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate %s schema: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s schema: %w", table, err)
	}
	if oldFound && !newFound {
		if _, err := store.db.ExecContext(ctx, `ALTER TABLE `+table+` RENAME COLUMN `+oldName+` TO `+newName); err != nil {
			return fmt.Errorf("rename %s.%s: %w", table, oldName, err)
		}
	}
	return nil
}

// removeObsoleteColumns migrates older databases while preserving all rows.
func (store *Store) removeObsoleteColumns(ctx context.Context, table, obsolete string) error {
	rows, err := store.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("read %s schema: %w", table, err)
		}
		found = found || name == obsolete
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate %s schema: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s schema: %w", table, err)
	}
	if found {
		if _, err := store.db.ExecContext(ctx, `ALTER TABLE `+table+` DROP COLUMN `+obsolete); err != nil {
			return fmt.Errorf("remove obsolete column %s.%s: %w", table, obsolete, err)
		}
	}
	return nil
}

func (store *Store) migrateDetections(ctx context.Context) error {
	rows, err := store.db.QueryContext(ctx, `PRAGMA table_info(detections)`)
	if err != nil {
		return fmt.Errorf("inspect detections schema: %w", err)
	}
	obsolete := map[string]bool{
		"pattern_method": false, "pattern_path": false, "group_fields_json": false,
		"group_key_json": false, "suspicious_threshold": false, "severity": false,
		"outcome": false,
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("read detections schema: %w", err)
		}
		if _, exists := obsolete[name]; exists {
			obsolete[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate detections schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close detections schema: %w", err)
	}
	needsMigration := false
	for _, present := range obsolete {
		needsMigration = needsMigration || present
	}
	if !needsMigration {
		return nil
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin detections schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE detections_new (
		id INTEGER PRIMARY KEY,
		log_source TEXT NOT NULL DEFAULT '',
		event_time_unix_ns INTEGER NOT NULL,
		event_time_text TEXT NOT NULL,
		recorded_at_unix_ms INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		grouping_id TEXT NOT NULL,
		group_values_json TEXT NOT NULL,
		trigger_ip TEXT NOT NULL,
		trigger_user_agent TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT '',
		path TEXT NOT NULL DEFAULT '',
		raw_query TEXT NOT NULL DEFAULT '',
		protocol TEXT NOT NULL DEFAULT '',
		raw_event TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0,
		request_count INTEGER NOT NULL CHECK (request_count > 0),
			window_millis INTEGER NOT NULL CHECK (window_millis > 0),
			threshold INTEGER NOT NULL CHECK (threshold > 0),
			dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1))
	)`); err != nil {
		return fmt.Errorf("create migrated detections table: %w", err)
	}
	const persistedColumns = `id, log_source, event_time_unix_ns, event_time_text, recorded_at_unix_ms,
		rule_id, grouping_id, group_values_json, trigger_ip, trigger_user_agent,
		method, path, raw_query, protocol, raw_event, reason, status,
		request_count, window_millis, threshold, dry_run`
	if _, err := tx.ExecContext(ctx, `INSERT INTO detections_new (`+persistedColumns+`) SELECT `+persistedColumns+` FROM detections`); err != nil {
		return fmt.Errorf("copy detections into migrated table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE detections`); err != nil {
		return fmt.Errorf("drop old detections table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE detections_new RENAME TO detections`); err != nil {
		return fmt.Errorf("rename migrated detections table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit detections schema migration: %w", err)
	}
	return nil
}

func (store *Store) WriteTrafficSamples(ctx context.Context, samples []metrics.Sample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin traffic sample transaction: %w", err)
	}
	defer tx.Rollback()

	statement, err := tx.PrepareContext(ctx, `INSERT INTO traffic_samples (
		bucket_start_unix, interval_seconds, requests, matched_requests,
		response_bytes, known_response_byte_rows
	) VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(bucket_start_unix) DO UPDATE SET
		requests = traffic_samples.requests + excluded.requests,
		matched_requests = traffic_samples.matched_requests + excluded.matched_requests,
		response_bytes = traffic_samples.response_bytes + excluded.response_bytes,
		known_response_byte_rows = traffic_samples.known_response_byte_rows + excluded.known_response_byte_rows`)
	if err != nil {
		return fmt.Errorf("prepare traffic sample write: %w", err)
	}
	defer statement.Close()
	sourceStatement, err := tx.PrepareContext(ctx, `INSERT INTO traffic_samples_by_source (
		source_id,bucket_start_unix,interval_seconds,requests,matched_requests,response_bytes,known_response_byte_rows
	) VALUES (?,?,?,?,?,?,?)
	ON CONFLICT(source_id,bucket_start_unix) DO UPDATE SET
		requests = traffic_samples_by_source.requests + excluded.requests,
		matched_requests = traffic_samples_by_source.matched_requests + excluded.matched_requests,
		response_bytes = traffic_samples_by_source.response_bytes + excluded.response_bytes,
		known_response_byte_rows = traffic_samples_by_source.known_response_byte_rows + excluded.known_response_byte_rows`)
	if err != nil {
		return fmt.Errorf("prepare per-source traffic sample write: %w", err)
	}
	defer sourceStatement.Close()

	for _, sample := range samples {
		if _, err := statement.ExecContext(ctx,
			sample.BucketStartUnix,
			sample.IntervalSeconds,
			sample.Requests,
			sample.MatchedRequests,
			sample.ResponseBytes,
			sample.KnownResponseByteRows,
		); err != nil {
			return fmt.Errorf("write traffic sample at %d: %w", sample.BucketStartUnix, err)
		}
		if _, err := sourceStatement.ExecContext(ctx, sample.SourceID, sample.BucketStartUnix, sample.IntervalSeconds, sample.Requests, sample.MatchedRequests, sample.ResponseBytes, sample.KnownResponseByteRows); err != nil {
			return fmt.Errorf("write traffic sample for source %q at %d: %w", sample.SourceID, sample.BucketStartUnix, err)
		}
		if sample.ResponseTimeRows > 0 {
			_, err := tx.ExecContext(ctx, `INSERT INTO response_time_samples(source_id,bucket_start_unix,min_ms,max_ms,total_ms,rows) VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,bucket_start_unix) DO UPDATE SET min_ms=MIN(response_time_samples.min_ms,excluded.min_ms),max_ms=MAX(response_time_samples.max_ms,excluded.max_ms),total_ms=response_time_samples.total_ms+excluded.total_ms,rows=response_time_samples.rows+excluded.rows`, sample.SourceID, sample.BucketStartUnix, sample.ResponseTimeMinMillis, sample.ResponseTimeMaxMillis, sample.ResponseTimeTotalMillis, sample.ResponseTimeRows)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO response_time_samples(source_id,bucket_start_unix,min_ms,max_ms,total_ms,rows) VALUES('',?,?,?,?,?) ON CONFLICT(source_id,bucket_start_unix) DO UPDATE SET min_ms=MIN(response_time_samples.min_ms,excluded.min_ms),max_ms=MAX(response_time_samples.max_ms,excluded.max_ms),total_ms=response_time_samples.total_ms+excluded.total_ms,rows=response_time_samples.rows+excluded.rows`, sample.BucketStartUnix, sample.ResponseTimeMinMillis, sample.ResponseTimeMaxMillis, sample.ResponseTimeTotalMillis, sample.ResponseTimeRows)
			if err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit traffic sample transaction: %w", err)
	}
	return nil
}

func (store *Store) RecordDetection(ctx context.Context, detection engine.Detection, event request.Event) error {
	groupValues, err := json.Marshal([]string{detection.GroupValue})
	if err != nil {
		return fmt.Errorf("encode detection group values: %w", err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO detections (
		log_source, event_time_unix_ns, event_time_text, recorded_at_unix_ms,
		rule_id, grouping_id, group_values_json,
		trigger_ip, trigger_user_agent, method, path, raw_query, protocol, raw_event, reason, status, request_count, window_millis,
		threshold, dry_run
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		detection.LogSource,
		event.Timestamp.UnixNano(),
		event.Timestamp.Format(time.RFC3339Nano),
		time.Now().UnixMilli(),
		detection.RuleID,
		string(detection.GroupField),
		string(groupValues),
		event.IP.Unmap().String(),
		event.UserAgent,
		event.Method,
		event.Path,
		event.RawQuery,
		event.Protocol,
		event.RawLine,
		detection.Reason,
		event.Status,
		detection.Count,
		detection.Window.Milliseconds(),
		detection.Threshold,
		detection.DryRun,
	)
	if err != nil {
		return fmt.Errorf("record detection: %w", err)
	}
	return nil
}

// RecordBlock persists an applied firewall block. Calls for a newly applied
// block replace an expired record for the same IP; duplicate actions must not
// call this method, so their original expiry is preserved.
func (store *Store) RecordBlock(ctx context.Context, ip netip.Addr, ruleID string, startedAt, expiresAt time.Time) error {
	if !ip.IsValid() || ruleID == "" || !expiresAt.After(startedAt) {
		return fmt.Errorf("invalid block record")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO active_blocks (
		ip, rule_id, started_at_unix_ms, expires_at_unix_ms
	) VALUES (?, ?, ?, ?)
	ON CONFLICT(ip) DO UPDATE SET
		rule_id = excluded.rule_id,
		started_at_unix_ms = excluded.started_at_unix_ms,
		expires_at_unix_ms = excluded.expires_at_unix_ms`,
		ip.Unmap().String(), ruleID, startedAt.UnixMilli(), expiresAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("record active block for %s: %w", ip, err)
	}
	return nil
}

func (store *Store) PruneExpiredBlocks(ctx context.Context, now time.Time) error {
	if _, err := store.db.ExecContext(ctx, `DELETE FROM active_blocks WHERE expires_at_unix_ms <= ?`, now.UnixMilli()); err != nil {
		return fmt.Errorf("prune expired block records: %w", err)
	}
	return nil
}

func (store *Store) UnexpiredBlocks(ctx context.Context, now time.Time) ([]BlockRow, error) {
	return queryActiveBlocks(ctx, store.db, now, 0)
}

func (store *Store) DeleteBlock(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("invalid block IP")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM active_blocks WHERE ip = ?`, ip.Unmap().String()); err != nil {
		return fmt.Errorf("delete active block record for %s: %w", ip, err)
	}
	return nil
}

const nftMigrationStateKey = "nftables_to_soft_block"

func (store *Store) NFTMigrationState(ctx context.Context) (string, error) {
	var value string
	err := store.db.QueryRowContext(ctx, `SELECT value FROM maintenance_state WHERE key = ?`, nftMigrationStateKey).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read nftables migration state: %w", err)
	}
	return value, nil
}

func (store *Store) MarkNFTMigrationPending(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO maintenance_state(key,value) VALUES(?, 'firewall_pending')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, nftMigrationStateKey)
	if err != nil {
		return fmt.Errorf("record pending nftables migration: %w", err)
	}
	return nil
}

// CompleteNFTMigration cancels legacy firewall records only after the owned
// nftables table has been removed. The transaction makes retries idempotent.
func (store *Store) CompleteNFTMigration(ctx context.Context) (int64, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin nftables migration completion: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM active_blocks`)
	if err != nil {
		return 0, fmt.Errorf("cancel legacy active block records: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count cancelled active block records: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO maintenance_state(key,value) VALUES(?, 'complete')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, nftMigrationStateKey); err != nil {
		return 0, fmt.Errorf("record completed nftables migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit nftables migration completion: %w", err)
	}
	return removed, nil
}

func (store *Store) Close() error {
	if err := store.db.Close(); err != nil {
		return fmt.Errorf("close SQLite database: %w", err)
	}
	return nil
}
