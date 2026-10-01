// Package storage persists traffic summaries and rule detections in SQLite.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("SQLite path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create SQLite directory: %w", err)
	}

	dsn := (&url.URL{Scheme: "file", Path: filepath.Clean(path)}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &Store{db: db}
	if err := store.configure(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.createSchema(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict SQLite database permissions: %w", err)
	}
	return store, nil
}

func (store *Store) configure(ctx context.Context) error {
	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("enable SQLite WAL mode: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("SQLite journal mode is %q, want wal", journalMode)
	}
	for _, pragma := range []string{
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
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
			homepage_requests INTEGER NOT NULL CHECK (homepage_requests >= 0 AND homepage_requests <= requests),
			response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
			known_response_byte_rows INTEGER NOT NULL CHECK (known_response_byte_rows >= 0 AND known_response_byte_rows <= requests)
		)`,
		`CREATE TABLE IF NOT EXISTS detections (
			id INTEGER PRIMARY KEY,
			event_time_unix_ns INTEGER NOT NULL,
			event_time_text TEXT NOT NULL,
		recorded_at_unix_ms INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		grouping_id TEXT NOT NULL,
		group_values_json TEXT NOT NULL,
		trigger_ip TEXT NOT NULL,
		trigger_user_agent TEXT NOT NULL,
		request_count INTEGER NOT NULL CHECK (request_count > 0),
			window_millis INTEGER NOT NULL CHECK (window_millis > 0),
			threshold INTEGER NOT NULL CHECK (threshold > 0),
			dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1))
		)`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create SQLite schema: %w", err)
		}
	}
	if err := store.removeObsoleteColumns(ctx, "traffic_samples", "updated_at_unix_ms"); err != nil {
		return err
	}
	if err := store.migrateDetections(ctx); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS detections_event_time_idx ON detections(event_time_unix_ns)`,
		`CREATE INDEX IF NOT EXISTS detections_trigger_ip_time_idx ON detections(trigger_ip, event_time_unix_ns)`,
		`CREATE INDEX IF NOT EXISTS detections_grouping_time_idx ON detections(grouping_id, event_time_unix_ns)`,
	} {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create SQLite index: %w", err)
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
		event_time_unix_ns INTEGER NOT NULL,
		event_time_text TEXT NOT NULL,
		recorded_at_unix_ms INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		grouping_id TEXT NOT NULL,
		group_values_json TEXT NOT NULL,
		trigger_ip TEXT NOT NULL,
		trigger_user_agent TEXT NOT NULL,
		request_count INTEGER NOT NULL CHECK (request_count > 0),
			window_millis INTEGER NOT NULL CHECK (window_millis > 0),
			threshold INTEGER NOT NULL CHECK (threshold > 0),
			dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1))
	)`); err != nil {
		return fmt.Errorf("create migrated detections table: %w", err)
	}
	const persistedColumns = `id, event_time_unix_ns, event_time_text, recorded_at_unix_ms,
		rule_id, grouping_id, group_values_json, trigger_ip, trigger_user_agent,
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
		bucket_start_unix, interval_seconds, requests, homepage_requests,
		response_bytes, known_response_byte_rows
	) VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(bucket_start_unix) DO UPDATE SET
		requests = traffic_samples.requests + excluded.requests,
		homepage_requests = traffic_samples.homepage_requests + excluded.homepage_requests,
		response_bytes = traffic_samples.response_bytes + excluded.response_bytes,
		known_response_byte_rows = traffic_samples.known_response_byte_rows + excluded.known_response_byte_rows`)
	if err != nil {
		return fmt.Errorf("prepare traffic sample write: %w", err)
	}
	defer statement.Close()

	for _, sample := range samples {
		if _, err := statement.ExecContext(ctx,
			sample.BucketStartUnix,
			sample.IntervalSeconds,
			sample.Requests,
			sample.HomepageRequests,
			sample.ResponseBytes,
			sample.KnownResponseByteRows,
		); err != nil {
			return fmt.Errorf("write traffic sample at %d: %w", sample.BucketStartUnix, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit traffic sample transaction: %w", err)
	}
	return nil
}

func (store *Store) RecordDetection(ctx context.Context, detection engine.Detection, event request.Event) error {
	groupValues, err := json.Marshal(detection.GroupValues)
	if err != nil {
		return fmt.Errorf("encode detection group values: %w", err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO detections (
		event_time_unix_ns, event_time_text, recorded_at_unix_ms,
		rule_id, grouping_id, group_values_json,
		trigger_ip, trigger_user_agent, request_count, window_millis,
		threshold, dry_run
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp.UnixNano(),
		event.Timestamp.Format(time.RFC3339Nano),
		time.Now().UnixMilli(),
		detection.RuleID,
		detection.GroupingID,
		string(groupValues),
		event.IP.Unmap().String(),
		event.UserAgent,
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

func (store *Store) Close() error {
	if err := store.db.Close(); err != nil {
		return fmt.Errorf("close SQLite database: %w", err)
	}
	return nil
}
