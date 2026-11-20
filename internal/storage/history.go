package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/request"
)

// HistoryImportRecord describes one immutable, isolated historical database.
type HistoryImportRecord struct {
	ID           string
	SourceID     string
	CreatedAt    time.Time
	FirstEvent   time.Time
	LastEvent    time.Time
	Files        int64
	Lines        int64
	Parsed       int64
	Ignored      int64
	Malformed    int64
	ManifestJSON string
}

// HistoryCoverageRecord captures what was observed, and only when supplied by
// the caller, the interval it requested. It is not shared-history ownership.
// Keeping those concepts distinct prevents sparse archive input from being
// represented as continuous coverage.
type HistoryCoverageRecord struct {
	ImportID, SourceID, AnalysisConfigID string
	ObservedFrom, ObservedTo             time.Time
	RequestedFrom, RequestedTo           time.Time
	WarmupFrom                           time.Time
	WarmupComplete                       bool
}

// HistoryImportSummary is a read-only view of one historical result. It is
// intentionally separate from Dashboard: opening it never mixes a result
// database with a configured live database.
type HistoryImportSummary struct {
	ID                                       string
	SourceID                                 string
	CreatedAt                                time.Time
	FirstEvent                               time.Time
	LastEvent                                time.Time
	Files, Lines, Parsed, Ignored, Malformed int64
	HasRequestedPeriod                       bool
	RequestedFrom, RequestedTo, WarmupFrom   time.Time
	WarmupComplete                           bool
	AnalysisConfigID                         string
}

func (reader *Reader) HistoryImportManifest(ctx context.Context, id string) ([]byte, error) {
	var document string
	if err := reader.db.QueryRowContext(ctx, `SELECT manifest_json FROM history_imports WHERE id=?`, id).Scan(&document); err != nil {
		return nil, fmt.Errorf("read history import manifest: %w", err)
	}
	return []byte(document), nil
}

// HistoryRuleCount is a compact, read-only review aid for an isolated import.
type HistoryRuleCount struct {
	RuleID string
	Count  int64
}

func (reader *Reader) HistoryRuleCounts(ctx context.Context) ([]HistoryRuleCount, error) {
	rows, err := reader.db.QueryContext(ctx, `SELECT rule_id,COUNT(*) FROM detections GROUP BY rule_id ORDER BY COUNT(*) DESC,rule_id`)
	if err != nil {
		return nil, fmt.Errorf("read historical rule counts: %w", err)
	}
	defer rows.Close()
	counts := []HistoryRuleCount{}
	for rows.Next() {
		var item HistoryRuleCount
		if err := rows.Scan(&item.RuleID, &item.Count); err != nil {
			return nil, fmt.Errorf("scan historical rule count: %w", err)
		}
		counts = append(counts, item)
	}
	return counts, rows.Err()
}

// HistoryPublishResult describes one atomic append of an immutable historical
// result into a dashboard database. It never creates enforcement records.
type HistoryPublishResult struct {
	AlreadyPublished bool
	Detections       int64
	TrafficSamples   int64
}

// RewriteHistoricalRule replaces only historical detections for one rule. It
// deliberately leaves traffic aggregates untouched: a rule edit changes which
// requests match, but cannot safely reconstruct any live contribution already
// present in an aggregate bucket.
func (store *Store) RewriteHistoricalRule(ctx context.Context, resultPath, importID, sourceID, ruleID string, from, to time.Time) (int64, error) {
	if !filepath.IsAbs(resultPath) || importID == "" || sourceID == "" || ruleID == "" || !from.Before(to) {
		return 0, fmt.Errorf("absolute result path, import, source, rule, and ordered period are required")
	}
	if _, err := store.db.ExecContext(ctx, `ATTACH DATABASE ? AS historical_result`, resultPath); err != nil {
		return 0, fmt.Errorf("attach historical result: %w", err)
	}
	defer store.db.ExecContext(context.Background(), `DETACH DATABASE historical_result`)
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var imports int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM historical_result.history_imports WHERE id=? AND source_id=?`, importID, sourceID).Scan(&imports); err != nil {
		return 0, err
	}
	if imports != 1 {
		return 0, fmt.Errorf("historical result does not contain the expected import")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM history_imports WHERE id=?`, importID).Scan(&exists); err != nil {
		return 0, err
	}
	if exists != 0 {
		return 0, fmt.Errorf("historical rule result %s is already published", importID)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE history_rule_replace AS
		SELECT p.detection_id FROM history_detection_provenance p JOIN detections d ON d.id=p.detection_id
		WHERE d.log_source=? AND d.rule_id=? AND d.event_time_unix_ns>=? AND d.event_time_unix_ns<?`, sourceID, ruleID, from.UnixNano(), to.UnixNano()); err != nil {
		return 0, err
	}
	defer tx.ExecContext(context.Background(), `DROP TABLE IF EXISTS history_rule_replace`)
	if _, err := tx.ExecContext(ctx, `DELETE FROM history_detection_provenance WHERE detection_id IN (SELECT detection_id FROM history_rule_replace)`); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM detections WHERE id IN (SELECT detection_id FROM history_rule_replace)`); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_imports SELECT * FROM historical_result.history_imports WHERE id=?`, importID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_coverage SELECT * FROM historical_result.history_coverage WHERE import_id=?`, importID); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO detections(log_source,event_time_unix_ns,event_time_text,recorded_at_unix_ms,rule_id,grouping_id,group_values_json,trigger_ip,trigger_user_agent,method,path,raw_query,protocol,raw_event,reason,status,request_count,window_millis,threshold,dry_run)
		SELECT d.log_source,d.event_time_unix_ns,d.event_time_text,d.recorded_at_unix_ms,d.rule_id,d.grouping_id,d.group_values_json,d.trigger_ip,d.trigger_user_agent,d.method,d.path,d.raw_query,d.protocol,d.raw_event,d.reason,d.status,d.request_count,d.window_millis,d.threshold,d.dry_run
		FROM historical_result.detections d JOIN historical_result.history_detection_provenance p ON p.detection_id=d.id WHERE p.import_id=? AND d.rule_id=? ORDER BY d.id`, importID, ruleID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if count > 0 {
		last, err := result.LastInsertId()
		if err != nil {
			return 0, err
		}
		first := last - count + 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO history_detection_provenance(import_id,detection_id) SELECT ?, ? + ROW_NUMBER() OVER (ORDER BY detection_id) - 1 FROM historical_result.history_detection_provenance p JOIN historical_result.detections d ON d.id=p.detection_id WHERE p.import_id=? AND d.rule_id=? ORDER BY d.id`, importID, first, importID, ruleID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// PublishHistoricalResult appends one verified isolated result. Existing live
// data in the requested source-period is a conflict, not something to merge:
// this prevents silently doubling dashboard buckets.
func (store *Store) PublishHistoricalResult(ctx context.Context, resultPath, importID, sourceID string, from, to time.Time) (HistoryPublishResult, error) {
	if !filepath.IsAbs(resultPath) || importID == "" || sourceID == "" || !from.Before(to) {
		return HistoryPublishResult{}, fmt.Errorf("absolute result path, import, source, and ordered period are required")
	}
	if err := store.db.PingContext(ctx); err != nil {
		return HistoryPublishResult{}, err
	}
	if _, err := store.db.ExecContext(ctx, `ATTACH DATABASE ? AS historical_result`, resultPath); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("attach historical result: %w", err)
	}
	defer store.db.ExecContext(context.Background(), `DETACH DATABASE historical_result`)
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return HistoryPublishResult{}, err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM history_imports WHERE id=?`, importID).Scan(&exists); err != nil {
		return HistoryPublishResult{}, err
	}
	if exists != 0 {
		if err := tx.Commit(); err != nil {
			return HistoryPublishResult{}, err
		}
		return HistoryPublishResult{AlreadyPublished: true}, nil
	}
	var sourceImports int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM historical_result.history_imports WHERE id=? AND source_id=?`, importID, sourceID).Scan(&sourceImports); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("read historical import: %w", err)
	}
	if sourceImports != 1 {
		return HistoryPublishResult{}, fmt.Errorf("historical result does not contain the expected import")
	}
	// A short test import must never replace an entire archived period.
	var partialOverlap int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM history_coverage c WHERE c.source_id=? AND c.has_requested_period=1 AND c.requested_from_unix_ns<? AND c.requested_to_unix_ns>? AND (c.requested_from_unix_ns<? OR c.requested_to_unix_ns>?) AND (EXISTS (SELECT 1 FROM history_traffic_samples h WHERE h.import_id=c.import_id) OR EXISTS (SELECT 1 FROM history_detection_provenance p WHERE p.import_id=c.import_id))`, sourceID, to.UnixNano(), from.UnixNano(), from.UnixNano(), to.UnixNano()).Scan(&partialOverlap); err != nil {
		return HistoryPublishResult{}, err
	}
	if partialOverlap != 0 {
		return HistoryPublishResult{}, fmt.Errorf("historical publication would replace a wider period; use history import for an isolated test")
	}
	// Replace only prior historical contributions in an overlapping interval.
	// Live traffic and detections have no provenance row and are never removed.
	if err := replaceOverlappingHistory(ctx, tx, sourceID, from, to); err != nil {
		return HistoryPublishResult{}, err
	}
	var conflicts int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_samples_by_source WHERE source_id=? AND bucket_start_unix>=? AND bucket_start_unix<?`, sourceID, from.Unix(), to.Unix()).Scan(&conflicts); err != nil {
		return HistoryPublishResult{}, err
	}
	if conflicts != 0 {
		return HistoryPublishResult{}, fmt.Errorf("historical publication overlaps existing source traffic")
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM detections WHERE log_source=? AND event_time_unix_ns>=? AND event_time_unix_ns<?`, sourceID, from.UnixNano(), to.UnixNano()).Scan(&conflicts); err != nil {
		return HistoryPublishResult{}, err
	}
	if conflicts != 0 {
		return HistoryPublishResult{}, fmt.Errorf("historical publication overlaps existing source detections")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_imports SELECT * FROM historical_result.history_imports WHERE id=?`, importID); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy history import: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_coverage SELECT * FROM historical_result.history_coverage WHERE import_id=?`, importID); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy history coverage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_traffic_samples SELECT * FROM historical_result.history_traffic_samples WHERE import_id=?`, importID); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy historical traffic provenance: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_response_time_samples SELECT * FROM historical_result.history_response_time_samples WHERE import_id=?`, importID); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy response time provenance: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO response_time_samples(source_id,bucket_start_unix,min_ms,max_ms,total_ms,rows) SELECT source_id,bucket_start_unix,min_ms,max_ms,total_ms,rows FROM historical_result.history_response_time_samples WHERE import_id=? ON CONFLICT(source_id,bucket_start_unix) DO UPDATE SET min_ms=MIN(response_time_samples.min_ms,excluded.min_ms),max_ms=MAX(response_time_samples.max_ms,excluded.max_ms),total_ms=response_time_samples.total_ms+excluded.total_ms,rows=response_time_samples.rows+excluded.rows`, importID); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy response time: %w", err)
	}
	traffic, err := tx.ExecContext(ctx, `INSERT INTO traffic_samples_by_source(source_id,bucket_start_unix,interval_seconds,requests,matched_requests,response_bytes,known_response_byte_rows)
		SELECT source_id,bucket_start_unix,interval_seconds,requests,matched_requests,response_bytes,known_response_byte_rows FROM historical_result.history_traffic_samples WHERE import_id=?
		ON CONFLICT(source_id,bucket_start_unix) DO UPDATE SET requests=requests+excluded.requests,matched_requests=matched_requests+excluded.matched_requests,response_bytes=response_bytes+excluded.response_bytes,known_response_byte_rows=known_response_byte_rows+excluded.known_response_byte_rows`, importID)
	if err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy source traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_samples(bucket_start_unix,interval_seconds,requests,matched_requests,response_bytes,known_response_byte_rows)
		SELECT bucket_start_unix,interval_seconds,requests,matched_requests,response_bytes,known_response_byte_rows FROM historical_result.history_traffic_samples WHERE import_id=?
		ON CONFLICT(bucket_start_unix) DO UPDATE SET requests=requests+excluded.requests,matched_requests=matched_requests+excluded.matched_requests,response_bytes=response_bytes+excluded.response_bytes,known_response_byte_rows=known_response_byte_rows+excluded.known_response_byte_rows`, importID); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy total traffic: %w", err)
	}
	detections, err := tx.ExecContext(ctx, `INSERT INTO detections(log_source,event_time_unix_ns,event_time_text,recorded_at_unix_ms,rule_id,grouping_id,group_values_json,trigger_ip,trigger_user_agent,method,path,raw_query,protocol,raw_event,reason,status,request_count,window_millis,threshold,dry_run)
		SELECT d.log_source,d.event_time_unix_ns,d.event_time_text,d.recorded_at_unix_ms,d.rule_id,d.grouping_id,d.group_values_json,d.trigger_ip,d.trigger_user_agent,d.method,d.path,d.raw_query,d.protocol,d.raw_event,d.reason,d.status,d.request_count,d.window_millis,d.threshold,d.dry_run
		FROM historical_result.detections d JOIN historical_result.history_detection_provenance p ON p.detection_id=d.id WHERE p.import_id=? ORDER BY d.id`, importID)
	if err != nil {
		return HistoryPublishResult{}, fmt.Errorf("copy historical detections: %w", err)
	}
	detectionCount, err := detections.RowsAffected()
	if err != nil {
		return HistoryPublishResult{}, err
	}
	if detectionCount > 0 {
		lastID, err := detections.LastInsertId()
		if err != nil {
			return HistoryPublishResult{}, err
		}
		firstID := lastID - detectionCount + 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO history_detection_provenance(import_id,detection_id)
			SELECT ?, ? + ROW_NUMBER() OVER (ORDER BY detection_id) - 1 FROM historical_result.history_detection_provenance WHERE import_id=? ORDER BY detection_id`, importID, firstID, importID); err != nil {
			return HistoryPublishResult{}, fmt.Errorf("copy historical detection provenance: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return HistoryPublishResult{}, fmt.Errorf("commit historical publication: %w", err)
	}
	trafficCount, err := traffic.RowsAffected()
	if err != nil {
		return HistoryPublishResult{}, err
	}
	return HistoryPublishResult{Detections: detectionCount, TrafficSamples: trafficCount}, nil
}

func replaceOverlappingHistory(ctx context.Context, tx *sql.Tx, sourceID string, from, to time.Time) error {
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE history_replace_imports AS
		SELECT import_id FROM history_coverage WHERE source_id=? AND has_requested_period=1
		AND requested_from_unix_ns<? AND requested_to_unix_ns>?`, sourceID, to.UnixNano(), from.UnixNano()); err != nil {
		return fmt.Errorf("prepare overlapping history replacement: %w", err)
	}
	defer tx.ExecContext(context.Background(), `DROP TABLE IF EXISTS history_replace_imports`)
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM history_replace_imports`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE history_replace_traffic AS
		SELECT source_id,bucket_start_unix,SUM(requests) requests,SUM(matched_requests) matched_requests,
		SUM(response_bytes) response_bytes,SUM(known_response_byte_rows) known_response_byte_rows
		FROM history_traffic_samples WHERE import_id IN (SELECT import_id FROM history_replace_imports)
		GROUP BY source_id,bucket_start_unix`); err != nil {
		return fmt.Errorf("prepare overlapping traffic replacement: %w", err)
	}
	defer tx.ExecContext(context.Background(), `DROP TABLE IF EXISTS history_replace_traffic`)
	// The following UPDATEs perform correlated lookups for each live bucket.
	// Without these temporary indexes SQLite scans every replaced bucket for
	// every row and a multi-week history replacement can take tens of minutes.
	if _, err := tx.ExecContext(ctx, `CREATE INDEX history_replace_traffic_source_bucket_idx ON history_replace_traffic(source_id,bucket_start_unix)`); err != nil {
		return fmt.Errorf("index replacement source traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX history_replace_traffic_bucket_idx ON history_replace_traffic(bucket_start_unix)`); err != nil {
		return fmt.Errorf("index replacement total traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE traffic_samples_by_source SET
		requests=requests-(SELECT requests FROM history_replace_traffic h WHERE h.source_id=traffic_samples_by_source.source_id AND h.bucket_start_unix=traffic_samples_by_source.bucket_start_unix),
		matched_requests=matched_requests-(SELECT matched_requests FROM history_replace_traffic h WHERE h.source_id=traffic_samples_by_source.source_id AND h.bucket_start_unix=traffic_samples_by_source.bucket_start_unix),
		response_bytes=response_bytes-(SELECT response_bytes FROM history_replace_traffic h WHERE h.source_id=traffic_samples_by_source.source_id AND h.bucket_start_unix=traffic_samples_by_source.bucket_start_unix),
		known_response_byte_rows=known_response_byte_rows-(SELECT known_response_byte_rows FROM history_replace_traffic h WHERE h.source_id=traffic_samples_by_source.source_id AND h.bucket_start_unix=traffic_samples_by_source.bucket_start_unix)
		WHERE EXISTS (SELECT 1 FROM history_replace_traffic h WHERE h.source_id=traffic_samples_by_source.source_id AND h.bucket_start_unix=traffic_samples_by_source.bucket_start_unix)`); err != nil {
		return fmt.Errorf("remove prior source traffic contribution: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE traffic_samples SET
		requests=requests-(SELECT requests FROM history_replace_traffic h WHERE h.bucket_start_unix=traffic_samples.bucket_start_unix),
		matched_requests=matched_requests-(SELECT matched_requests FROM history_replace_traffic h WHERE h.bucket_start_unix=traffic_samples.bucket_start_unix),
		response_bytes=response_bytes-(SELECT response_bytes FROM history_replace_traffic h WHERE h.bucket_start_unix=traffic_samples.bucket_start_unix),
		known_response_byte_rows=known_response_byte_rows-(SELECT known_response_byte_rows FROM history_replace_traffic h WHERE h.bucket_start_unix=traffic_samples.bucket_start_unix)
		WHERE EXISTS (SELECT 1 FROM history_replace_traffic h WHERE h.bucket_start_unix=traffic_samples.bucket_start_unix)`); err != nil {
		return fmt.Errorf("remove prior total traffic contribution: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_samples_by_source WHERE requests=0 AND matched_requests=0 AND response_bytes=0 AND known_response_byte_rows=0`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_samples WHERE requests=0 AND matched_requests=0 AND response_bytes=0 AND known_response_byte_rows=0`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE history_replace_detections AS SELECT detection_id FROM history_detection_provenance WHERE import_id IN (SELECT import_id FROM history_replace_imports)`); err != nil {
		return err
	}
	defer tx.ExecContext(context.Background(), `DROP TABLE IF EXISTS history_replace_detections`)
	if _, err := tx.ExecContext(ctx, `DELETE FROM history_detection_provenance WHERE import_id IN (SELECT import_id FROM history_replace_imports)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM detections WHERE id IN (SELECT detection_id FROM history_replace_detections)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM history_traffic_samples WHERE import_id IN (SELECT import_id FROM history_replace_imports)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM history_coverage WHERE import_id IN (SELECT import_id FROM history_replace_imports)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM history_imports WHERE id IN (SELECT import_id FROM history_replace_imports)`); err != nil {
		return err
	}
	return nil
}

func (reader *Reader) HistoryImports(ctx context.Context) ([]HistoryImportSummary, error) {
	query := `SELECT i.id,i.source_id,i.created_at_unix_ms,i.first_event_unix_ns,i.last_event_unix_ns,i.files,i.lines,i.parsed,i.ignored,i.malformed,c.has_requested_period,c.requested_from_unix_ns,c.requested_to_unix_ns,c.warmup_from_unix_ns,c.warmup_complete,c.analysis_config_id FROM history_imports i LEFT JOIN history_coverage c ON c.import_id=i.id ORDER BY i.created_at_unix_ms DESC`
	rows, err := reader.db.QueryContext(ctx, query)
	if err != nil && strings.Contains(err.Error(), "no such table: history_coverage") {
		// Isolated databases made by the first historical MVP did not have
		// coverage metadata. They remain reportable but cannot make a future
		// ownership claim.
		rows, err = reader.db.QueryContext(ctx, `SELECT id,source_id,created_at_unix_ms,first_event_unix_ns,last_event_unix_ns,files,lines,parsed,ignored,malformed FROM history_imports ORDER BY created_at_unix_ms DESC`)
		if err != nil {
			return nil, fmt.Errorf("read history imports: %w", err)
		}
		return scanHistoryImports(rows, false)
	}
	if err != nil {
		return nil, fmt.Errorf("read history imports: %w", err)
	}
	return scanHistoryImports(rows, true)
}

func scanHistoryImports(rows *sql.Rows, coverage bool) ([]HistoryImportSummary, error) {
	defer rows.Close()
	result := []HistoryImportSummary{}
	for rows.Next() {
		var item HistoryImportSummary
		var createdMS, firstNS, lastNS int64
		if coverage {
			var requestedFrom, requestedTo, warmupFrom sql.NullInt64
			var hasRequested, warmupComplete sql.NullBool
			var analysis sql.NullString
			err := rows.Scan(&item.ID, &item.SourceID, &createdMS, &firstNS, &lastNS, &item.Files, &item.Lines, &item.Parsed, &item.Ignored, &item.Malformed, &hasRequested, &requestedFrom, &requestedTo, &warmupFrom, &warmupComplete, &analysis)
			if err != nil {
				return nil, fmt.Errorf("scan history import: %w", err)
			}
			item.HasRequestedPeriod = hasRequested.Bool
			item.WarmupComplete = warmupComplete.Bool
			item.AnalysisConfigID = analysis.String
			if requestedFrom.Valid {
				item.RequestedFrom = time.Unix(0, requestedFrom.Int64)
			}
			if requestedTo.Valid {
				item.RequestedTo = time.Unix(0, requestedTo.Int64)
			}
			if warmupFrom.Valid {
				item.WarmupFrom = time.Unix(0, warmupFrom.Int64)
			}
		} else if err := rows.Scan(&item.ID, &item.SourceID, &createdMS, &firstNS, &lastNS, &item.Files, &item.Lines, &item.Parsed, &item.Ignored, &item.Malformed); err != nil {
			return nil, fmt.Errorf("scan history import: %w", err)
		}
		item.CreatedAt = time.UnixMilli(createdMS)
		item.FirstEvent = time.Unix(0, firstNS)
		item.LastEvent = time.Unix(0, lastNS)
		result = append(result, item)
	}
	return result, rows.Err()
}

// HistoryBatch keeps an isolated import in one transaction. It is not used by
// live runtime and has no block-related methods.
type HistoryBatch struct {
	tx              *sql.Tx
	importID        string
	detection       *sql.Stmt
	detectionOrigin *sql.Stmt
	traffic         *sql.Stmt
	source          *sql.Stmt
	trafficOrigin   *sql.Stmt
	responseTime    *sql.Stmt
	closed          bool
}

func (store *Store) BeginHistoryBatch(ctx context.Context, importID string) (*HistoryBatch, error) {
	if importID == "" {
		return nil, fmt.Errorf("history import ID must not be empty")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin history transaction: %w", err)
	}
	rollback := func() { _ = tx.Rollback() }
	detection, err := tx.PrepareContext(ctx, `INSERT INTO detections (
		log_source, event_time_unix_ns, event_time_text, recorded_at_unix_ms,
		rule_id, grouping_id, group_values_json, trigger_ip, trigger_user_agent,
		method, path, raw_query, protocol, raw_event, reason, status,
		request_count, window_millis, threshold, dry_run
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		rollback()
		return nil, fmt.Errorf("prepare historical detection: %w", err)
	}
	detectionOrigin, err := tx.PrepareContext(ctx, `INSERT INTO history_detection_provenance (import_id, detection_id) VALUES (?, ?)`)
	if err != nil {
		detection.Close()
		rollback()
		return nil, fmt.Errorf("prepare historical detection provenance: %w", err)
	}
	traffic, err := tx.PrepareContext(ctx, `INSERT INTO traffic_samples (
		bucket_start_unix, interval_seconds, requests, matched_requests,
		response_bytes, known_response_byte_rows
	) VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(bucket_start_unix) DO UPDATE SET
		requests = traffic_samples.requests + excluded.requests,
		matched_requests = traffic_samples.matched_requests + excluded.matched_requests,
		response_bytes = traffic_samples.response_bytes + excluded.response_bytes,
		known_response_byte_rows = traffic_samples.known_response_byte_rows + excluded.known_response_byte_rows`)
	if err != nil {
		detectionOrigin.Close()
		detection.Close()
		rollback()
		return nil, fmt.Errorf("prepare historical traffic: %w", err)
	}
	source, err := tx.PrepareContext(ctx, `INSERT INTO traffic_samples_by_source (
		source_id, bucket_start_unix, interval_seconds, requests, matched_requests,
		response_bytes, known_response_byte_rows
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(source_id,bucket_start_unix) DO UPDATE SET
		requests = traffic_samples_by_source.requests + excluded.requests,
		matched_requests = traffic_samples_by_source.matched_requests + excluded.matched_requests,
		response_bytes = traffic_samples_by_source.response_bytes + excluded.response_bytes,
		known_response_byte_rows = traffic_samples_by_source.known_response_byte_rows + excluded.known_response_byte_rows`)
	if err != nil {
		traffic.Close()
		detectionOrigin.Close()
		detection.Close()
		rollback()
		return nil, fmt.Errorf("prepare historical source traffic: %w", err)
	}
	trafficOrigin, err := tx.PrepareContext(ctx, `INSERT INTO history_traffic_samples (
		import_id, source_id, bucket_start_unix, interval_seconds, requests, matched_requests,
		response_bytes, known_response_byte_rows
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		source.Close()
		traffic.Close()
		detectionOrigin.Close()
		detection.Close()
		rollback()
		return nil, fmt.Errorf("prepare historical traffic provenance: %w", err)
	}
	responseTime, err := tx.PrepareContext(ctx, `INSERT INTO history_response_time_samples(import_id,source_id,bucket_start_unix,min_ms,max_ms,total_ms,rows) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		trafficOrigin.Close()
		source.Close()
		traffic.Close()
		detectionOrigin.Close()
		detection.Close()
		rollback()
		return nil, err
	}
	return &HistoryBatch{tx: tx, importID: importID, detection: detection, detectionOrigin: detectionOrigin, traffic: traffic, source: source, trafficOrigin: trafficOrigin, responseTime: responseTime}, nil
}

func (batch *HistoryBatch) RecordDetection(ctx context.Context, detection engine.Detection, event request.Event) error {
	groupValues, err := json.Marshal([]string{detection.GroupValue})
	if err != nil {
		return fmt.Errorf("encode detection group values: %w", err)
	}
	result, err := batch.detection.ExecContext(ctx,
		detection.LogSource, event.Timestamp.UnixNano(), event.Timestamp.Format(time.RFC3339Nano), time.Now().UnixMilli(),
		detection.RuleID, string(detection.GroupField), string(groupValues), event.IP.Unmap().String(), event.UserAgent,
		event.Method, event.Path, event.RawQuery, event.Protocol, event.RawLine, detection.Reason, event.Status,
		detection.Count, detection.Window.Milliseconds(), detection.Threshold, true,
	)
	if err != nil {
		return fmt.Errorf("record historical detection: %w", err)
	}
	detectionID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read historical detection ID: %w", err)
	}
	if _, err := batch.detectionOrigin.ExecContext(ctx, batch.importID, detectionID); err != nil {
		return fmt.Errorf("record historical detection provenance: %w", err)
	}
	return nil
}

func (batch *HistoryBatch) WriteTrafficSamples(ctx context.Context, samples []metrics.Sample) error {
	for _, sample := range samples {
		if _, err := batch.traffic.ExecContext(ctx, sample.BucketStartUnix, sample.IntervalSeconds, sample.Requests, sample.MatchedRequests, sample.ResponseBytes, sample.KnownResponseByteRows); err != nil {
			return fmt.Errorf("write historical traffic at %d: %w", sample.BucketStartUnix, err)
		}
		if _, err := batch.source.ExecContext(ctx, sample.SourceID, sample.BucketStartUnix, sample.IntervalSeconds, sample.Requests, sample.MatchedRequests, sample.ResponseBytes, sample.KnownResponseByteRows); err != nil {
			return fmt.Errorf("write historical source traffic at %d: %w", sample.BucketStartUnix, err)
		}
		if _, err := batch.trafficOrigin.ExecContext(ctx, batch.importID, sample.SourceID, sample.BucketStartUnix, sample.IntervalSeconds, sample.Requests, sample.MatchedRequests, sample.ResponseBytes, sample.KnownResponseByteRows); err != nil {
			return fmt.Errorf("write historical traffic provenance at %d: %w", sample.BucketStartUnix, err)
		}
		if sample.ResponseTimeRows > 0 {
			if _, err := batch.responseTime.ExecContext(ctx, batch.importID, sample.SourceID, sample.BucketStartUnix, sample.ResponseTimeMinMillis, sample.ResponseTimeMaxMillis, sample.ResponseTimeTotalMillis, sample.ResponseTimeRows); err != nil {
				return err
			}
		}
	}
	return nil
}

func (batch *HistoryBatch) RecordImport(ctx context.Context, record HistoryImportRecord) error {
	_, err := batch.tx.ExecContext(ctx, `INSERT INTO history_imports (
		id,source_id,created_at_unix_ms,first_event_unix_ns,last_event_unix_ns,
		files,lines,parsed,ignored,malformed,manifest_json
	) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, record.ID, record.SourceID, record.CreatedAt.UnixMilli(),
		record.FirstEvent.UnixNano(), record.LastEvent.UnixNano(), record.Files, record.Lines,
		record.Parsed, record.Ignored, record.Malformed, record.ManifestJSON)
	if err != nil {
		return fmt.Errorf("record history manifest: %w", err)
	}
	return nil
}

func (batch *HistoryBatch) RecordCoverage(ctx context.Context, record HistoryCoverageRecord) error {
	if record.ImportID == "" || record.SourceID == "" || record.AnalysisConfigID == "" {
		return fmt.Errorf("history coverage identity is required")
	}
	if record.ObservedTo.Before(record.ObservedFrom) {
		return fmt.Errorf("observed history range is invalid")
	}
	hasRequested := !record.RequestedFrom.IsZero() || !record.RequestedTo.IsZero()
	if hasRequested != (!record.RequestedFrom.IsZero() && !record.RequestedTo.IsZero()) || (hasRequested && !record.RequestedFrom.Before(record.RequestedTo)) {
		return fmt.Errorf("requested history range is invalid")
	}
	var requestedFrom, requestedTo, warmupFrom any
	if hasRequested {
		requestedFrom = record.RequestedFrom.UnixNano()
		requestedTo = record.RequestedTo.UnixNano()
		warmupFrom = record.WarmupFrom.UnixNano()
	}
	_, err := batch.tx.ExecContext(ctx, `INSERT INTO history_coverage(import_id,source_id,observed_from_unix_ns,observed_to_unix_ns,has_requested_period,requested_from_unix_ns,requested_to_unix_ns,warmup_from_unix_ns,warmup_complete,analysis_config_id) VALUES(?,?,?,?,?,?,?,?,?,?)`, record.ImportID, record.SourceID, record.ObservedFrom.UnixNano(), record.ObservedTo.UnixNano(), hasRequested, requestedFrom, requestedTo, warmupFrom, record.WarmupComplete, record.AnalysisConfigID)
	if err != nil {
		return fmt.Errorf("record history coverage: %w", err)
	}
	return nil
}

func (batch *HistoryBatch) Commit() error {
	if batch.closed {
		return fmt.Errorf("history transaction is already closed")
	}
	batch.closed = true
	batch.closeStatements()
	if err := batch.tx.Commit(); err != nil {
		return fmt.Errorf("commit history transaction: %w", err)
	}
	return nil
}

func (batch *HistoryBatch) Rollback() error {
	if batch.closed {
		return nil
	}
	batch.closed = true
	batch.closeStatements()
	return batch.tx.Rollback()
}

func (batch *HistoryBatch) closeStatements() {
	_ = batch.detection.Close()
	_ = batch.detectionOrigin.Close()
	_ = batch.traffic.Close()
	_ = batch.source.Close()
	_ = batch.trafficOrigin.Close()
	_ = batch.responseTime.Close()
}
