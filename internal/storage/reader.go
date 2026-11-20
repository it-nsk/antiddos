package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"time"

	"github.com/it-nsk/antiddos/internal/metrics"
)

// Reader never creates a database, changes permissions, or runs migrations.
type Reader struct{ db *sql.DB }

func OpenReader(path string) (*Reader, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("SQLite path must be absolute")
	}
	u := &url.URL{Scheme: "file", Path: filepath.Clean(path)}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("_busy_timeout", "5000")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("read database %s: %w", path, err)
	}
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error { return r.db.Close() }

type DetectionRow struct {
	ID               int64
	EventTimeText    string
	RuleID           string
	GroupingID       string
	GroupValuesJSON  string
	TriggerIP        string
	TriggerUserAgent string
	RequestCount     int64
	WindowMillis     int64
	Threshold        int64
}

// HistoricalDetection is a provenance-scoped detection from an isolated
// historical result. The import ID is selected by the caller and is never
// inferred from live detections.
type HistoricalDetection struct {
	DetectionRow
	LogSource string
	EventTime time.Time
}

type BlockRow struct {
	IP        netip.Addr
	RuleID    string
	StartedAt time.Time
	ExpiresAt time.Time
	Origin    string
}

func (r *Reader) ActiveBlocks(ctx context.Context, now time.Time, limit int) ([]BlockRow, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}
	return queryActiveBlocks(ctx, r.db, now, limit)
}

type rowsQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func queryActiveBlocks(ctx context.Context, db rowsQuerier, now time.Time, limit int) ([]BlockRow, error) {
	query := `SELECT ip, rule_id, started_at_unix_ms, expires_at_unix_ms, origin
		FROM active_blocks WHERE expires_at_unix_ms > ?
		ORDER BY expires_at_unix_ms DESC, ip`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = db.QueryContext(ctx, query+` LIMIT ?`, now.UnixMilli(), limit)
	} else {
		rows, err = db.QueryContext(ctx, query, now.UnixMilli())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]BlockRow, 0)
	for rows.Next() {
		var row BlockRow
		var ip string
		var startedAt, expiresAt int64
		if err := rows.Scan(&ip, &row.RuleID, &startedAt, &expiresAt, &row.Origin); err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("read invalid stored block IP %q: %w", ip, err)
		}
		row.IP = address
		row.StartedAt = time.UnixMilli(startedAt)
		row.ExpiresAt = time.UnixMilli(expiresAt)
		result = append(result, row)
	}
	return result, rows.Err()
}

func (r *Reader) Detections(ctx context.Context, limit int) ([]DetectionRow, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, event_time_text, rule_id,
		grouping_id, group_values_json, trigger_ip, trigger_user_agent,
		request_count, window_millis, threshold
		FROM detections ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DetectionRow, 0)
	for rows.Next() {
		var row DetectionRow
		if err := rows.Scan(&row.ID, &row.EventTimeText, &row.RuleID, &row.GroupingID,
			&row.GroupValuesJSON, &row.TriggerIP, &row.TriggerUserAgent,
			&row.RequestCount, &row.WindowMillis, &row.Threshold); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// HistoricalDetectionsRange returns detections owned by one historical import
// in the half-open event-time range. It is deliberately provenance-scoped so
// an isolated database with unrelated rows cannot leak them into a catalog.
func (r *Reader) HistoricalDetectionsRange(ctx context.Context, importID string, from, to time.Time, limit int) ([]HistoricalDetection, error) {
	if importID == "" || !from.Before(to) || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("import, ordered detection range, and limit 1-1000 are required")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT d.id,d.log_source,d.event_time_unix_ns,d.event_time_text,d.rule_id,
		d.grouping_id,d.group_values_json,d.trigger_ip,d.trigger_user_agent,
		d.request_count,d.window_millis,d.threshold
		FROM detections d JOIN history_detection_provenance p ON p.detection_id=d.id
		WHERE p.import_id=? AND d.event_time_unix_ns>=? AND d.event_time_unix_ns<?
		ORDER BY d.event_time_unix_ns,d.id LIMIT ?`, importID, from.UnixNano(), to.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []HistoricalDetection{}
	for rows.Next() {
		var item HistoricalDetection
		var eventNS int64
		if err := rows.Scan(&item.ID, &item.LogSource, &eventNS, &item.EventTimeText, &item.RuleID,
			&item.GroupingID, &item.GroupValuesJSON, &item.TriggerIP, &item.TriggerUserAgent,
			&item.RequestCount, &item.WindowMillis, &item.Threshold); err != nil {
			return nil, err
		}
		item.EventTime = time.Unix(0, eventNS)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *Reader) Traffic(ctx context.Context, limit int) ([]metrics.Sample, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT bucket_start_unix, interval_seconds,
		requests, matched_requests, response_bytes, known_response_byte_rows
		FROM traffic_samples ORDER BY bucket_start_unix DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]metrics.Sample, 0)
	for rows.Next() {
		var s metrics.Sample
		if err := rows.Scan(&s.BucketStartUnix, &s.IntervalSeconds, &s.Requests, &s.MatchedRequests,
			&s.ResponseBytes, &s.KnownResponseByteRows); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// TrafficRange returns source-scoped, unaggregated 15-second historical
// samples. It is read-only and uses the half-open event-time convention.
func (r *Reader) TrafficRange(ctx context.Context, sourceID string, from, to time.Time) ([]metrics.Sample, error) {
	if sourceID == "" || !from.Before(to) {
		return nil, fmt.Errorf("source and ordered traffic range are required")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT source_id,bucket_start_unix,interval_seconds,requests,matched_requests,response_bytes,known_response_byte_rows FROM traffic_samples_by_source WHERE source_id=? AND bucket_start_unix>=? AND bucket_start_unix<? ORDER BY bucket_start_unix`, sourceID, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []metrics.Sample{}
	for rows.Next() {
		var s metrics.Sample
		if err := rows.Scan(&s.SourceID, &s.BucketStartUnix, &s.IntervalSeconds, &s.Requests, &s.MatchedRequests, &s.ResponseBytes, &s.KnownResponseByteRows); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}
