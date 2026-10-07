package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"

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
