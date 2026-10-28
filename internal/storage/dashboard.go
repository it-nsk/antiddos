package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"
)

type TrafficPoint struct {
	Time       int64 `json:"time"`
	Interval   int64 `json:"interval"`
	Requests   int64 `json:"requests"`
	Matched    int64 `json:"matched"`
	Bytes      int64 `json:"bytes"`
	KnownRows  int64 `json:"known_rows"`
	Detections int64 `json:"detections"`
}
type DashboardDetection struct {
	ID         int64  `json:"id"`
	SourceID   string `json:"source_id"`
	EventTime  string `json:"event_time"`
	RecordedAt int64  `json:"recorded_at"`
	Rule       string `json:"rule"`
	GroupBy    string `json:"group_by"`
	Group      string `json:"group"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int64  `json:"status"`
	Count      int64  `json:"count"`
	WindowMS   int64  `json:"window_ms"`
	Threshold  int64  `json:"threshold"`
}
type DashboardBlock struct {
	IP        string `json:"ip"`
	Rule      string `json:"rule"`
	StartedAt int64  `json:"started_at"`
	ExpiresAt int64  `json:"expires_at"`
}
type Dashboard struct {
	From           int64                `json:"from"`
	To             int64                `json:"to"`
	UpdatedAt      int64                `json:"updated_at"`
	Points         []TrafficPoint       `json:"points"`
	SourcePoints   []SourceTraffic      `json:"source_points"`
	Detections     []DashboardDetection `json:"detections"`
	Blocks         []DashboardBlock     `json:"blocks"`
	DetectionCount int64                `json:"detection_count"`
	BlockCount     int64                `json:"block_count"`
	NextBefore     int64                `json:"next_before"`
}

type SourceTraffic struct {
	SourceID string         `json:"source_id"`
	Points   []TrafficPoint `json:"points"`
}

// Dashboard returns a consistent, bounded snapshot. Traffic is aggregated across all sources.
// Detections are events, not proof that an enforcement action was applied.
func (r *Reader) Dashboard(ctx context.Context, from, to time.Time, before int64, limit int) (Dashboard, error) {
	d := Dashboard{From: from.Unix(), To: to.Unix(), UpdatedAt: time.Now().Unix(), Points: []TrafficPoint{}, SourcePoints: []SourceTraffic{}, Detections: []DashboardDetection{}, Blocks: []DashboardBlock{}}
	span := d.To - d.From
	if d.From < 0 || span < 15 || span > 31*86400 || limit < 1 || limit > 1000 || before < 0 {
		return d, fmt.Errorf("range must be 15 seconds–31 days; limit 1–1000; cursor nonnegative")
	}
	step := ((span+599)/600 + 14) / 15 * 15
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return d, err
	}
	defer tx.Rollback()
	points := map[int64]*TrafficPoint{}
	// Emit missing intervals explicitly; no requests were recorded in those intervals.
	for bucket := d.From / step * step; bucket < d.To; bucket += step {
		points[bucket] = &TrafficPoint{Time: bucket, Interval: step}
	}
	sourceBuckets := map[string]map[int64]*TrafficPoint{}
	sourceRows, err := tx.QueryContext(ctx, `SELECT source_id,(bucket_start_unix / ?) * ?,SUM(requests),SUM(matched_requests),SUM(response_bytes),SUM(known_response_byte_rows)
		FROM traffic_samples_by_source WHERE bucket_start_unix>=? AND bucket_start_unix<? GROUP BY 1,2 ORDER BY 1,2`, step, step, d.From, d.To)
	if err != nil {
		return d, err
	}
	for sourceRows.Next() {
		var sourceID string
		var p TrafficPoint
		if err := sourceRows.Scan(&sourceID, &p.Time, &p.Requests, &p.Matched, &p.Bytes, &p.KnownRows); err != nil {
			sourceRows.Close()
			return d, err
		}
		p.Interval = step
		if sourceBuckets[sourceID] == nil {
			sourceBuckets[sourceID] = make(map[int64]*TrafficPoint)
			for bucket := d.From / step * step; bucket < d.To; bucket += step {
				sourceBuckets[sourceID][bucket] = &TrafficPoint{Time: bucket, Interval: step}
			}
		}
		copy := p
		sourceBuckets[sourceID][p.Time] = &copy
	}
	if err := sourceRows.Err(); err != nil {
		sourceRows.Close()
		return d, err
	}
	if err := sourceRows.Close(); err != nil {
		return d, err
	}
	sourceDetectionRows, err := tx.QueryContext(ctx, `SELECT log_source,((event_time_unix_ns / 1000000000) / ?) * ?,COUNT(*)
		FROM detections WHERE event_time_unix_ns>=? AND event_time_unix_ns<? GROUP BY 1,2 ORDER BY 1,2`, step, step, from.UnixNano(), to.UnixNano())
	if err != nil {
		return d, err
	}
	for sourceDetectionRows.Next() {
		var sourceID string
		var bucket, count int64
		if err := sourceDetectionRows.Scan(&sourceID, &bucket, &count); err != nil {
			sourceDetectionRows.Close()
			return d, err
		}
		if sourceBuckets[sourceID] == nil {
			sourceBuckets[sourceID] = make(map[int64]*TrafficPoint)
			for bucketStart := d.From / step * step; bucketStart < d.To; bucketStart += step {
				sourceBuckets[sourceID][bucketStart] = &TrafficPoint{Time: bucketStart, Interval: step}
			}
		}
		if point := sourceBuckets[sourceID][bucket]; point != nil {
			point.Detections = count
		}
	}
	if err := sourceDetectionRows.Err(); err != nil {
		sourceDetectionRows.Close()
		return d, err
	}
	if err := sourceDetectionRows.Close(); err != nil {
		return d, err
	}
	for sourceID, buckets := range sourceBuckets {
		source := SourceTraffic{SourceID: sourceID, Points: make([]TrafficPoint, 0, len(buckets))}
		for bucket := d.From / step * step; bucket < d.To; bucket += step {
			p := *buckets[bucket]
			start := max(bucket, d.From)
			end := min(bucket+step, d.To)
			p.Time = start
			p.Interval = end - start
			source.Points = append(source.Points, p)
		}
		d.SourcePoints = append(d.SourcePoints, source)
	}
	sort.Slice(d.SourcePoints, func(i, j int) bool { return d.SourcePoints[i].SourceID < d.SourcePoints[j].SourceID })
	rows, err := tx.QueryContext(ctx, `SELECT (bucket_start_unix / ?) * ?, SUM(requests),SUM(matched_requests),SUM(response_bytes),SUM(known_response_byte_rows)
 FROM traffic_samples WHERE bucket_start_unix>=? AND bucket_start_unix<? GROUP BY 1 ORDER BY 1`, step, step, d.From, d.To)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var p TrafficPoint
		if err := rows.Scan(&p.Time, &p.Requests, &p.Matched, &p.Bytes, &p.KnownRows); err != nil {
			rows.Close()
			return d, err
		}
		p.Interval = step
		points[p.Time] = &p
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return d, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT ((event_time_unix_ns / 1000000000) / ?) * ?,COUNT(*) FROM detections WHERE event_time_unix_ns>=? AND event_time_unix_ns<? GROUP BY 1`, step, step, from.UnixNano(), to.UnixNano())
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var bucket, n int64
		if err := rows.Scan(&bucket, &n); err != nil {
			rows.Close()
			return d, err
		}
		if p := points[bucket]; p != nil {
			p.Detections = n
		}
		d.DetectionCount += n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return d, err
	}
	rows.Close()
	for bucket := d.From / step * step; bucket < d.To; bucket += step {
		p := *points[bucket]
		start := max(bucket, d.From)
		end := min(bucket+step, d.To)
		p.Time = start
		p.Interval = end - start
		d.Points = append(d.Points, p)
	}
	query := `SELECT id,log_source,event_time_text,recorded_at_unix_ms,rule_id,grouping_id,group_values_json,trigger_ip,trigger_user_agent,method,path,status,request_count,window_millis,threshold FROM detections WHERE event_time_unix_ns>=? AND event_time_unix_ns<?`
	args := []any{from.UnixNano(), to.UnixNano()}
	if before > 0 {
		query += ` AND id<?`
		args = append(args, before)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err = tx.QueryContext(ctx, query, args...)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var v DashboardDetection
		if err := rows.Scan(&v.ID, &v.SourceID, &v.EventTime, &v.RecordedAt, &v.Rule, &v.GroupBy, &v.Group, &v.IP, &v.UserAgent, &v.Method, &v.Path, &v.Status, &v.Count, &v.WindowMS, &v.Threshold); err != nil {
			rows.Close()
			return d, err
		}
		d.Detections = append(d.Detections, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return d, err
	}
	rows.Close()
	if len(d.Detections) > limit {
		d.Detections = d.Detections[:limit]
		d.NextBefore = d.Detections[limit-1].ID
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM active_blocks WHERE expires_at_unix_ms>?`, d.UpdatedAt*1000).Scan(&d.BlockCount); err != nil {
		return d, err
	}
	blocks, err := queryActiveBlocks(ctx, tx, time.Unix(d.UpdatedAt, 0), 1000)
	if err != nil {
		return d, err
	}
	for _, b := range blocks {
		d.Blocks = append(d.Blocks, DashboardBlock{b.IP.String(), b.RuleID, b.StartedAt.Unix(), b.ExpiresAt.Unix()})
	}
	return d, tx.Commit()
}
