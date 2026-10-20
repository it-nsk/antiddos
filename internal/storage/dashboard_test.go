package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDashboardRangeAggregationPagination(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "stats.sqlite")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Unix(1800000000, 0)
	for i := 0; i < 3; i++ {
		_, err := store.db.Exec(`INSERT INTO traffic_samples VALUES(?,?,?,?,?,?)`, base.Unix()+int64(i*15), 15, 10, 4, 200, 5)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		_, err := store.db.Exec(`INSERT INTO detections(event_time_unix_ns,event_time_text,recorded_at_unix_ms,rule_id,grouping_id,group_values_json,trigger_ip,trigger_user_agent,request_count,window_millis,threshold,dry_run) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, base.Add(time.Duration(i)*time.Second).UnixNano(), base.Format(time.RFC3339), base.UnixMilli(), "home", "ip", "[\"192.0.2.1\"]", "192.0.2.1", "test", 5, 5000, 5, 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = store.db.Exec(`INSERT INTO active_blocks VALUES(?,?,?,?)`, "192.0.2.2", "home", time.Now().UnixMilli(), time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	d, err := reader.Dashboard(ctx, base, base.Add(time.Hour), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	var req, matched, bytes, known int64
	for _, p := range d.Points {
		req += p.Requests
		matched += p.Matched
		bytes += p.Bytes
		known += p.KnownRows
	}
	if req != 30 || matched != 12 || bytes != 600 || known != 15 || d.DetectionCount != 4 || len(d.Detections) != 2 || d.NextBefore == 0 || d.BlockCount != 1 {
		t.Fatalf("wrong snapshot: %+v totals %d %d %d %d", d, req, matched, bytes, known)
	}
	next, err := reader.Dashboard(ctx, base, base.Add(time.Hour), d.NextBefore, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Detections) != 2 || next.NextBefore != 0 || next.Detections[0].ID >= d.NextBefore {
		t.Fatal("pagination")
	}
	empty, err := reader.Dashboard(ctx, base.Add(time.Hour), base.Add(2*time.Hour), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if empty.DetectionCount != 0 || len(empty.Detections) != 0 || empty.Points[0].Requests != 0 {
		t.Fatal("range not applied")
	}
	large, err := reader.Dashboard(ctx, base, base.Add(31*24*time.Hour), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(large.Points) > 602 {
		t.Fatal("unbounded points")
	}
	if _, err := reader.Dashboard(ctx, base, base.Add(32*24*time.Hour), 0, 100); err == nil {
		t.Fatal("unbounded range")
	}
}
