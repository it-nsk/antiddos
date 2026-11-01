package storage

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/request"
	_ "github.com/mattn/go-sqlite3"
)

func TestDashboardReturnsDetectionReasonAndExactRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "details.sqlite")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().Truncate(time.Second)
	event := request.Event{
		Timestamp: when, IP: netip.MustParseAddr("203.0.113.10"), Method: "GET",
		Path: "/where2buy", RawQuery: "region=1%20UNION%20SELECT%20NULL", Protocol: "HTTP/2.0",
		Status: 200, UserAgent: "scanner", RawLine: `203.0.113.10 - - [date] "GET /where2buy?region=1%20UNION%20SELECT%20NULL HTTP/2.0" 200`,
	}
	detection := engine.Detection{
		RuleID: "web-sqli", LogSource: "web", GroupField: engine.GroupByIP, GroupValue: event.IP.String(),
		EventTimestamp: when, Count: 1, Window: time.Second, Threshold: 1, DryRun: true,
		Reason: "Query совпал с сигнатурой: UNION%20SELECT",
	}
	if err := store.RecordDetection(context.Background(), detection, event); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	dashboard, err := reader.Dashboard(context.Background(), when.Add(-time.Minute), when.Add(time.Minute), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard.Detections) != 1 {
		t.Fatalf("detections = %#v", dashboard.Detections)
	}
	got := dashboard.Detections[0]
	if got.RawQuery != event.RawQuery || got.Protocol != event.Protocol || got.RawEvent != event.RawLine || got.Reason != detection.Reason {
		t.Fatalf("detection details = %#v", got)
	}
}

func TestOpenAddsDetectionDetailsWithoutLosingExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE detections (
		id INTEGER PRIMARY KEY, log_source TEXT NOT NULL DEFAULT '', event_time_unix_ns INTEGER NOT NULL,
		event_time_text TEXT NOT NULL, recorded_at_unix_ms INTEGER NOT NULL, rule_id TEXT NOT NULL,
		grouping_id TEXT NOT NULL, group_values_json TEXT NOT NULL, trigger_ip TEXT NOT NULL,
		trigger_user_agent TEXT NOT NULL, method TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0, request_count INTEGER NOT NULL, window_millis INTEGER NOT NULL,
		threshold INTEGER NOT NULL, dry_run INTEGER NOT NULL
	);
	INSERT INTO detections VALUES (7,'web',1,'legacy',2,'web-sqli','ip','["203.0.113.10"]','203.0.113.10','agent','GET','/where2buy',200,1,1000,1,1)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var id int
	var pathValue, rawQuery, protocol, rawEvent, reason string
	if err := store.db.QueryRow(`SELECT id,path,raw_query,protocol,raw_event,reason FROM detections WHERE id=7`).Scan(&id, &pathValue, &rawQuery, &protocol, &rawEvent, &reason); err != nil {
		t.Fatal(err)
	}
	if id != 7 || pathValue != "/where2buy" || rawQuery != "" || protocol != "" || rawEvent != "" || reason != "" {
		t.Fatalf("migrated legacy row = %d %q %q %q %q %q", id, pathValue, rawQuery, protocol, rawEvent, reason)
	}
}
