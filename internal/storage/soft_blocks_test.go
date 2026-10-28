package storage

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestReaderListsOnlyActiveSoftDecisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	for _, l := range []SoftBlockLease{
		{SiteID: "bgt", RuleID: "demo", SourceID: "web", IP: netip.MustParseAddr("192.0.2.1"), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		{SiteID: "bgt", RuleID: "demo", SourceID: "web", IP: netip.MustParseAddr("192.0.2.2"), CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute)},
	} {
		if err := store.CreateSoftBlockLease(context.Background(), l); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	leases, err := reader.ActiveSoftBlocks(context.Background(), now, 1)
	if err != nil || len(leases) != 1 || leases[0].IP.String() != "192.0.2.1" || leases[0].SiteID != "bgt" {
		t.Fatalf("leases=%+v err=%v", leases, err)
	}
	if _, err := reader.ActiveSoftBlocks(context.Background(), now, 1001); err == nil {
		t.Fatal("accepted unbounded limit")
	}
}

func TestSoftBlockLeaseAndAuditCommitAtomically(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.Exec(`CREATE TRIGGER fail_soft_audit BEFORE INSERT ON soft_block_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lease := SoftBlockLease{SiteID: "main", RuleID: "r", SourceID: "web", IP: netip.MustParseAddr("192.0.2.1"), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, err := store.PutSoftBlockLease(context.Background(), lease); err == nil {
		t.Fatal("expected audit insert failure")
	}
	rows, err := store.SoftBlockDecisions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("lease persisted without audit: %+v", rows)
	}
}

func TestSoftBlockMigrationPreservesLegacyActiveBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE active_blocks(ip TEXT PRIMARY KEY,rule_id TEXT NOT NULL,started_at_unix_ms INTEGER NOT NULL,expires_at_unix_ms INTEGER NOT NULL); INSERT INTO active_blocks VALUES('203.0.113.9','legacy',100,9999999999999)`)
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
	rows, err := store.UnexpiredBlocks(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IP.String() != "203.0.113.9" || rows[0].RuleID != "legacy" {
		t.Fatalf("legacy active_blocks changed: %+v", rows)
	}
	lease := SoftBlockLease{SiteID: "main", RuleID: "r", SourceID: "web", IP: netip.MustParseAddr("2001:db8::1"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.CreateSoftBlockLease(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
}
