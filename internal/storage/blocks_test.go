package storage

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestActiveBlockRecordsAreReadableAndExpiredRowsCanBePruned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("203.0.113.42")
	if err := store.RecordBlock(context.Background(), ip, "homepage", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	rows, err := reader.ActiveBlocks(context.Background(), now.Add(30*time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IP != ip || rows[0].RuleID != "homepage" || !rows[0].StartedAt.Equal(now) || !rows[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("active blocks = %+v", rows)
	}
	rows, err = reader.ActiveBlocks(context.Background(), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("expired block still visible: %+v", rows)
	}
	if err := store.PruneExpiredBlocks(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestNFTMigrationStateAndCompletionAreTransactional(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "migration.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if state, err := store.NFTMigrationState(ctx); err != nil || state != "" {
		t.Fatalf("initial state=%q err=%v", state, err)
	}
	now := time.Now().UTC()
	if err := store.RecordBlock(ctx, netip.MustParseAddr("192.0.2.10"), "home", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkNFTMigrationPending(ctx); err != nil {
		t.Fatal(err)
	}
	if state, err := store.NFTMigrationState(ctx); err != nil || state != "firewall_pending" {
		t.Fatalf("pending state=%q err=%v", state, err)
	}
	removed, err := store.CompleteNFTMigration(ctx)
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if state, err := store.NFTMigrationState(ctx); err != nil || state != "complete" {
		t.Fatalf("complete state=%q err=%v", state, err)
	}
	if blocks, err := store.UnexpiredBlocks(ctx, now); err != nil || len(blocks) != 0 {
		t.Fatalf("blocks=%v err=%v", blocks, err)
	}
	if removed, err := store.CompleteNFTMigration(ctx); err != nil || removed != 0 {
		t.Fatalf("idempotent removed=%d err=%v", removed, err)
	}
}

func TestRecordBlockRejectsInvalidLease(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.RecordBlock(context.Background(), netip.Addr{}, "homepage", time.Now(), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("invalid IP was accepted")
	}
}
