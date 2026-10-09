package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/storage"
)

func TestMonitorShowsUnexpiredBlockRecords(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "state.sqlite")
	store, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ip := netip.MustParseAddr("203.0.113.42")
	if err := store.RecordBlock(context.Background(), ip, "homepage", now, now.Add(time.Minute)); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	contents := fmt.Sprintf(`{"log_file":"/var/log/nginx/access.log","database_path":%q}`, databasePath)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err = executeCommand(context.Background(), []string{"monitor", "--once", "--limit", "5", "--config", configPath}, slog.Default(), &output)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"BLOCKS (active, latest 5)", "203.0.113.42", "homepage", "EXPIRES AT", "REMAINING"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("monitor output missing %q:\n%s", expected, output.String())
		}
	}
}
