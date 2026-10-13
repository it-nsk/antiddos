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

	"github.com/it-nsk/antiddos/internal/config"
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

func TestMonitorLogFileOverrideUsesServiceEnvironmentFile(t *testing.T) {
	environmentFile := filepath.Join(t.TempDir(), "antiddos.env")
	if err := os.WriteFile(environmentFile, []byte("# installer override\nANTIDDOS_LOG_FILE=/www/bgtweb/runtime/antiddos_access.log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := monitorLogFileOverride(config.DefaultPath, "", environmentFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/www/bgtweb/runtime/antiddos_access.log"; got != want {
		t.Fatalf("monitorLogFileOverride() = %q, want %q", got, want)
	}
}

func TestMonitorLogFileOverridePrecedenceAndCustomConfig(t *testing.T) {
	environmentFile := filepath.Join(t.TempDir(), "antiddos.env")
	if err := os.WriteFile(environmentFile, []byte("ANTIDDOS_LOG_FILE=/from/systemd.log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := monitorLogFileOverride(config.DefaultPath, "/from/process.env", environmentFile)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/from/process.env" {
		t.Fatalf("process environment override = %q, want /from/process.env", got)
	}

	got, err = monitorLogFileOverride(filepath.Join(t.TempDir(), "custom.json"), "", environmentFile)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("custom config unexpectedly used global override %q", got)
	}
}

func TestParseLogFileOverride(t *testing.T) {
	got := parseLogFileOverride("# comment\nANTIDDOS_CONFIG=/etc/antiddos/config.json\nANTIDDOS_LOG_FILE=\"/var/log/nginx/access.log\"\nANTIDDOS_LOG_FILE='/var/log/nginx/final.log'\n")
	if want := "/var/log/nginx/final.log"; got != want {
		t.Fatalf("parseLogFileOverride() = %q, want %q", got, want)
	}
}
