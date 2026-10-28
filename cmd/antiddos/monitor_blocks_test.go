package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

func TestMonitorShowsChallengeStatusAndSurvivesUnavailableChecker(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "state.sqlite")
	store, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	contents := fmt.Sprintf(`{"log_sources":{"web":{"path":"/tmp/access.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":%q,"block_mode":"soft_block","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"rules":[{"id":"r1","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`, databasePath)
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "admin.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/metrics" {
			_, _ = w.Write([]byte(`[{"bucket":1792756800,"site":"main","reason":"issued","count":3}]`))
			return
		}
		_, _ = w.Write([]byte(`{"health":"ready","mode":"soft_block","config_revision":"cfg1","epoch":"e1","revision":2,"sites":1,"metrics_health":"ready","metrics_dropped":0}`))
	})}
	go server.Serve(listener)
	var output bytes.Buffer
	err = executeCommand(context.Background(), []string{"monitor", "--once", "--config", configPath, "--challenge-admin-socket", socketPath}, slog.Default(), &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Challenge: ready (running mode=soft_block revision=cfg1 sites=1)") {
		t.Fatalf("monitor output:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "CHALLENGE METRICS") || !strings.Contains(output.String(), "issued") || !strings.Contains(output.String(), "main") {
		t.Fatalf("missing checker metrics:\n%s", output.String())
	}
	_ = server.Close()
	output.Reset()
	err = executeCommand(context.Background(), []string{"monitor", "--once", "--config", configPath, "--challenge-admin-socket", socketPath}, slog.Default(), &output)
	if err != nil {
		t.Fatalf("monitor failed with checker unavailable: %v", err)
	}
	if !strings.Contains(output.String(), "Challenge: unavailable") || !strings.Contains(output.String(), "TRAFFIC") {
		t.Fatalf("degraded monitor output:\n%s", output.String())
	}
}
