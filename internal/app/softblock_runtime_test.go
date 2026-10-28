package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/softfeed"
	"github.com/it-nsk/antiddos/internal/storage"
)

func TestSoftBlockRunPublishesDetectionAndStopsFeedSocket(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	configPath := filepath.Join(dir, "config.json")
	feedPath := filepath.Join(dir, "feed", "feed.sock")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := map[string]any{
		"log_sources":   map[string]any{"web": map[string]any{"path": logPath, "format": "nginx_custom", "log_format": `log_format antiddos '$remote_addr [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $antiddos_response_origin';`}},
		"database_path": filepath.Join(dir, "state.sqlite"), "start_position": "end", "block_mode": "soft_block", "block_duration": "1m",
		"soft_block": map[string]any{"cookie_ttl": "30m", "sites": map[string]any{"main": map[string]any{"hosts": []string{"example.test"}, "log_sources": []string{"web"}}}},
		"engine":     map[string]any{"rules": []any{map[string]any{"id": "home", "log_source": "web", "path_regex": `^/$`, "window": "5s", "threshold": 1, "group_by": "ip"}}},
	}
	raw, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	groupID := os.Getgid()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	go func() {
		done <- Run(ctx, RunOptions{Config: configPath, SoftFeedSocketPath: feedPath, SoftFeedSocketGroupID: &groupID}, logger)
	}()
	waitForFeedSocket(t, feedPath)
	line := fmt.Sprintf("192.0.2.55 [%s] \"GET / HTTP/1.1\" 200 1 \"-\" \"softblock-test\" application\n", time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := file.WriteString(line); err != nil {
		file.Close()
		cancel()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		cancel()
		t.Fatal(err)
	}
	state := softfeed.NewState()
	client := softfeed.Client{SocketPath: feedPath, State: state}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.PollOnce(context.Background()); err == nil {
			if snapshot, ok := state.Current(); ok && len(snapshot.Decisions) == 1 {
				if snapshot.Decisions[0].SiteID != "main" || snapshot.Decisions[0].RuleID != "home" || snapshot.Decisions[0].IP != netip.MustParseAddr("192.0.2.55").String() {
					cancel()
					t.Fatalf("unexpected decision: %+v", snapshot.Decisions[0])
				}
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	snapshot, ok := state.Current()
	if !ok || len(snapshot.Decisions) != 1 {
		cancel()
		t.Fatalf("soft-block detection was not published: %+v", snapshot)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("soft-block daemon run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("soft-block daemon did not stop cleanly")
	}
	if _, err := os.Lstat(feedPath); !os.IsNotExist(err) {
		t.Fatalf("feed socket remains after shutdown: %v", err)
	}
}

func TestHybridRunAppliesFirewallAndPublishesSoftDecision(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	nftPath := filepath.Join(binDir, "nft")
	if err := os.WriteFile(nftPath, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	logPath := filepath.Join(dir, "access.log")
	configPath := filepath.Join(dir, "config.json")
	databasePath := filepath.Join(dir, "state.sqlite")
	feedPath := filepath.Join(dir, "feed", "feed.sock")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := map[string]any{
		"log_sources":   map[string]any{"web": map[string]any{"path": logPath, "format": "nginx_custom", "log_format": `log_format antiddos '$remote_addr [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $antiddos_response_origin';`}},
		"database_path": databasePath, "start_position": "end", "block_mode": "hybrid", "block_duration": "1m",
		"soft_block": map[string]any{"cookie_ttl": "30m", "sites": map[string]any{"main": map[string]any{"hosts": []string{"example.test"}, "log_sources": []string{"web"}}}},
		"engine": map[string]any{"rules": []any{
			map[string]any{"id": "observe", "action": "dry_run", "log_source": "web", "path_regex": `^/$`, "window": "10s", "threshold": 1, "group_by": "ip"},
			map[string]any{"id": "captcha", "action": "soft_block", "log_source": "web", "path_regex": `^/$`, "window": "10s", "threshold": 1, "group_by": "ip"},
			map[string]any{"id": "firewall", "action": "nftables", "log_source": "web", "path_regex": `^/$`, "window": "1s", "threshold": 1, "group_by": "ip"},
		}},
	}
	raw, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	groupID := os.Getgid()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunOptions{Config: configPath, SoftFeedSocketPath: feedPath, SoftFeedSocketGroupID: &groupID}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	waitForFeedSocket(t, feedPath)
	state := softfeed.NewState()
	client := softfeed.Client{SocketPath: feedPath, State: state}
	if err := client.PollOnce(context.Background()); err != nil {
		cancel()
		t.Fatal(err)
	}
	pollDone := make(chan error, 1)
	go func() { pollDone <- client.PollOnce(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	started := time.Now()
	line := fmt.Sprintf("192.0.2.77 [%s] \"GET / HTTP/1.1\" 200 1 \"-\" \"hybrid-test\" application", time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	appendLines(t, logPath, []string{line})
	select {
	case err := <-pollDone:
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		elapsed := time.Since(started)
		t.Logf("detection log append to checker snapshot wake: %s", elapsed)
		if elapsed > 500*time.Millisecond {
			cancel()
			t.Fatalf("decision feed wake took %s, want <=500ms", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		cancel()
		t.Fatal("checker feed did not wake within 500ms")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		reader, openErr := storage.OpenReader(databasePath)
		if openErr == nil {
			blocks, blockErr := reader.ActiveBlocks(context.Background(), time.Now(), 10)
			_ = reader.Close()
			snapshot, ready := state.Current()
			if blockErr == nil && len(blocks) == 1 && ready && len(snapshot.Decisions) == 1 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	reader, err := storage.OpenReader(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	blocks, err := reader.ActiveBlocks(context.Background(), time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ready := state.Current()
	detections, err := reader.Detections(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || blocks[0].RuleID != "firewall" || !ready || len(snapshot.Decisions) != 1 || snapshot.Decisions[0].RuleID != "captcha" || snapshot.Mode != "hybrid" {
		t.Fatalf("hybrid result: blocks=%+v snapshot=%+v", blocks, snapshot)
	}
	seen := map[string]bool{}
	for _, detection := range detections {
		seen[detection.RuleID] = true
	}
	if !seen["observe"] || !seen["captcha"] || !seen["firewall"] {
		t.Fatalf("hybrid detections = %+v; want dry, soft and nft rules", detections)
	}
}

func TestDryOnlyHybridPublishesDisabledFeedAndOnlyRecordsDetection(t *testing.T) {
	t.Setenv("ANTIDDOS_SOFT_BLOCK_ENABLED", "1")
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	configPath := filepath.Join(dir, "config.json")
	databasePath := filepath.Join(dir, "state.sqlite")
	feedPath := filepath.Join(dir, "feed", "feed.sock")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := map[string]any{
		"log_sources":   map[string]any{"audit": map[string]any{"path": logPath, "format": "nginx_combined"}},
		"database_path": databasePath, "start_position": "end", "block_mode": "hybrid", "block_duration": "1m",
		"engine": map[string]any{"rules": []any{map[string]any{"id": "observe", "action": "dry_run", "log_source": "audit", "path_regex": `^/$`, "window": "5s", "threshold": 1, "group_by": "path"}}},
	}
	raw, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	groupID := os.Getgid()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunOptions{Config: configPath, SoftFeedSocketPath: feedPath, SoftFeedSocketGroupID: &groupID}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	waitForFeedSocket(t, feedPath)
	state := softfeed.NewState()
	client := softfeed.Client{SocketPath: feedPath, State: state}
	if err := client.PollOnce(context.Background()); err != nil {
		cancel()
		t.Fatal(err)
	}
	if snapshot, ok := state.Current(); !ok || snapshot.Mode != "hybrid" || len(snapshot.Sites) != 0 {
		cancel()
		t.Fatalf("dry-only snapshot = %+v, ready=%v", snapshot, ok)
	}
	if check := state.Check("missing", netip.MustParseAddr("192.0.2.10"), time.Now()); check.Challenge || check.Reason != "mode_disabled" {
		cancel()
		t.Fatalf("dry-only checker result = %+v", check)
	}
	line := fmt.Sprintf("192.0.2.10 - - [%s] \"GET / HTTP/1.1\" 200 1 \"-\" \"dry-only-test\"", time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	appendLines(t, logPath, []string{line})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		reader, openErr := storage.OpenReader(databasePath)
		if openErr == nil {
			detections, readErr := reader.Detections(context.Background(), 10)
			blocks, blockErr := reader.ActiveBlocks(context.Background(), time.Now(), 10)
			_ = reader.Close()
			if readErr == nil && blockErr == nil && len(detections) == 1 && detections[0].RuleID == "observe" && len(blocks) == 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	reader, err := storage.OpenReader(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	detections, err := reader.Detections(context.Background(), 10)
	if err != nil || len(detections) != 1 || detections[0].RuleID != "observe" {
		t.Fatalf("detections = %+v, %v", detections, err)
	}
	blocks, err := reader.ActiveBlocks(context.Background(), time.Now(), 10)
	if err != nil || len(blocks) != 0 {
		t.Fatalf("blocks = %+v, %v", blocks, err)
	}
}

func TestNonSoftStartupRevokesPersistedSoftDecisionsWithoutStartingFeed(t *testing.T) {
	t.Setenv("ANTIDDOS_SOFT_BLOCK_ENABLED", "")
	dir := t.TempDir()
	databasePath := filepath.Join(dir, "state.sqlite")
	store, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := store.PutSoftBlockLease(context.Background(), storage.SoftBlockLease{SiteID: "main", RuleID: "home", SourceID: "web", IP: netip.MustParseAddr("192.0.2.55"), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	logPath, configPath := filepath.Join(dir, "access.log"), filepath.Join(dir, "config.json")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`{"log_sources":{"web":{"path":%q,"format":"nginx_custom","log_format":%q}},"database_path":%q,"start_position":"beginning","block_mode":"dry_run","block_duration":"1m","engine":{"rules":[{"id":"home","log_source":"web","path_regex":"^/$","window":"5s","threshold":1,"group_by":"ip"}]}}`, logPath, `log_format antiddos '$remote_addr [$time_local] "$request" $status';`, databasePath)
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, RunOptions{Config: configPath, FromStart: true}, logger) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		reader, openErr := storage.Open(databasePath)
		if openErr == nil {
			remaining, readErr := reader.SoftBlockDecisions(context.Background())
			_ = reader.Close()
			if readErr == nil && len(remaining) == 0 {
				break
			}
		}
		select {
		case runErr := <-done:
			cancel()
			t.Fatalf("daemon exited before soft decision revocation: %v", runErr)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop after disable-mode cleanup")
	}
	reader, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	remaining, err := reader.SoftBlockDecisions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("non-soft startup retained decisions: %+v", remaining)
	}
}

func waitForFeedSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("feed socket %s was not created", path)
}
