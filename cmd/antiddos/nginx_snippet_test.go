package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNginxSnippetPreviewAndWrite(t *testing.T) {
	root := t.TempDir()
	configFile := filepath.Join(root, "config.json")
	configData, err := json.Marshal(map[string]any{
		"log_sources": map[string]any{"web": map[string]any{
			"path": "/tmp/web.log", "format": "nginx_custom",
			"log_format": `$remote_addr [$time_local] "$request" $status $body_bytes_sent $antiddos_response_origin`,
		}},
		"database_path": "/tmp/state.sqlite", "block_mode": "soft_block", "block_duration": "1m",
		"soft_block": map[string]any{"cookie_ttl": "30m", "sites": map[string]any{
			"bgt": map[string]any{"hosts": []string{"bgt.my"}, "log_sources": []string{"web"}},
		}},
		"engine": map[string]any{"rules": []any{map[string]any{
			"id": "limit", "log_source": "web", "path_regex": "^/$", "window": "5s", "threshold": 2, "group_by": "ip",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, configData, 0600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(root, "snippets")
	args := []string{"nginx-snippet", "--config", configFile, "--site", "bgt", "--output", outputDir}
	var preview bytes.Buffer
	if err := executeCommand(context.Background(), args, slog.Default(), &preview); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.String(), "===== "+filepath.Join(outputDir, "server-context.conf")+" =====") || !strings.Contains(preview.String(), "auth_request /__antiddos_check;") {
		t.Fatalf("preview missing generated Nginx configuration:\n%s", preview.String())
	}
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		t.Fatalf("preview created output directory: err=%v", err)
	}

	writeArgs := append(append([]string(nil), args...), "--write")
	var written bytes.Buffer
	if err := executeCommand(context.Background(), writeArgs, slog.Default(), &written); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(written.String(), "No active Nginx configuration was edited or reloaded") {
		t.Fatalf("write output does not state that active Nginx was left untouched: %s", written.String())
	}
	for _, name := range []string{"http-shared.conf", "http-site.conf", "server-context.conf", "proxy-location.conf", "fastcgi-location.conf", "README.txt"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Errorf("generated file %s: %v", name, err)
		}
	}
	if err := executeCommand(context.Background(), writeArgs, slog.Default(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second --write error = %v, want no-overwrite error", err)
	}
}
