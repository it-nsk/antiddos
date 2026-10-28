package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareV04RollbackWritesSeparateCompatibleConfig(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "current.json")
	output := filepath.Join(directory, "rollback-v0.4.json")
	current := `{
  "log_sources": {"web": {"path":"/var/log/nginx/access.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" $antiddos_response_origin"}},
  "database_path":"/var/lib/antiddos/antiddos.sqlite",
  "block_mode":"soft_block",
  "block_duration":"5m",
  "block_tcp_ports":[80,443],
  "soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},
  "engine":{"rules":[{"id":"home","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}
}`
	if err := os.WriteFile(input, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	var commandOutput bytes.Buffer
	if err := prepareV04Rollback([]string{"--config", input, "--output", output}, &commandOutput); err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(input)
	if err != nil || string(unchanged) != current {
		t.Fatalf("source config changed: err=%v", err)
	}
	prepared, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(prepared, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["block_mode"] != "dry_run" {
		t.Fatalf("block_mode=%v, want dry_run", decoded["block_mode"])
	}
	if _, exists := decoded["soft_block"]; exists {
		t.Fatal("rollback config retained soft_block")
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rollback mode=%v", info.Mode().Perm())
	}
	if err := prepareV04Rollback([]string{"--config", input, "--output", output}, &commandOutput); err == nil || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("existing output was not rejected: %v", err)
	}
	if err := prepareV04Rollback([]string{"--config", input, "--output", input}, &commandOutput); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("in-place rewrite was not rejected: %v", err)
	}
}
