package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSoftBlockDoctorReportsConfigAndSocketStateWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"log_sources":{"default":{"path":"/tmp/access.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":"/tmp/db.sqlite","block_mode":"soft_block","block_duration":"1m","engine":{"rules":[{"id":"r1","log_source":"default","path_regex":"^/$","window":"1s","threshold":2,"group_by":"ip"}]},"soft_block":{"cookie_ttl":"1h","sites":{"bgt":{"hosts":["example.test"],"log_sources":["default"]}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := softBlockCommand(context.Background(), []string{"doctor", "--config", configPath, "--site", "bgt", "--feed-socket", filepath.Join(dir, "missing-feed.sock"), "--check-socket", filepath.Join(dir, "missing-check.sock"), "--nginx-binary", filepath.Join(dir, "missing-nginx")}, &out)
	if err != nil {
		t.Fatalf("doctor returned command error: %v", err)
	}
	got := out.String()
	for _, expected := range []string{"config: OK", "site bgt: OK", "feed socket: MISSING", "check socket: MISSING", "nginx auth_request: UNKNOWN"} {
		if !strings.Contains(got, expected) {
			t.Errorf("doctor output missing %q:\n%s", expected, got)
		}
	}
}

func TestSoftBlockDoctorRejectsUnreadableConfig(t *testing.T) {
	var out bytes.Buffer
	err := softBlockCommand(context.Background(), []string{"doctor", "--config", filepath.Join("testdata", "does-not-exist"), "--site", "absent"}, &out)
	if err == nil || !strings.Contains(err.Error(), "load config") {
		t.Fatalf("expected config error, got %v", err)
	}
}
