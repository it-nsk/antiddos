package config

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeBlockSettingsDefaultToDryRun(t *testing.T) {
	cfg, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log"}`), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != BlockModeDryRun {
		t.Fatalf("BlockMode = %q, want %q", cfg.BlockMode, BlockModeDryRun)
	}
	if cfg.BlockDuration != 5*time.Minute {
		t.Fatalf("BlockDuration = %s, want 5m", cfg.BlockDuration)
	}
}

func TestDecodeBlockSettingsAcceptNFTablesAndMinuteDuration(t *testing.T) {
	cfg, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log","block_mode":"nftables","block_duration":"1m"}`), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != BlockModeNFTables || cfg.BlockDuration != time.Minute {
		t.Fatalf("block settings = %q, %s; want nftables, 1m", cfg.BlockMode, cfg.BlockDuration)
	}
}

func TestDecodeRejectsUnknownBlockModeAndInvalidDuration(t *testing.T) {
	for _, document := range []string{
		`{"log_file":"/tmp/access.log","block_mode":"root"}`,
		`{"log_file":"/tmp/access.log","block_duration":"soon"}`,
	} {
		if _, err := decode(strings.NewReader(document), "test", ""); err == nil {
			t.Errorf("decode(%s) unexpectedly succeeded", document)
		}
	}
}
