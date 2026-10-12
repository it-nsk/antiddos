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
	cfg, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log","block_mode":"nftables","block_duration":"1m","block_tcp_ports":[80,443]}`), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != BlockModeNFTables || cfg.BlockDuration != time.Minute || len(cfg.BlockTCPPorts) != 2 || cfg.BlockTCPPorts[0] != 80 || cfg.BlockTCPPorts[1] != 443 {
		t.Fatalf("block settings = %q, %s, ports %v; want nftables, 1m, [80 443]", cfg.BlockMode, cfg.BlockDuration, cfg.BlockTCPPorts)
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

func TestDecodeRejectsInvalidBlockTCPPorts(t *testing.T) {
	for _, ports := range []string{`[0]`, `[65536]`, `[-1]`, `[443,443]`, `[{"port":443}]`} {
		document := `{"log_file":"/tmp/access.log","block_tcp_ports":` + ports + `}`
		if _, err := decode(strings.NewReader(document), "test", ""); err == nil {
			t.Errorf("decode with block_tcp_ports %s unexpectedly succeeded", ports)
		}
	}
}
