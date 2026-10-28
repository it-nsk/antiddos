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

func TestSoftBlockConfigRequiresValidSiteSourceAndOriginMarker(t *testing.T) {
	document := `{"log_sources":{"web":{"path":"/tmp/web.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":"/tmp/db.sqlite","block_mode":"soft_block","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"rules":[{"id":"r","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != BlockModeSoftBlock || cfg.SoftBlock.CookieTTL != 30*time.Minute || len(cfg.SoftBlock.Sites) != 1 {
		t.Fatalf("soft block config = %#v", cfg.SoftBlock)
	}
	for _, invalid := range []string{
		strings.Replace(document, `"log_sources":["web"]`, `"log_sources":["missing"]`, 1),
		strings.Replace(document, `$antiddos_response_origin`, `-`, 1),
		strings.Replace(document, `"example.test"`, `"https://example.test/path"`, 1),
		strings.Replace(document, `"30m"`, `"0s"`, 1),
	} {
		if _, err := decode(strings.NewReader(invalid), "test", ""); err == nil {
			t.Errorf("accepted invalid soft-block config: %s", invalid)
		}
	}
}

func TestHybridConfigRequiresExplicitRuleActions(t *testing.T) {
	document := `{"log_sources":{"web":{"path":"/tmp/web.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":"/tmp/db.sqlite","block_mode":"hybrid","block_duration":"1m","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"rules":[{"id":"observe","action":"dry_run","log_source":"web","path_regex":"^/observe","window":"10s","threshold":8,"group_by":"ip"},{"id":"captcha","action":"soft_block","log_source":"web","path_regex":"^/","window":"10s","threshold":8,"group_by":"ip"},{"id":"firewall","action":"nftables","log_source":"web","path_regex":"^/","window":"1s","threshold":10,"group_by":"ip"}]}}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != BlockModeHybrid || cfg.Engine.Rules[0].Action != RuleActionDryRun || cfg.Engine.Rules[1].Action != RuleActionSoftBlock || cfg.Engine.Rules[2].Action != RuleActionNFTables {
		t.Fatalf("hybrid config = %#v", cfg)
	}

	for _, invalid := range []string{
		strings.Replace(document, `"action":"soft_block",`, "", 1),
		strings.Replace(document, `"action":"soft_block"`, `"action":"unknown"`, 1),
		strings.Replace(document, `"group_by":"ip"`, `"group_by":"path"`, 2),
	} {
		if _, err := decode(strings.NewReader(invalid), "test", ""); err == nil {
			t.Errorf("accepted invalid hybrid config: %s", invalid)
		}
	}
}

func TestHybridCanContainOnlyDryRunRulesWithoutSoftBlockConfig(t *testing.T) {
	document := `{"log_sources":{"audit":"/tmp/audit.log"},"block_mode":"hybrid","engine":{"rules":[{"id":"observe","action":"dry_run","log_source":"audit","path_regex":"^/","window":"5s","threshold":2,"group_by":"ip"}]}}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveRuleAction(cfg.BlockMode, cfg.Engine.Rules[0]); got != RuleActionDryRun {
		t.Fatalf("effective action = %q, want %q", got, RuleActionDryRun)
	}
	if UsesSoftBlock(cfg) || UsesNFTables(cfg) {
		t.Fatalf("dry-only hybrid enabled enforcement: %#v", cfg)
	}
}

func TestHybridSupportsIndependentActionsAcrossSiteLogSources(t *testing.T) {
	document := `{
  "log_sources": {
    "site1": {"path":"/tmp/site1.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"},
    "site2": "/tmp/site2.log",
    "site3": "/tmp/site3.log"
  },
  "block_mode":"hybrid",
  "soft_block":{"cookie_ttl":"30m","sites":{"site1":{"hosts":["site1.test"],"log_sources":["site1"]}}},
  "engine":{"rules":[
    {"id":"site1-soft","action":"soft_block","log_source":"site1","path_regex":"^/","window":"10s","threshold":8,"group_by":"ip"},
    {"id":"site1-hard","action":"nftables","log_source":"site1","path_regex":"^/","window":"1s","threshold":10,"group_by":"ip"},
    {"id":"site2-observe","action":"dry_run","log_source":"site2","path_regex":"^/","window":"10s","threshold":8,"group_by":"path"},
    {"id":"site3-hard","action":"nftables","log_source":"site3","path_regex":"^/","window":"1s","threshold":10,"group_by":"ip"}
  ]}
}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LogSources) != 3 || len(cfg.SoftBlock.Sites) != 1 || cfg.SoftBlock.Sites[0].ID != "site1" {
		t.Fatalf("independent site config = %#v", cfg)
	}
	if !UsesSoftBlock(cfg) || !UsesNFTables(cfg) || EffectiveRuleAction(cfg.BlockMode, cfg.Engine.Rules[2]) != RuleActionDryRun {
		t.Fatalf("independent actions were not preserved: %#v", cfg.Engine.Rules)
	}
}

func TestLegacyModesKeepRulesWithoutActions(t *testing.T) {
	for _, mode := range []string{BlockModeDryRun, BlockModeNFTables} {
		document := `{"log_file":"/tmp/access.log","block_mode":"` + mode + `","engine":{"rules":[{"id":"r","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`
		cfg, err := decode(strings.NewReader(document), "test", "")
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if cfg.Engine.Rules[0].Action != "" {
			t.Fatalf("mode %s action = %q, want empty legacy action", mode, cfg.Engine.Rules[0].Action)
		}
	}
}

func TestDryRunAcceptsProspectiveRuleActions(t *testing.T) {
	document := `{"log_file":"/tmp/access.log","block_mode":"dry_run","engine":{"rules":[{"id":"captcha","action":"soft_block","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"},{"id":"firewall","action":"nftables","path_regex":"^/$","window":"1s","threshold":10,"group_by":"ip"}]}}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine.Rules[0].Action != RuleActionSoftBlock || cfg.Engine.Rules[1].Action != RuleActionNFTables {
		t.Fatalf("dry-run actions = %q, %q", cfg.Engine.Rules[0].Action, cfg.Engine.Rules[1].Action)
	}
}

func TestLegacyEnforcementModesOverrideProspectiveRuleActions(t *testing.T) {
	for _, mode := range []string{BlockModeNFTables, BlockModeSoftBlock} {
		document := `{"log_sources":{"web":{"path":"/tmp/web.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"block_mode":"` + mode + `","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"rules":[{"id":"r","action":"dry_run","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`
		cfg, err := decode(strings.NewReader(document), "test", "")
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if got := EffectiveRuleAction(cfg.BlockMode, cfg.Engine.Rules[0]); got != mode {
			t.Fatalf("mode %s effective action = %q", mode, got)
		}
		if cfg.Engine.Rules[0].Action != RuleActionDryRun {
			t.Fatalf("mode %s lost prospective action", mode)
		}
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
