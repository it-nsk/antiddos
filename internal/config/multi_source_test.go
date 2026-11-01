package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestDecodeMultipleLogSourcesAndRuleWhitelists(t *testing.T) {
	document := `{
		"log_sources": {"web": "/var/log/nginx/site.log", "admin": "/var/log/nginx/admin.log"},
		"database_path": "/tmp/state.sqlite",
		"engine": {
			"ignore_ips": ["192.0.2.0/24"],
			"rules": [
				{"id":"site-home", "log_source":"web", "path_regex":"^/$", "window":"5s", "threshold":5, "group_by":"ip", "ignore_ips":["198.51.100.7", "2001:db8::/32"]},
				{"id":"admin-login", "log_source":"admin", "path_regex":"^/login$", "window":"10s", "threshold":3, "group_by":"ip"}
			]
		}
	}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LogSources) != 2 || cfg.LogSources[0].ID != "admin" || cfg.LogSources[1].ID != "web" {
		t.Fatalf("LogSources = %#v, want sorted admin and web", cfg.LogSources)
	}
	if cfg.LogFile != "" {
		t.Fatalf("LogFile = %q for multiple sources, want empty", cfg.LogFile)
	}
	if got := cfg.Engine.Rules[0]; got.LogSource != "web" || got.Window != 5*time.Second || len(got.IgnoreIPs) != 2 || got.IgnoreIPs[0] != "198.51.100.7/32" {
		t.Fatalf("first rule = %#v, whitelist was not normalized", got)
	}
	if got := cfg.Engine.Rules[1]; got.LogSource != "admin" || len(got.IgnoreIPs) != 0 {
		t.Fatalf("second rule = %#v", got)
	}
}

func TestDecodeLegacySingleLogRemainsCompatible(t *testing.T) {
	cfg, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log"}`), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != "/tmp/access.log" || len(cfg.LogSources) != 1 || cfg.LogSources[0].ID != "default" || cfg.Engine.Rules[0].LogSource != "default" {
		t.Fatalf("legacy config did not map to default source: %#v", cfg)
	}
}

func TestDecodeRuleTypes(t *testing.T) {
	cfg, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log","engine":{"rules":[{"id":"probe","type":"signature","unique_by":"path","path_regex":"^/\\.env$","window":"1s","threshold":1,"group_by":"ip"}]}}`), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Engine.Rules[0]; got.Type != "signature" || got.Threshold != 1 || got.Window != time.Second || got.UniqueBy != "" {
		t.Fatalf("signature rule = %#v", got)
	}
}

func TestDecodeCardinalityRule(t *testing.T) {
	cfg, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log","engine":{"rules":[{"id":"ports","type":"cardinality","unique_by":"destination_port","path_regex":"^/port/","window":"30s","threshold":8,"group_by":"ip"}]}}`), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Engine.Rules[0]; got.Type != "cardinality" || got.UniqueBy != "destination_port" || got.Threshold != 8 {
		t.Fatalf("cardinality rule = %#v", got)
	}
	if _, err := decode(strings.NewReader(`{"log_file":"/tmp/access.log","engine":{"rules":[{"id":"ports","type":"cardinality","path_regex":".*","window":"30s","threshold":8,"group_by":"ip"}]}}`), "test", ""); err == nil {
		t.Fatal("cardinality rule without unique_by was accepted")
	}
}

func TestSecurityExampleConfigDecodes(t *testing.T) {
	file, err := os.Open("../../deploy/config.security.example.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cfg, err := decode(file, "security example", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != BlockModeDryRun || len(cfg.LogSources) != 4 || len(cfg.Engine.Rules) != 9 {
		t.Fatalf("unexpected security example: mode=%s sources=%d rules=%d", cfg.BlockMode, len(cfg.LogSources), len(cfg.Engine.Rules))
	}
	if cfg.Engine.Rules[7].Enabled || cfg.Engine.Rules[7].Type != "cardinality" {
		t.Fatalf("port preset must ship disabled cardinality: %#v", cfg.Engine.Rules[7])
	}
}

func TestDecodeLogSourceFormatConfiguration(t *testing.T) {
	document := `{
		"log_sources": {
			"combined": "/var/log/nginx/access.log",
			"custom": {
				"path": "/var/log/nginx/custom.log",
				"format": "nginx_custom",
				"log_format": "log_format custom '$remote_addr [$time_iso8601] \"$request\" $status';"
			}
		},
		"database_path":"/tmp/state.sqlite",
		"engine":{"rules":[
			{"id":"combined-rule","log_source":"combined","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"},
			{"id":"custom-rule","log_source":"custom","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}
		]}
	}`
	cfg, err := decode(strings.NewReader(document), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogSources[0].Format != LogFormatNginxCombined || cfg.LogSources[1].Format != LogFormatNginxCustom {
		t.Fatalf("source formats = %#v", cfg.LogSources)
	}
	if cfg.LogSources[1].LogFormat == "" {
		t.Fatal("custom source lost its log_format directive")
	}
}

func TestDecodeRejectsInvalidOrAmbiguousLogSourceConfig(t *testing.T) {
	tests := []struct{ name, config, override string }{
		{"mixed source forms", `{"log_file":"/tmp/a.log","log_sources":{"web":"/tmp/b.log"}}`, ""},
		{"duplicate paths", `{"log_sources":{"web":"/tmp/a.log","other":"/tmp/./a.log"},"engine":{"rules":[{"id":"a","log_source":"web","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"},{"id":"b","log_source":"other","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, ""},
		{"missing source on multi config", `{"log_sources":{"a":"/tmp/a.log","b":"/tmp/b.log"},"engine":{"rules":[{"id":"r","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, ""},
		{"unknown source", `{"log_sources":{"a":"/tmp/a.log"},"engine":{"rules":[{"id":"r","log_source":"missing","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, ""},
		{"unused source", `{"log_sources":{"a":"/tmp/a.log","b":"/tmp/b.log"},"engine":{"rules":[{"id":"r","log_source":"a","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, ""},
		{"override on multi config", `{"log_sources":{"a":"/tmp/a.log"},"engine":{"rules":[{"id":"r","log_source":"a","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, "/tmp/override.log"},
		{"bad rule whitelist", `{"log_file":"/tmp/a.log","engine":{"rules":[{"id":"r","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip","ignore_ips":["example.com"]}]}}`, ""},
		{"missing custom log format", `{"log_sources":{"a":{"path":"/tmp/a.log","format":"nginx_custom"}},"engine":{"rules":[{"id":"r","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, ""},
		{"unknown format", `{"log_sources":{"a":{"path":"/tmp/a.log","format":"unsupported_format"}},"engine":{"rules":[{"id":"r","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decode(strings.NewReader(test.config), "test", test.override); err == nil {
				t.Fatal("decode unexpectedly succeeded")
			}
		})
	}
}
