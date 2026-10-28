package configservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/config"
)

const fixture = `{"log_sources":{"one":"/tmp/one.log","two":"/tmp/two.log"},"database_path":"/tmp/stats.sqlite","block_mode":"dry_run","block_duration":"1m","engine":{"ignore_ips":[],"rules":[{"id":"home","log_source":"one","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip","ignore_ips":["192.0.2.1"]},{"id":"login","log_source":"two","path_regex":"^/login$","window":"10s","threshold":3,"group_by":"ip"}]}}`

func testService(t *testing.T) *Service {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(fixture), 0640); err != nil {
		t.Fatal(err)
	}
	return &Service{Path: path}
}
func ips(values ...string) *[]string { return &values }
func regex(value string) *string     { return &value }
func action(value string) *string    { return &value }
func source(value string) *string    { return &value }
func TestWhitelistRoundTrip(t *testing.T) {
	s := testService(t)
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Save(Update{
		Revision:  doc.Revision,
		IgnoreIPs: ips("2001:db8::1", "192.0.2.0/24"),
		Rules: map[string]RuleUpdate{
			"home":  {IgnoreIPs: ips("198.51.100.7"), PathRegex: regex("^/landing$")},
			"login": {PathRegex: regex("^/signin$")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine.Rules[0].PathRegex != "^/landing$" || cfg.Engine.Rules[1].PathRegex != "^/signin$" || cfg.Engine.Rules[1].Threshold != 3 || cfg.LogSources[1].ID != "two" {
		t.Fatal("unrelated settings changed")
	}
	if len(cfg.Engine.IgnoreIPs) != 2 || cfg.Engine.Rules[0].IgnoreIPs[0] != "198.51.100.7/32" {
		t.Fatal(cfg.Engine)
	}
	if next.Revision == doc.Revision || next.WhitelistRevision == doc.WhitelistRevision {
		t.Fatal("revision not updated")
	}
	info, _ := os.Stat(s.Path)
	if info.Mode().Perm() != 0640 {
		t.Fatal("permissions changed")
	}
	if _, err := s.Save(Update{Revision: doc.Revision}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}
}

func TestRuleLogSourceRoundTrip(t *testing.T) {
	s := testService(t)
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Save(Update{Revision: doc.Revision, Rules: map[string]RuleUpdate{
		"home":  {LogSource: source("two")},
		"login": {LogSource: source("one")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if next.Rules[0].LogSource != "two" || next.Rules[1].LogSource != "one" {
		t.Fatalf("sources were not changed: %+v", next.Rules)
	}
	bad := "missing"
	if _, err := s.Save(Update{Revision: next.Revision, Rules: map[string]RuleUpdate{"home": {LogSource: &bad}}}); err == nil {
		t.Fatal("unknown source was accepted")
	}
}

func TestAddReadableLogSourceAndRule(t *testing.T) {
	s := testService(t)
	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, []byte(""), 0640); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Save(Update{
		Revision:   doc.Revision,
		AddSources: []Source{{ID: "ssh_auth", Path: logPath, Format: config.LogFormatSyslogSSHD}},
		AddRules:   []Rule{{ID: "ssh_auth-ssh-password", Enabled: true, Type: "rate", Action: config.RuleActionDryRun, LogSource: "ssh_auth", PathRegex: "^/ssh/failed$", Window: "60s", Threshold: 5, GroupBy: "ip", IgnoreIPs: []string{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Sources) != 3 || next.Sources[2].ID != "two" {
		t.Fatalf("sources = %+v", next.Sources)
	}
	cfg, err := config.Load(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LogSources) != 3 || cfg.LogSources[1].ID != "ssh_auth" || cfg.Engine.Rules[2].LogSource != "ssh_auth" {
		t.Fatalf("saved config = sources %+v rules %+v", cfg.LogSources, cfg.Engine.Rules)
	}
}

func TestAddLogSourceMigratesLegacyLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	legacyLog := filepath.Join(dir, "access.log")
	sshLog := filepath.Join(dir, "auth.log")
	for _, logPath := range []string{legacyLog, sshLog} {
		if err := os.WriteFile(logPath, nil, 0640); err != nil {
			t.Fatal(err)
		}
	}
	legacy := `{"log_file":` + fmt.Sprintf("%q", legacyLog) + `,"database_path":"/tmp/stats.sqlite","block_mode":"dry_run","engine":{"rules":[{"id":"homepage","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`
	if err := os.WriteFile(path, []byte(legacy), 0640); err != nil {
		t.Fatal(err)
	}
	s := &Service{Path: path}
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Save(Update{
		Revision:   doc.Revision,
		AddSources: []Source{{ID: "ssh_auth", Path: sshLog, Format: config.LogFormatSyslogSSHD}},
		AddRules:   []Rule{{ID: "ssh", Enabled: true, Type: "rate", Action: config.RuleActionDryRun, LogSource: "ssh_auth", PathRegex: "^/ssh/failed$", Window: "60s", Threshold: 5, GroupBy: "ip"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != "" || len(cfg.LogSources) != 2 || cfg.Engine.Rules[0].LogSource != "default" {
		t.Fatalf("legacy migration failed: %+v", cfg)
	}
}

func TestAddLogSourceRejectsUnreadablePathWithoutChangingConfig(t *testing.T) {
	s := testService(t)
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Save(Update{
		Revision:   doc.Revision,
		AddSources: []Source{{ID: "missing", Path: filepath.Join(t.TempDir(), "missing.log"), Format: config.LogFormatSyslogSSHD}},
		AddRules:   []Rule{{ID: "missing-rule", Enabled: true, Type: "rate", Action: config.RuleActionDryRun, LogSource: "missing", PathRegex: "^/ssh/failed$", Window: "60s", Threshold: 5, GroupBy: "ip"}},
	})
	if err == nil || !strings.Contains(err.Error(), "daemon cannot read") {
		t.Fatalf("error = %v", err)
	}
	after, readErr := s.Read()
	if readErr != nil || after.Revision != doc.Revision {
		t.Fatalf("failed source changed config: %+v %v", after, readErr)
	}
}

func TestSoftBlockFieldsSurviveGUIStyleSave(t *testing.T) {
	softFixture := `{"log_sources":{"web":{"path":"/tmp/web.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":"/tmp/stats.sqlite","block_mode":"soft_block","block_duration":"1m","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"ignore_ips":[],"rules":[{"id":"home","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"}]}}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(softFixture), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Service{Path: path}
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.SoftBlock) == 0 {
		t.Fatal("ConfigService omitted soft_block fields")
	}
	ttl := "45m"
	updated, err := s.Save(Update{Revision: doc.Revision, IgnoreIPs: ips("192.0.2.1"), CookieTTL: &ttl})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlockMode != config.BlockModeSoftBlock || cfg.SoftBlock.CookieTTL != 45*time.Minute || len(cfg.SoftBlock.Sites) != 1 || cfg.SoftBlock.Sites[0].Hosts[0] != "example.test" {
		t.Fatalf("soft config lost during save: %#v", cfg.SoftBlock)
	}
	if updated.BlockMode != config.BlockModeSoftBlock {
		t.Fatalf("saved mode = %q", updated.BlockMode)
	}
	bad := "999h"
	if _, err := s.Save(Update{Revision: updated.Revision, CookieTTL: &bad}); err == nil {
		t.Fatal("accepted invalid TTL")
	}
	after, err := s.Read()
	if err != nil || after.Revision != updated.Revision {
		t.Fatalf("invalid TTL changed config: %+v %v", after, err)
	}
}
func TestHybridRuleActionRoundTripAndNFTConfirmation(t *testing.T) {
	hybrid := `{"log_sources":{"web":{"path":"/tmp/web.log","format":"nginx_custom","log_format":"$remote_addr [$time_local] \"$request\" $status $antiddos_response_origin"}},"database_path":"/tmp/stats.sqlite","block_mode":"hybrid","block_duration":"1m","soft_block":{"cookie_ttl":"30m","sites":{"main":{"hosts":["example.test"],"log_sources":["web"]}}},"engine":{"rules":[{"id":"home","action":"soft_block","log_source":"web","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip"},{"id":"audit","action":"dry_run","log_source":"web","path_regex":"^/audit$","window":"5s","threshold":5,"group_by":"ip"}]}}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(hybrid), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Service{Path: path}
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(Update{Revision: doc.Revision, Rules: map[string]RuleUpdate{"audit": {Action: action(config.RuleActionNFTables)}}}); err == nil {
		t.Fatal("nftables rule action enabled without confirmation")
	}
	next, err := s.Save(Update{Revision: doc.Revision, ConfirmRealBlocks: true, Rules: map[string]RuleUpdate{"audit": {Action: action(config.RuleActionNFTables)}, "home": {Action: action(config.RuleActionDryRun)}}})
	if err != nil {
		t.Fatal(err)
	}
	if next.Rules[0].Action != config.RuleActionDryRun || next.Rules[1].Action != config.RuleActionNFTables {
		t.Fatalf("saved actions = %+v", next.Rules)
	}
}
func TestBlockModeChangeRequiresExplicitConfirmation(t *testing.T) {
	s := testService(t)
	doc, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	mode := config.BlockModeNFTables
	if _, err := s.Save(Update{Revision: doc.Revision, BlockMode: &mode}); err == nil {
		t.Fatal("real blocking enabled without explicit confirmation")
	}
	unchanged, err := s.Read()
	if err != nil || unchanged.BlockMode != config.BlockModeDryRun || unchanged.Revision != doc.Revision {
		t.Fatalf("unconfirmed change modified config: %#v, %v", unchanged, err)
	}
	if _, err := s.Save(Update{Revision: doc.Revision, BlockMode: &mode, ConfirmRealBlocks: true}); err != nil {
		t.Fatal(err)
	}
	updated, err := s.Read()
	if err != nil || updated.BlockMode != config.BlockModeNFTables {
		t.Fatalf("confirmed mode = %q, %v", updated.BlockMode, err)
	}
	doc = updated
	mode = "invalid"
	if _, err := s.Save(Update{Revision: doc.Revision, BlockMode: &mode}); err == nil {
		t.Fatal("invalid block mode accepted")
	}
}
func TestInvalidEditsNeverChangeFile(t *testing.T) {
	for _, u := range []Update{
		{IgnoreIPs: ips("bad")},
		{Rules: map[string]RuleUpdate{"unknown": {IgnoreIPs: ips()}}},
		{Rules: map[string]RuleUpdate{"home": {IgnoreIPs: ips("10.0.0.1/999")}}},
		{Rules: map[string]RuleUpdate{"home": {PathRegex: regex("(?=admin)")}}},
		{Rules: map[string]RuleUpdate{"home": {Action: action("unknown")}}},
	} {
		s := testService(t)
		d, _ := s.Read()
		u.Revision = d.Revision
		if _, err := s.Save(u); err == nil {
			t.Fatal("accepted invalid edit")
		}
		b, _ := os.ReadFile(s.Path)
		if string(b) != fixture {
			t.Fatal("invalid edit changed file")
		}
	}
}
func TestConcurrentEditors(t *testing.T) {
	s := testService(t)
	d, _ := s.Read()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := &Service{Path: s.Path}
			_, err := other.Save(Update{Revision: d.Revision, IgnoreIPs: ips("127.0.0.1")})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	n := 0
	for err := range results {
		if err == nil {
			n++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if n != 1 {
		t.Fatalf("successful saves %d", n)
	}
}
func TestSymlinkRefused(t *testing.T) {
	s := testService(t)
	link := filepath.Join(filepath.Dir(s.Path), "link")
	if err := os.Symlink(s.Path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Service{Path: link}).Read(); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestImplicitDefaultRule(t *testing.T) {
	s := testService(t)
	os.WriteFile(s.Path, []byte(`{"log_file":"/tmp/access.log"}`), 0600)
	d, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Save(Update{Revision: d.Revision, IgnoreIPs: ips("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(s.Path)
	if !strings.Contains(string(b), `"homepage"`) {
		t.Fatal("default rule lost")
	}
}
