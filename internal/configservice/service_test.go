package configservice

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
