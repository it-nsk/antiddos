// Package configservice edits rule path filters and allowlists while retaining
// every other field in the primary config.
package configservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/parser"
	"golang.org/x/sys/unix"
)

var ErrConflict = errors.New("config changed; reload it before saving")

type Service struct {
	Path string
	mu   sync.Mutex
}
type Rule struct {
	ID        string   `json:"id"`
	LogSource string   `json:"log_source"`
	PathRegex string   `json:"path_regex"`
	GroupBy   string   `json:"group_by"`
	Window    string   `json:"window"`
	Threshold int      `json:"threshold"`
	IgnoreIPs []string `json:"ignore_ips"`
}
type Document struct {
	Revision          string                   `json:"revision"`
	WhitelistRevision string                   `json:"whitelist_revision"`
	IgnoreIPs         []string                 `json:"ignore_ips"`
	Rules             []Rule                   `json:"rules"`
	LogSources        []config.LogSourceConfig `json:"-"`
	Sources           []Source                 `json:"sources"`
	BlockMode         string                   `json:"block_mode"`
}
type Source struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Format string `json:"format"`
}
type Update struct {
	Revision          string                `json:"revision"`
	IgnoreIPs         *[]string             `json:"ignore_ips"`
	Rules             map[string]RuleUpdate `json:"rules"`
	BlockMode         *string               `json:"block_mode,omitempty"`
	ConfirmRealBlocks bool                  `json:"confirm_real_blocks,omitempty"`
}
type RuleUpdate struct {
	IgnoreIPs *[]string `json:"ignore_ips"`
	PathRegex *string   `json:"path_regex"`
}

func revision(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (s *Service) read() ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(s.Path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("config must be a regular file, not a symlink")
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > 1<<20 {
		return nil, nil, fmt.Errorf("config exceeds 1 MiB")
	}
	return b, info, nil
}
func document(data []byte) (Document, error) {
	cfg, err := config.Decode(bytes.NewReader(data))
	if err != nil {
		return Document{}, err
	}
	d := Document{Revision: revision(data), WhitelistRevision: config.WhitelistRevision(cfg), IgnoreIPs: cfg.Engine.IgnoreIPs, Rules: []Rule{}, Sources: []Source{}, BlockMode: cfg.BlockMode}
	if d.IgnoreIPs == nil {
		d.IgnoreIPs = []string{}
	}
	for _, r := range cfg.Engine.Rules {
		ips := r.IgnoreIPs
		if ips == nil {
			ips = []string{}
		}
		d.Rules = append(d.Rules, Rule{r.ID, r.LogSource, r.PathRegex, r.GroupBy, r.Window.String(), r.Threshold, ips})
	}
	for _, v := range cfg.LogSources {
		d.Sources = append(d.Sources, Source{v.ID, v.Path, v.Format})
	}
	return d, nil
}
func (s *Service) Read() (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _, err := s.read()
	if err != nil {
		return Document{}, err
	}
	return document(b)
}
func (s *Service) Save(update Update) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Document{}, fmt.Errorf("config directory is not writable: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return Document{}, ErrConflict
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	data, info, err := s.read()
	if err != nil {
		return Document{}, err
	}
	if revision(data) != update.Revision {
		return Document{}, ErrConflict
	}
	if update.BlockMode != nil {
		if *update.BlockMode != config.BlockModeDryRun && *update.BlockMode != config.BlockModeNFTables {
			return Document{}, fmt.Errorf("block_mode must be %q or %q", config.BlockModeDryRun, config.BlockModeNFTables)
		}
		if *update.BlockMode == config.BlockModeNFTables && !update.ConfirmRealBlocks {
			return Document{}, fmt.Errorf("switching to real firewall blocking requires explicit confirmation")
		}
	}
	cfg, err := config.Decode(bytes.NewReader(data))
	if err != nil {
		return Document{}, err
	}
	if update.IgnoreIPs != nil && len(*update.IgnoreIPs) > 4096 {
		return Document{}, fmt.Errorf("at most 4096 global whitelist entries")
	}
	known := map[string]bool{}
	for _, r := range cfg.Engine.Rules {
		known[r.ID] = true
	}
	for id, ruleUpdate := range update.Rules {
		if !known[id] {
			return Document{}, fmt.Errorf("unknown rule %q", id)
		}
		if ruleUpdate.IgnoreIPs != nil && len(*ruleUpdate.IgnoreIPs) > 4096 {
			return Document{}, fmt.Errorf("at most 4096 whitelist entries per rule")
		}
		if ruleUpdate.PathRegex != nil && len(*ruleUpdate.PathRegex) > 4096 {
			return Document{}, fmt.Errorf("path_regex for rule %q exceeds 4096 bytes", id)
		}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, err
	}
	var engine map[string]json.RawMessage
	if len(raw["engine"]) > 0 {
		if err := json.Unmarshal(raw["engine"], &engine); err != nil {
			return Document{}, err
		}
	} else {
		engine = map[string]json.RawMessage{}
		var rules []map[string]any
		for _, r := range cfg.Engine.Rules {
			rules = append(rules, map[string]any{"id": r.ID, "log_source": r.LogSource, "path_regex": r.PathRegex, "window": r.Window.String(), "threshold": r.Threshold, "group_by": r.GroupBy})
		}
		engine["rules"], _ = json.Marshal(rules)
	}
	if update.IgnoreIPs != nil {
		ips := *update.IgnoreIPs
		if ips == nil {
			ips = []string{}
		}
		engine["ignore_ips"], _ = json.Marshal(ips)
	}
	if update.BlockMode != nil {
		raw["block_mode"], _ = json.Marshal(*update.BlockMode)
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(engine["rules"], &rules); err != nil {
		return Document{}, err
	}
	for _, r := range rules {
		var id string
		_ = json.Unmarshal(r["id"], &id)
		if ruleUpdate, ok := update.Rules[id]; ok {
			if ruleUpdate.IgnoreIPs != nil {
				ips := *ruleUpdate.IgnoreIPs
				if ips == nil {
					ips = []string{}
				}
				r["ignore_ips"], _ = json.Marshal(ips)
			}
			if ruleUpdate.PathRegex != nil {
				r["path_regex"], _ = json.Marshal(*ruleUpdate.PathRegex)
			}
		}
	}
	engine["rules"], _ = json.Marshal(rules)
	raw["engine"], _ = json.Marshal(engine)
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return Document{}, err
	}
	out = append(out, '\n')
	validated, err := config.Decode(bytes.NewReader(out))
	if err != nil {
		return Document{}, err
	}
	if _, err := blockpolicy.New(validated.BlockDuration); err != nil {
		return Document{}, err
	}
	for _, source := range validated.LogSources {
		if _, err := parser.New(source.Format, source.LogFormat); err != nil {
			return Document{}, err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".antiddos-config-*")
	if err != nil {
		return Document{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return Document{}, err
	}
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		// Preserve the group used by the daemon/web installation. The daemon owns
		// GUI-written replacements, so retaining a root uid is neither possible nor
		// required.
		if err := tmp.Chown(-1, int(stat.Gid)); err != nil {
			return Document{}, err
		}
	}
	if _, err := tmp.Write(out); err != nil {
		return Document{}, err
	}
	if err := tmp.Sync(); err != nil {
		return Document{}, err
	}
	if err := tmp.Close(); err != nil {
		return Document{}, err
	}
	// Catch external editor changes that happened while validation was running.
	latest, _, err := s.read()
	if err != nil {
		return Document{}, err
	}
	if revision(latest) != update.Revision {
		return Document{}, ErrConflict
	}
	if err := os.Rename(tmp.Name(), s.Path); err != nil {
		return Document{}, err
	}
	dir, err := os.Open(filepath.Dir(s.Path))
	if err != nil {
		return Document{}, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return Document{}, err
	}
	return document(out)
}
