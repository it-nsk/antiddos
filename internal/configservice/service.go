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
	"strings"
	"sync"
	"time"

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
	ID         string   `json:"id"`
	Enabled    bool     `json:"enabled"`
	Type       string   `json:"type,omitempty"`
	Action     string   `json:"action,omitempty"`
	LogSource  string   `json:"log_source"`
	PathRegex  string   `json:"path_regex"`
	QueryRegex string   `json:"query_regex,omitempty"`
	Statuses   []int    `json:"statuses,omitempty"`
	UniqueBy   string   `json:"unique_by,omitempty"`
	GroupBy    string   `json:"group_by"`
	Window     string   `json:"window"`
	Threshold  int      `json:"threshold"`
	IgnoreIPs  []string `json:"ignore_ips"`
}
type Document struct {
	Revision          string                   `json:"revision"`
	WhitelistRevision string                   `json:"whitelist_revision"`
	IgnoreIPs         []string                 `json:"ignore_ips"`
	Rules             []Rule                   `json:"rules"`
	LogSources        []config.LogSourceConfig `json:"-"`
	Sources           []Source                 `json:"sources"`
	BlockMode         string                   `json:"block_mode"`
	SoftBlock         json.RawMessage          `json:"soft_block,omitempty"`
}
type Source struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	LogFormat string `json:"log_format,omitempty"`
}
type Update struct {
	Revision          string                `json:"revision"`
	IgnoreIPs         *[]string             `json:"ignore_ips"`
	Rules             map[string]RuleUpdate `json:"rules"`
	BlockMode         *string               `json:"block_mode,omitempty"`
	CookieTTL         *string               `json:"cookie_ttl,omitempty"`
	ConfirmRealBlocks bool                  `json:"confirm_real_blocks,omitempty"`
	AddRules          []Rule                `json:"add_rules,omitempty"`
	DeleteRules       []string              `json:"delete_rules,omitempty"`
	AddSources        []Source              `json:"add_sources,omitempty"`
}
type RuleUpdate struct {
	Enabled    *bool     `json:"enabled,omitempty"`
	LogSource  *string   `json:"log_source,omitempty"`
	IgnoreIPs  *[]string `json:"ignore_ips"`
	PathRegex  *string   `json:"path_regex"`
	QueryRegex *string   `json:"query_regex,omitempty"`
	Statuses   *[]int    `json:"statuses,omitempty"`
	UniqueBy   *string   `json:"unique_by,omitempty"`
	Action     *string   `json:"action,omitempty"`
	Window     *string   `json:"window,omitempty"`
	Threshold  *int      `json:"threshold,omitempty"`
	GroupBy    *string   `json:"group_by,omitempty"`
	Type       *string   `json:"type,omitempty"`
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, err
	}
	d.SoftBlock = raw["soft_block"]
	if d.IgnoreIPs == nil {
		d.IgnoreIPs = []string{}
	}
	for _, r := range cfg.Engine.Rules {
		ips := r.IgnoreIPs
		if ips == nil {
			ips = []string{}
		}
		d.Rules = append(d.Rules, Rule{ID: r.ID, Enabled: r.Enabled, Type: r.Type, Action: r.Action, LogSource: r.LogSource, PathRegex: r.PathRegex, QueryRegex: r.QueryRegex, Statuses: r.Statuses, UniqueBy: r.UniqueBy, GroupBy: r.GroupBy, Window: r.Window.String(), Threshold: r.Threshold, IgnoreIPs: ips})
	}
	for _, v := range cfg.LogSources {
		d.Sources = append(d.Sources, Source{ID: v.ID, Path: v.Path, Format: v.Format, LogFormat: v.LogFormat})
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
		if *update.BlockMode != config.BlockModeDryRun && *update.BlockMode != config.BlockModeNFTables && *update.BlockMode != config.BlockModeSoftBlock && *update.BlockMode != config.BlockModeHybrid {
			return Document{}, fmt.Errorf("unsupported block_mode %q", *update.BlockMode)
		}
		if (*update.BlockMode == config.BlockModeNFTables || *update.BlockMode == config.BlockModeHybrid) && !update.ConfirmRealBlocks {
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
	knownSources := map[string]bool{}
	for _, source := range cfg.LogSources {
		knownSources[source.ID] = true
	}
	for _, source := range update.AddSources {
		knownSources[source.ID] = true
	}
	for id, ruleUpdate := range update.Rules {
		if !known[id] {
			return Document{}, fmt.Errorf("unknown rule %q", id)
		}
		if ruleUpdate.IgnoreIPs != nil && len(*ruleUpdate.IgnoreIPs) > 4096 {
			return Document{}, fmt.Errorf("at most 4096 whitelist entries per rule")
		}
		if ruleUpdate.LogSource != nil && !knownSources[*ruleUpdate.LogSource] {
			return Document{}, fmt.Errorf("unknown log source %q for rule %q", *ruleUpdate.LogSource, id)
		}
		if ruleUpdate.PathRegex != nil && len(*ruleUpdate.PathRegex) > 4096 {
			return Document{}, fmt.Errorf("path_regex for rule %q exceeds 4096 bytes", id)
		}
		if ruleUpdate.Window != nil {
			if _, err := time.ParseDuration(*ruleUpdate.Window); err != nil {
				return Document{}, fmt.Errorf("invalid window for rule %q: %w", id, err)
			}
		}
		if ruleUpdate.Threshold != nil && *ruleUpdate.Threshold < 1 {
			return Document{}, fmt.Errorf("threshold for rule %q must be at least 1", id)
		}
		if ruleUpdate.GroupBy != nil && *ruleUpdate.GroupBy != "ip" && *ruleUpdate.GroupBy != "path" {
			return Document{}, fmt.Errorf("unsupported group_by %q for rule %q", *ruleUpdate.GroupBy, id)
		}
		if ruleUpdate.Action != nil {
			action := *ruleUpdate.Action
			if action != "" && action != config.RuleActionDryRun && action != config.RuleActionSoftBlock && action != config.RuleActionNFTables {
				return Document{}, fmt.Errorf("unsupported action %q for rule %q", action, id)
			}
			for _, current := range cfg.Engine.Rules {
				if current.ID == id && action == config.RuleActionNFTables && current.Action != action && !update.ConfirmRealBlocks {
					return Document{}, fmt.Errorf("switching a rule to real firewall blocking requires explicit confirmation")
				}
			}
		}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, err
	}
	migratedLegacySource := false
	if len(update.AddSources) > 0 {
		if os.Getenv("ANTIDDOS_LOG_FILE") != "" {
			return Document{}, fmt.Errorf("cannot add named log sources while ANTIDDOS_LOG_FILE override is set; remove it from /etc/default/antiddos and restart the daemon")
		}
		var sources map[string]json.RawMessage
		if len(raw["log_sources"]) > 0 {
			if err := json.Unmarshal(raw["log_sources"], &sources); err != nil {
				return Document{}, err
			}
		}
		if sources == nil {
			sources = map[string]json.RawMessage{}
		}
		if len(raw["log_file"]) > 0 {
			var legacyPath string
			if err := json.Unmarshal(raw["log_file"], &legacyPath); err != nil || legacyPath == "" {
				return Document{}, fmt.Errorf("cannot migrate legacy log_file to named sources")
			}
			legacy, _ := json.Marshal(map[string]string{"path": legacyPath, "format": config.LogFormatNginxCombined})
			sources["default"] = legacy
			delete(raw, "log_file")
			migratedLegacySource = true
		}
		for _, added := range update.AddSources {
			if _, exists := sources[added.ID]; exists {
				return Document{}, fmt.Errorf("log source %q already exists", added.ID)
			}
			if added.ID == "" || len(added.ID) > 64 {
				return Document{}, fmt.Errorf("log source id must contain 1 to 64 characters")
			}
			if !filepath.IsAbs(added.Path) {
				return Document{}, fmt.Errorf("log source %q path must be absolute", added.ID)
			}
			if len(added.Path) > 4096 || strings.ContainsAny(added.Path, "\r\n\x00") {
				return Document{}, fmt.Errorf("log source %q path is invalid", added.ID)
			}
			file, err := os.Open(filepath.Clean(added.Path))
			if err != nil {
				return Document{}, fmt.Errorf("daemon cannot read log source %q at %q: %w", added.ID, added.Path, err)
			}
			info, statErr := file.Stat()
			_ = file.Close()
			if statErr != nil {
				return Document{}, fmt.Errorf("inspect log source %q: %w", added.ID, statErr)
			}
			if !info.Mode().IsRegular() {
				return Document{}, fmt.Errorf("log source %q path must resolve to a regular file", added.ID)
			}
			value := map[string]string{"path": filepath.Clean(added.Path), "format": added.Format}
			if added.LogFormat != "" {
				value["log_format"] = added.LogFormat
			}
			sources[added.ID], _ = json.Marshal(value)
		}
		raw["log_sources"], _ = json.Marshal(sources)
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
			rule := map[string]any{"id": r.ID, "enabled": r.Enabled, "type": r.Type, "log_source": r.LogSource, "path_regex": r.PathRegex, "query_regex": r.QueryRegex, "statuses": r.Statuses, "unique_by": r.UniqueBy, "window": r.Window.String(), "threshold": r.Threshold, "group_by": r.GroupBy}
			if r.Action != "" {
				rule["action"] = r.Action
			}
			rules = append(rules, rule)
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
	if update.CookieTTL != nil {
		var soft map[string]json.RawMessage
		if len(raw["soft_block"]) == 0 || json.Unmarshal(raw["soft_block"], &soft) != nil || soft == nil {
			return Document{}, fmt.Errorf("soft_block must be configured before setting cookie TTL")
		}
		soft["cookie_ttl"], _ = json.Marshal(*update.CookieTTL)
		raw["soft_block"], _ = json.Marshal(soft)
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(engine["rules"], &rules); err != nil {
		return Document{}, err
	}
	if migratedLegacySource {
		for _, rule := range rules {
			if len(rule["log_source"]) == 0 {
				rule["log_source"], _ = json.Marshal("default")
			}
		}
	}
	deleteSet := map[string]bool{}
	for _, id := range update.DeleteRules {
		if !known[id] {
			return Document{}, fmt.Errorf("unknown rule %q", id)
		}
		deleteSet[id] = true
	}
	if len(rules)-len(deleteSet)+len(update.AddRules) < 1 {
		return Document{}, fmt.Errorf("at least one rule must remain")
	}
	for _, added := range update.AddRules {
		if added.ID == "" || known[added.ID] {
			return Document{}, fmt.Errorf("rule id %q is empty or already exists", added.ID)
		}
		if added.LogSource == "" || added.PathRegex == "" || added.Window == "" || added.Threshold < 1 || added.GroupBy == "" {
			return Document{}, fmt.Errorf("new rule %q is incomplete", added.ID)
		}
		if _, err := time.ParseDuration(added.Window); err != nil {
			return Document{}, fmt.Errorf("invalid window for rule %q: %w", added.ID, err)
		}
		if added.GroupBy != "ip" && added.GroupBy != "path" {
			return Document{}, fmt.Errorf("unsupported group_by %q", added.GroupBy)
		}
		if added.Action != "" && added.Action != config.RuleActionDryRun && added.Action != config.RuleActionSoftBlock && added.Action != config.RuleActionNFTables {
			return Document{}, fmt.Errorf("unsupported action %q", added.Action)
		}
		if added.Type == "" {
			added.Type = "rate"
		}
		if added.Type != "rate" && added.Type != "signature" && added.Type != "cardinality" {
			return Document{}, fmt.Errorf("unsupported rule type %q", added.Type)
		}
		if added.Type == "signature" && (added.Window != "1s" || added.Threshold != 1) {
			return Document{}, fmt.Errorf("signature rule %q requires window 1s and threshold 1", added.ID)
		}
		m := map[string]any{"id": added.ID, "enabled": added.Enabled, "type": added.Type, "log_source": added.LogSource, "path_regex": added.PathRegex, "query_regex": added.QueryRegex, "statuses": added.Statuses, "unique_by": added.UniqueBy, "window": added.Window, "threshold": added.Threshold, "group_by": added.GroupBy, "ignore_ips": added.IgnoreIPs}
		if added.Action != "" {
			m["action"] = added.Action
		}
		b, _ := json.Marshal(m)
		var rm map[string]json.RawMessage
		_ = json.Unmarshal(b, &rm)
		rules = append(rules, rm)
		known[added.ID] = true
	}
	filtered := rules[:0]
	for _, r := range rules {
		var id string
		_ = json.Unmarshal(r["id"], &id)
		if !deleteSet[id] {
			filtered = append(filtered, r)
		}
	}
	rules = filtered
	for _, r := range rules {
		var id string
		_ = json.Unmarshal(r["id"], &id)
		if ruleUpdate, ok := update.Rules[id]; ok {
			if ruleUpdate.Enabled != nil {
				r["enabled"], _ = json.Marshal(*ruleUpdate.Enabled)
			}
			if ruleUpdate.LogSource != nil {
				r["log_source"], _ = json.Marshal(*ruleUpdate.LogSource)
			}
			if ruleUpdate.Action != nil {
				if *ruleUpdate.Action == "" {
					delete(r, "action")
				} else {
					r["action"], _ = json.Marshal(*ruleUpdate.Action)
				}
			}
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
			if ruleUpdate.QueryRegex != nil {
				r["query_regex"], _ = json.Marshal(*ruleUpdate.QueryRegex)
			}
			if ruleUpdate.Statuses != nil {
				r["statuses"], _ = json.Marshal(*ruleUpdate.Statuses)
			}
			if ruleUpdate.UniqueBy != nil {
				r["unique_by"], _ = json.Marshal(*ruleUpdate.UniqueBy)
			}
			if ruleUpdate.Window != nil {
				r["window"], _ = json.Marshal(*ruleUpdate.Window)
			}
			if ruleUpdate.Threshold != nil {
				r["threshold"], _ = json.Marshal(*ruleUpdate.Threshold)
			}
			if ruleUpdate.GroupBy != nil {
				r["group_by"], _ = json.Marshal(*ruleUpdate.GroupBy)
			}
			if ruleUpdate.Type != nil {
				r["type"], _ = json.Marshal(*ruleUpdate.Type)
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
		softSource := false
		for _, site := range validated.SoftBlock.Sites {
			for _, sourceID := range site.LogSources {
				if sourceID == source.ID {
					softSource = true
				}
			}
		}
		if _, err := parser.NewWithOriginRequirement(source.Format, source.LogFormat, config.UsesSoftBlock(validated) && softSource); err != nil {
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
