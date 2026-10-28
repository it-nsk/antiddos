package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

const DefaultPath = "/etc/antiddos/config.json"
const DefaultDatabasePath = "/var/lib/antiddos/antiddos.sqlite"
const DefaultBlockMode = "dry_run"
const DefaultBlockDuration = 5 * time.Minute

const (
	BlockModeDryRun    = "dry_run"
	BlockModeNFTables  = "nftables"
	BlockModeSoftBlock = "soft_block"
	BlockModeHybrid    = "hybrid"
)

const (
	RuleActionDryRun    = "dry_run"
	RuleActionNFTables  = "nftables"
	RuleActionSoftBlock = "soft_block"
)

const (
	LogFormatNginxCombined = "nginx_combined"
	LogFormatNginxCustom   = "nginx_custom"
	LogFormatNginxError    = "nginx_error"
	LogFormatSyslogSSHD    = "syslog_sshd"
	LogFormatNetfilterLog  = "netfilter_log"
)

const (
	defaultPathRegex = `^/$`
	defaultWindow    = 5 * time.Second
	defaultThreshold = 5
)

type Config struct {
	LogFile       string // primary log path, retained for --log-file compatibility
	LogSources    []LogSourceConfig
	DatabasePath  string
	StartPosition string
	BlockMode     string
	BlockDuration time.Duration
	BlockTCPPorts []uint16
	Engine        EngineConfig
	SoftBlock     SoftBlockConfig
}

type SoftBlockConfig struct {
	CookieTTL time.Duration
	Sites     []SiteConfig
}

type SiteConfig struct {
	ID         string
	Hosts      []string
	LogSources []string
}

type LogSourceConfig struct {
	ID        string `json:"-"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	LogFormat string `json:"log_format"`
}

type EngineConfig struct {
	Rules     []RuleConfig
	IgnoreIPs []string
}

type RuleConfig struct {
	ID      string
	Enabled bool
	// ExplicitlyDisabled distinguishes enabled:false from zero-value structs
	// built by internal callers and older tests, where Enabled was absent.
	ExplicitlyDisabled bool
	Type               string
	Action             string
	LogSource          string
	PathRegex          string
	QueryRegex         string
	Statuses           []int
	UniqueBy           string
	Window             time.Duration
	Threshold          int
	GroupBy            string
	IgnoreIPs          []string
}

// EffectiveRuleAction returns the action the daemon applies for a rule in the
// configured mode. Dry-run deliberately has no effective action even when a
// prospective action is present in the rule.
func EffectiveRuleAction(mode string, rule RuleConfig) string {
	switch mode {
	case BlockModeNFTables:
		return RuleActionNFTables
	case BlockModeSoftBlock:
		return RuleActionSoftBlock
	case BlockModeHybrid:
		return rule.Action
	default:
		return ""
	}
}

func UsesSoftBlock(cfg Config) bool {
	for _, rule := range cfg.Engine.Rules {
		if EffectiveRuleAction(cfg.BlockMode, rule) == RuleActionSoftBlock {
			return true
		}
	}
	return false
}

func UsesNFTables(cfg Config) bool {
	for _, rule := range cfg.Engine.Rules {
		if EffectiveRuleAction(cfg.BlockMode, rule) == RuleActionNFTables {
			return true
		}
	}
	return false
}

type rawConfig struct {
	LogFile       string                     `json:"log_file"`
	LogSources    map[string]json.RawMessage `json:"log_sources"`
	DatabasePath  string                     `json:"database_path"`
	StartPosition string                     `json:"start_position"`
	BlockMode     string                     `json:"block_mode"`
	BlockDuration string                     `json:"block_duration"`
	BlockTCPPorts []int                      `json:"block_tcp_ports"`
	Engine        json.RawMessage            `json:"engine"`
	SoftBlock     rawSoftBlockConfig         `json:"soft_block"`
}

type rawSoftBlockConfig struct {
	CookieTTL string                   `json:"cookie_ttl"`
	Sites     map[string]rawSiteConfig `json:"sites"`
}

type rawSiteConfig struct {
	Hosts      []string `json:"hosts"`
	LogSources []string `json:"log_sources"`
}

type rawEngineConfig struct {
	Rules     []rawRuleConfig `json:"rules"`
	IgnoreIPs []string        `json:"ignore_ips"`
}

type rawRuleConfig struct {
	ID         string   `json:"id"`
	Enabled    *bool    `json:"enabled"`
	Type       string   `json:"type"`
	Action     string   `json:"action"`
	LogSource  *string  `json:"log_source"`
	PathRegex  *string  `json:"path_regex"`
	QueryRegex string   `json:"query_regex"`
	Statuses   []int    `json:"statuses"`
	UniqueBy   string   `json:"unique_by"`
	Window     *string  `json:"window"`
	Threshold  *int     `json:"threshold"`
	GroupBy    *string  `json:"group_by"`
	IgnoreIPs  []string `json:"ignore_ips"`
}

func Load(path string) (Config, error) { return LoadWithLogFile(path, "") }

func LoadWithLogFile(path, logFile string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()
	return decode(file, path, logFile)
}

func decode(input io.Reader, path, logFile string) (Config, error) {
	var raw rawConfig
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("unexpected data after the JSON object")
		}
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if logFile != "" {
		if len(raw.LogSources) != 0 {
			return Config{}, fmt.Errorf("config %q: --log-file cannot be used with log_sources; edit log_sources in the config", path)
		}
		raw.LogFile = logFile
	}
	logSources, err := parseLogSources(raw.LogFile, raw.LogSources)
	if err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	if raw.DatabasePath == "" {
		raw.DatabasePath = DefaultDatabasePath
	}
	if !filepath.IsAbs(raw.DatabasePath) {
		return Config{}, fmt.Errorf("config %q: database_path must be an absolute path", path)
	}
	if raw.StartPosition == "" {
		raw.StartPosition = "end"
	}
	if raw.StartPosition != "end" && raw.StartPosition != "beginning" {
		return Config{}, fmt.Errorf("config %q: start_position must be %q or %q", path, "end", "beginning")
	}
	engineConfig, err := parseEngine(raw.Engine, logSources)
	if err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	blockMode := raw.BlockMode
	if blockMode == "" {
		blockMode = DefaultBlockMode
	}
	if blockMode != BlockModeDryRun && blockMode != BlockModeNFTables && blockMode != BlockModeSoftBlock && blockMode != BlockModeHybrid {
		return Config{}, fmt.Errorf("config %q: unsupported block_mode %q", path, blockMode)
	}
	if err := validateRuleActions(blockMode, engineConfig); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	softBlock, err := parseSoftBlock(raw.SoftBlock, blockMode, logSources, engineConfig)
	if err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	blockDuration := DefaultBlockDuration
	if raw.BlockDuration != "" {
		blockDuration, err = time.ParseDuration(raw.BlockDuration)
		if err != nil {
			return Config{}, fmt.Errorf("config %q: block_duration: %w", path, err)
		}
	}
	blockTCPPorts := make([]uint16, 0, len(raw.BlockTCPPorts))
	seenPorts := make(map[int]struct{}, len(raw.BlockTCPPorts))
	for index, port := range raw.BlockTCPPorts {
		if port < 1 || port > 65535 {
			return Config{}, fmt.Errorf("config %q: block_tcp_ports[%d] must be between 1 and 65535", path, index)
		}
		if _, exists := seenPorts[port]; exists {
			return Config{}, fmt.Errorf("config %q: block_tcp_ports contains duplicate port %d", path, port)
		}
		seenPorts[port] = struct{}{}
		blockTCPPorts = append(blockTCPPorts, uint16(port))
	}
	primaryLog := ""
	if len(logSources) == 1 {
		primaryLog = logSources[0].Path
	}
	return Config{
		LogFile: primaryLog, LogSources: logSources, DatabasePath: filepath.Clean(raw.DatabasePath),
		StartPosition: raw.StartPosition, BlockMode: blockMode, BlockDuration: blockDuration,
		BlockTCPPorts: blockTCPPorts, Engine: engineConfig, SoftBlock: softBlock,
	}, nil
}

func parseSoftBlock(raw rawSoftBlockConfig, mode string, sources []LogSourceConfig, engine EngineConfig) (SoftBlockConfig, error) {
	softRules := make(map[string]bool)
	for _, rule := range engine.Rules {
		if mode == BlockModeSoftBlock || mode == BlockModeHybrid && rule.Action == RuleActionSoftBlock {
			softRules[rule.LogSource] = true
		}
	}
	if mode != BlockModeSoftBlock && mode != BlockModeHybrid || len(softRules) == 0 {
		return SoftBlockConfig{}, nil
	}
	ttl, err := time.ParseDuration(raw.CookieTTL)
	if err != nil || ttl < time.Minute || ttl > 24*time.Hour {
		return SoftBlockConfig{}, fmt.Errorf("soft_block.cookie_ttl must be between 1m and 24h")
	}
	if len(raw.Sites) == 0 || len(raw.Sites) > 32 {
		return SoftBlockConfig{}, fmt.Errorf("soft_block.sites must contain between 1 and 32 sites")
	}
	sourceByID := make(map[string]LogSourceConfig, len(sources))
	for _, source := range sources {
		sourceByID[source.ID] = source
	}
	assigned := make(map[string]string)
	hosts := make(map[string]string)
	ids := make([]string, 0, len(raw.Sites))
	for id := range raw.Sites {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := SoftBlockConfig{CookieTTL: ttl, Sites: make([]SiteConfig, 0, len(ids))}
	for _, id := range ids {
		if err := validateID(id); err != nil {
			return SoftBlockConfig{}, fmt.Errorf("soft_block.sites key %q: %w", id, err)
		}
		site := raw.Sites[id]
		if len(site.Hosts) == 0 || len(site.LogSources) == 0 {
			return SoftBlockConfig{}, fmt.Errorf("soft_block.sites[%q] requires hosts and log_sources", id)
		}
		seenHost := map[string]bool{}
		seenSource := map[string]bool{}
		for _, host := range site.Hosts {
			if !validSoftHost(host) {
				return SoftBlockConfig{}, fmt.Errorf("soft_block.sites[%q] host %q must be lowercase ASCII/punycode without scheme, path, or port", id, host)
			}
			if seenHost[host] {
				return SoftBlockConfig{}, fmt.Errorf("soft_block.sites[%q] repeats host %q", id, host)
			}
			seenHost[host] = true
			if other, exists := hosts[host]; exists {
				return SoftBlockConfig{}, fmt.Errorf("host %q is assigned to both sites %q and %q", host, other, id)
			}
			hosts[host] = id
		}
		for _, sourceID := range site.LogSources {
			source, ok := sourceByID[sourceID]
			if !ok {
				return SoftBlockConfig{}, fmt.Errorf("soft_block.sites[%q] references unknown log source %q", id, sourceID)
			}
			if seenSource[sourceID] {
				return SoftBlockConfig{}, fmt.Errorf("soft_block.sites[%q] repeats log source %q", id, sourceID)
			}
			seenSource[sourceID] = true
			if other, exists := assigned[sourceID]; exists {
				return SoftBlockConfig{}, fmt.Errorf("log source %q is assigned to both sites %q and %q", sourceID, other, id)
			}
			assigned[sourceID] = id
			if source.Format != LogFormatNginxCustom || !strings.Contains(source.LogFormat, "$antiddos_response_origin") {
				return SoftBlockConfig{}, fmt.Errorf("log source %q requires nginx_custom log_format with $antiddos_response_origin", sourceID)
			}
		}
		result.Sites = append(result.Sites, SiteConfig{ID: id, Hosts: append([]string(nil), site.Hosts...), LogSources: append([]string(nil), site.LogSources...)})
	}
	for sourceID := range softRules {
		if _, ok := assigned[sourceID]; !ok {
			return SoftBlockConfig{}, fmt.Errorf("log source %q is not assigned to a soft_block site", sourceID)
		}
	}
	for _, rule := range engine.Rules {
		if mode == BlockModeHybrid && rule.Action != RuleActionSoftBlock {
			continue
		}
		if _, ok := assigned[rule.LogSource]; !ok {
			return SoftBlockConfig{}, fmt.Errorf("rule %q uses log source %q not assigned to a soft_block site", rule.ID, rule.LogSource)
		}
	}
	return result, nil
}

func validSoftHost(host string) bool {
	if host == "" || strings.ToLower(host) != host || strings.ContainsAny(host, ":/%") || strings.TrimSpace(host) != host {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsValid() {
		return false
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func parseLogSources(single string, named map[string]json.RawMessage) ([]LogSourceConfig, error) {
	if single != "" && len(named) != 0 {
		return nil, fmt.Errorf("log_file and log_sources cannot be used together")
	}
	if single != "" {
		if !filepath.IsAbs(single) {
			return nil, fmt.Errorf("log_file must be an absolute path")
		}
		return []LogSourceConfig{{ID: "default", Path: filepath.Clean(single), Format: LogFormatNginxCombined}}, nil
	}
	if len(named) == 0 {
		return nil, fmt.Errorf("log_file or log_sources is required")
	}
	result := make([]LogSourceConfig, 0, len(named))
	seenPaths := make(map[string]string, len(named))
	for id, rawSource := range named {
		if err := validateID(id); err != nil {
			return nil, fmt.Errorf("log_sources key %q: %w", id, err)
		}
		var source LogSourceConfig
		if err := json.Unmarshal(rawSource, &source.Path); err != nil {
			decoder := json.NewDecoder(bytes.NewReader(rawSource))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&source); err != nil {
				return nil, fmt.Errorf("log_sources[%q]: expected a path string or object with path, format, and log_format", id)
			}
		}
		path := source.Path
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("log_sources[%q] must be an absolute path", id)
		}
		if source.Format == "" {
			source.Format = LogFormatNginxCombined
		}
		switch source.Format {
		case LogFormatNginxCombined:
			if source.LogFormat != "" {
				return nil, fmt.Errorf("log_sources[%q]: log_format is only valid with format %q", id, LogFormatNginxCustom)
			}
		case LogFormatNginxCustom:
			if strings.TrimSpace(source.LogFormat) == "" {
				return nil, fmt.Errorf("log_sources[%q]: log_format is required with format %q", id, LogFormatNginxCustom)
			}
		case LogFormatNginxError, LogFormatSyslogSSHD, LogFormatNetfilterLog:
			if source.LogFormat != "" {
				return nil, fmt.Errorf("log_sources[%q]: log_format is not valid with format %q", id, source.Format)
			}
		default:
			return nil, fmt.Errorf("log_sources[%q]: unsupported format %q", id, source.Format)
		}
		path = filepath.Clean(path)
		if other, exists := seenPaths[path]; exists {
			return nil, fmt.Errorf("log_sources[%q] and log_sources[%q] use the same path %q", other, id, path)
		}
		seenPaths[path] = id
		source.ID = id
		source.Path = path
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func parseEngine(data json.RawMessage, sources []LogSourceConfig) (EngineConfig, error) {
	if len(data) == 0 {
		if len(sources) != 1 {
			return EngineConfig{}, fmt.Errorf("engine.rules must be configured when multiple log_sources are configured")
		}
		defaults := defaultEngine()
		defaults.Rules[0].LogSource = sources[0].ID
		return defaults, nil
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return EngineConfig{}, fmt.Errorf("engine must be an object, not null")
	}
	var raw rawEngineConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return EngineConfig{}, fmt.Errorf("decode engine: %w", err)
	}
	if len(raw.Rules) == 0 {
		return EngineConfig{}, fmt.Errorf("engine.rules must contain at least one rule")
	}
	result := EngineConfig{Rules: make([]RuleConfig, 0, len(raw.Rules)), IgnoreIPs: make([]string, 0, len(raw.IgnoreIPs))}
	ignoreIPs, err := parseIgnoreIPs(raw.IgnoreIPs, "engine.ignore_ips")
	if err != nil {
		return EngineConfig{}, err
	}
	result.IgnoreIPs = ignoreIPs
	sourceIDs := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		sourceIDs[source.ID] = struct{}{}
	}
	ruleIDs := make(map[string]struct{}, len(raw.Rules))
	usedSources := make(map[string]struct{}, len(sources))
	for index, rule := range raw.Rules {
		parsed, err := parseRule(rule)
		if err != nil {
			return EngineConfig{}, fmt.Errorf("engine.rules[%d]: %w", index, err)
		}
		if parsed.LogSource == "" {
			if len(sources) != 1 {
				return EngineConfig{}, fmt.Errorf("engine.rules[%d]: log_source is required when multiple log_sources are configured", index)
			}
			parsed.LogSource = sources[0].ID
		}
		if _, exists := sourceIDs[parsed.LogSource]; !exists {
			return EngineConfig{}, fmt.Errorf("engine.rules[%d]: unknown log_source %q", index, parsed.LogSource)
		}
		if _, exists := ruleIDs[parsed.ID]; exists {
			return EngineConfig{}, fmt.Errorf("engine.rules[%d]: duplicate id %q", index, parsed.ID)
		}
		ruleIDs[parsed.ID] = struct{}{}
		usedSources[parsed.LogSource] = struct{}{}
		parsed.IgnoreIPs, err = parseIgnoreIPs(rule.IgnoreIPs, fmt.Sprintf("engine.rules[%d].ignore_ips", index))
		if err != nil {
			return EngineConfig{}, err
		}
		result.Rules = append(result.Rules, parsed)
	}
	for _, source := range sources {
		if _, used := usedSources[source.ID]; !used {
			return EngineConfig{}, fmt.Errorf("log_sources[%q] is not referenced by any rule", source.ID)
		}
	}
	return result, nil
}

func parseIgnoreIPs(values []string, field string) ([]string, error) {
	result := make([]string, 0, len(values))
	for index, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			if address, addressErr := netip.ParseAddr(value); addressErr == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			} else {
				return nil, fmt.Errorf("%s[%d]: invalid IP or CIDR %q", field, index, value)
			}
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("%s[%d]: invalid IPv4-mapped prefix %q", field, index, value)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		result = append(result, prefix.String())
	}
	sort.Strings(result)
	return result, nil
}

func parseRule(raw rawRuleConfig) (RuleConfig, error) {
	if err := validateID(raw.ID); err != nil {
		return RuleConfig{}, fmt.Errorf("id: %w", err)
	}
	if raw.PathRegex == nil || raw.Window == nil || raw.Threshold == nil || raw.GroupBy == nil {
		return RuleConfig{}, fmt.Errorf("path_regex, window, threshold, and group_by are required")
	}
	if _, err := regexp.Compile(*raw.PathRegex); err != nil {
		return RuleConfig{}, fmt.Errorf("path_regex: %w", err)
	}
	if raw.QueryRegex != "" {
		if _, err := regexp.Compile(raw.QueryRegex); err != nil {
			return RuleConfig{}, fmt.Errorf("query_regex: %w", err)
		}
	}
	for _, status := range raw.Statuses {
		if status < 100 || status > 999 {
			return RuleConfig{}, fmt.Errorf("invalid HTTP status %d", status)
		}
	}
	window, err := time.ParseDuration(*raw.Window)
	if err != nil || window <= 0 {
		return RuleConfig{}, fmt.Errorf("window must be a positive duration")
	}
	if *raw.Threshold < 1 {
		return RuleConfig{}, fmt.Errorf("threshold must be at least 1")
	}
	ruleType := strings.TrimSpace(raw.Type)
	if ruleType == "" {
		ruleType = "rate"
	}
	if ruleType != "rate" && ruleType != "signature" && ruleType != "cardinality" {
		return RuleConfig{}, fmt.Errorf("unsupported rule type %q", ruleType)
	}
	if ruleType == "signature" && (*raw.Threshold != 1 || window != time.Second) {
		return RuleConfig{}, fmt.Errorf("signature rules require threshold=1 and window=1s")
	}
	if ruleType == "cardinality" && raw.UniqueBy != "path" && raw.UniqueBy != "destination_port" {
		return RuleConfig{}, fmt.Errorf("cardinality rules require unique_by path or destination_port")
	}
	if !supportedGroupField(*raw.GroupBy) {
		return RuleConfig{}, fmt.Errorf("unsupported group_by %q", *raw.GroupBy)
	}
	logSource := ""
	if raw.LogSource != nil {
		logSource = strings.TrimSpace(*raw.LogSource)
		if err := validateID(logSource); err != nil {
			return RuleConfig{}, fmt.Errorf("log_source: %w", err)
		}
	}
	enabled := true
	if raw.Enabled != nil {
		enabled = *raw.Enabled
	}
	return RuleConfig{ID: raw.ID, Enabled: enabled, ExplicitlyDisabled: raw.Enabled != nil && !*raw.Enabled, Type: ruleType, Action: strings.TrimSpace(raw.Action), LogSource: logSource, PathRegex: *raw.PathRegex, QueryRegex: raw.QueryRegex, Statuses: raw.Statuses, UniqueBy: raw.UniqueBy, Window: window, Threshold: *raw.Threshold, GroupBy: *raw.GroupBy}, nil
}

func validateRuleActions(mode string, engine EngineConfig) error {
	for index, rule := range engine.Rules {
		action := rule.Action
		if mode == BlockModeHybrid && action == "" {
			return fmt.Errorf("engine.rules[%d]: action is required in hybrid mode", index)
		}
		if action != "" && action != RuleActionDryRun && action != RuleActionSoftBlock && action != RuleActionNFTables {
			return fmt.Errorf("engine.rules[%d]: unsupported action %q", index, action)
		}
		effective := EffectiveRuleAction(mode, rule)
		if (effective == RuleActionSoftBlock || effective == RuleActionNFTables) && rule.GroupBy != "ip" {
			return fmt.Errorf("engine.rules[%d]: effective action %q requires group_by %q", index, effective, "ip")
		}
	}
	return nil
}

func defaultEngine() EngineConfig {
	return EngineConfig{Rules: []RuleConfig{{
		ID: "homepage", PathRegex: defaultPathRegex, Window: defaultWindow,
		Threshold: defaultThreshold, GroupBy: "ip",
	}}}
}

func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("must not be empty")
	}
	for _, char := range id {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return fmt.Errorf("%q must not contain whitespace or control characters", id)
		}
	}
	return nil
}

func supportedGroupField(field string) bool {
	switch field {
	case "ip", "user_agent", "method", "path", "status":
		return true
	default:
		return false
	}
}
