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
	BlockModeDryRun   = "dry_run"
	BlockModeNFTables = "nftables"
)

const (
	LogFormatNginxCombined = "nginx_combined"
	LogFormatNginxCustom   = "nginx_custom"
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
	ID        string
	LogSource string
	PathRegex string
	Window    time.Duration
	Threshold int
	GroupBy   string
	IgnoreIPs []string
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
}

type rawEngineConfig struct {
	Rules     []rawRuleConfig `json:"rules"`
	IgnoreIPs []string        `json:"ignore_ips"`
}

type rawRuleConfig struct {
	ID        string   `json:"id"`
	LogSource *string  `json:"log_source"`
	PathRegex *string  `json:"path_regex"`
	Window    *string  `json:"window"`
	Threshold *int     `json:"threshold"`
	GroupBy   *string  `json:"group_by"`
	IgnoreIPs []string `json:"ignore_ips"`
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
	if blockMode != BlockModeDryRun && blockMode != BlockModeNFTables {
		return Config{}, fmt.Errorf("config %q: block_mode must be %q or %q", path, BlockModeDryRun, BlockModeNFTables)
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
		BlockTCPPorts: blockTCPPorts, Engine: engineConfig,
	}, nil
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
	window, err := time.ParseDuration(*raw.Window)
	if err != nil || window <= 0 {
		return RuleConfig{}, fmt.Errorf("window must be a positive duration")
	}
	if *raw.Threshold < 1 {
		return RuleConfig{}, fmt.Errorf("threshold must be at least 1")
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
	return RuleConfig{ID: raw.ID, LogSource: logSource, PathRegex: *raw.PathRegex, Window: window, Threshold: *raw.Threshold, GroupBy: *raw.GroupBy}, nil
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
