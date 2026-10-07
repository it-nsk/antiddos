package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode"
)

const DefaultPath = "/etc/antiddos/config.json"
const DefaultDatabasePath = "/var/lib/antiddos/antiddos.sqlite"

const (
	defaultPathRegex = `^/$`
	defaultWindow    = 5 * time.Second
	defaultThreshold = 5
)

type Config struct {
	LogFile       string
	DatabasePath  string
	StartPosition string
	Engine        EngineConfig
}

type EngineConfig struct{ Rules []RuleConfig }

type RuleConfig struct {
	ID        string
	PathRegex string
	Window    time.Duration
	Threshold int
	GroupBy   string
}

type rawConfig struct {
	LogFile       string          `json:"log_file"`
	DatabasePath  string          `json:"database_path"`
	StartPosition string          `json:"start_position"`
	Engine        json.RawMessage `json:"engine"`
}

type rawEngineConfig struct {
	Rules []rawRuleConfig `json:"rules"`
}

type rawRuleConfig struct {
	ID        string  `json:"id"`
	PathRegex *string `json:"path_regex"`
	Window    *string `json:"window"`
	Threshold *int    `json:"threshold"`
	GroupBy   *string `json:"group_by"`
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
		raw.LogFile = logFile
	}
	if raw.LogFile == "" {
		return Config{}, fmt.Errorf("config %q: log_file is required", path)
	}
	if !filepath.IsAbs(raw.LogFile) {
		return Config{}, fmt.Errorf("config %q: log_file must be an absolute path", path)
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
	engineConfig, err := parseEngine(raw.Engine)
	if err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	return Config{
		LogFile: filepath.Clean(raw.LogFile), DatabasePath: filepath.Clean(raw.DatabasePath),
		StartPosition: raw.StartPosition, Engine: engineConfig,
	}, nil
}

func parseEngine(data json.RawMessage) (EngineConfig, error) {
	if len(data) == 0 {
		return defaultEngine(), nil
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
	result := EngineConfig{Rules: make([]RuleConfig, 0, len(raw.Rules))}
	ruleIDs := make(map[string]struct{}, len(raw.Rules))
	for index, rule := range raw.Rules {
		parsed, err := parseRule(rule)
		if err != nil {
			return EngineConfig{}, fmt.Errorf("engine.rules[%d]: %w", index, err)
		}
		if _, exists := ruleIDs[parsed.ID]; exists {
			return EngineConfig{}, fmt.Errorf("engine.rules[%d]: duplicate id %q", index, parsed.ID)
		}
		ruleIDs[parsed.ID] = struct{}{}
		result.Rules = append(result.Rules, parsed)
	}
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
	return RuleConfig{ID: raw.ID, PathRegex: *raw.PathRegex, Window: window, Threshold: *raw.Threshold, GroupBy: *raw.GroupBy}, nil
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
