package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const DefaultPath = "/etc/antiddos/config.json"
const DefaultDatabasePath = "/var/lib/antiddos/antiddos.sqlite"

const (
	defaultWindow            = 5 * time.Second
	defaultThreshold         = 5
	defaultSuspicious        = 3
	defaultLiveEventLateness = 30 * time.Second
)

type Config struct {
	LogFile       string
	DatabasePath  string
	StartPosition string
	Engine        EngineConfig
}

type EngineConfig struct {
	LiveEventLateness time.Duration
	Rules             []RuleConfig
}

type RuleConfig struct {
	ID                  string
	Window              time.Duration
	Threshold           int
	SuspiciousThreshold int
	Groupings           []GroupingConfig
}

type GroupingConfig struct {
	ID     string
	Fields []string
}

type rawConfig struct {
	LogFile       string          `json:"log_file"`
	DatabasePath  string          `json:"database_path"`
	StartPosition string          `json:"start_position"`
	Engine        json.RawMessage `json:"engine"`
}

type rawEngineConfig struct {
	LiveEventLateness *string         `json:"live_event_lateness"`
	Rules             []rawRuleConfig `json:"rules"`
}

type rawRuleConfig struct {
	ID                  string              `json:"id"`
	Window              *string             `json:"window"`
	Threshold           *int                `json:"threshold"`
	SuspiciousThreshold *int                `json:"suspicious_threshold"`
	Groupings           []rawGroupingConfig `json:"groupings"`
}

type rawGroupingConfig struct {
	ID     string   `json:"id"`
	Fields []string `json:"fields"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	var raw rawConfig
	decoder := json.NewDecoder(file)
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
		LogFile:       filepath.Clean(raw.LogFile),
		DatabasePath:  filepath.Clean(raw.DatabasePath),
		StartPosition: raw.StartPosition,
		Engine:        engineConfig,
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

	liveEventLateness := defaultLiveEventLateness
	if raw.LiveEventLateness != nil {
		parsed, err := time.ParseDuration(*raw.LiveEventLateness)
		if err != nil || parsed < 0 {
			return EngineConfig{}, fmt.Errorf("engine.live_event_lateness must be a non-negative duration")
		}
		liveEventLateness = parsed
	}
	result := EngineConfig{
		LiveEventLateness: liveEventLateness,
		Rules:             make([]RuleConfig, 0, len(raw.Rules)),
	}
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
	if raw.Window == nil || raw.Threshold == nil || raw.SuspiciousThreshold == nil {
		return RuleConfig{}, fmt.Errorf("window, threshold, and suspicious_threshold are required")
	}
	window, err := time.ParseDuration(*raw.Window)
	if err != nil || window <= 0 {
		return RuleConfig{}, fmt.Errorf("window must be a positive duration")
	}
	if *raw.Threshold < 1 {
		return RuleConfig{}, fmt.Errorf("threshold must be at least 1")
	}
	if *raw.SuspiciousThreshold < 0 || (*raw.SuspiciousThreshold > 0 && *raw.SuspiciousThreshold >= *raw.Threshold) {
		return RuleConfig{}, fmt.Errorf("suspicious_threshold must be 0 or less than threshold")
	}
	if len(raw.Groupings) == 0 {
		return RuleConfig{}, fmt.Errorf("groupings must contain at least one grouping")
	}

	result := RuleConfig{
		ID:                  raw.ID,
		Window:              window,
		Threshold:           *raw.Threshold,
		SuspiciousThreshold: *raw.SuspiciousThreshold,
		Groupings:           make([]GroupingConfig, 0, len(raw.Groupings)),
	}
	groupingIDs := make(map[string]struct{}, len(raw.Groupings))
	definitions := make(map[string]struct{}, len(raw.Groupings))
	for index, grouping := range raw.Groupings {
		if err := validateID(grouping.ID); err != nil {
			return RuleConfig{}, fmt.Errorf("groupings[%d].id: %w", index, err)
		}
		if _, exists := groupingIDs[grouping.ID]; exists {
			return RuleConfig{}, fmt.Errorf("groupings[%d]: duplicate id %q", index, grouping.ID)
		}
		if len(grouping.Fields) == 0 {
			return RuleConfig{}, fmt.Errorf("groupings[%d].fields must not be empty", index)
		}

		fieldSet := make(map[string]struct{}, len(grouping.Fields))
		for _, field := range grouping.Fields {
			if !supportedGroupField(field) {
				return RuleConfig{}, fmt.Errorf("groupings[%d]: unsupported field %q", index, field)
			}
			if _, exists := fieldSet[field]; exists {
				return RuleConfig{}, fmt.Errorf("groupings[%d]: duplicate field %q", index, field)
			}
			fieldSet[field] = struct{}{}
		}
		definition := strings.Join(grouping.Fields, "\x00")
		if _, exists := definitions[definition]; exists {
			return RuleConfig{}, fmt.Errorf("groupings[%d]: duplicate grouping definition", index)
		}
		groupingIDs[grouping.ID] = struct{}{}
		definitions[definition] = struct{}{}
		result.Groupings = append(result.Groupings, GroupingConfig{
			ID:     grouping.ID,
			Fields: append([]string(nil), grouping.Fields...),
		})
	}
	return result, nil
}

func defaultEngine() EngineConfig {
	return EngineConfig{
		LiveEventLateness: defaultLiveEventLateness,
		Rules: []RuleConfig{{
			ID:                  "homepage",
			Window:              defaultWindow,
			Threshold:           defaultThreshold,
			SuspiciousThreshold: defaultSuspicious,
			Groupings:           []GroupingConfig{{ID: "by_ip", Fields: []string{"ip"}}},
		}},
	}
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
