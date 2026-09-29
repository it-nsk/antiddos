package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/it-nsk/antiddos/internal/request"
)

const (
	ruleSemanticsVersion = "homepage-get-v1"
	cleanupInterval      = time.Second
)

type Severity string

const (
	SeverityNormal            Severity = "normal"
	SeveritySuspicious        Severity = "suspicious"
	SeverityThresholdExceeded Severity = "threshold_exceeded"
)

type Rule struct {
	ID                  string
	Window              time.Duration
	Threshold           int
	SuspiciousThreshold int
	Groupings           []Grouping
}

type Detection struct {
	RuleID              string
	RuleRevision        string
	GroupingID          string
	GroupFields         []GroupField
	GroupValues         []string
	GroupKey            GroupKey
	EventTimestamp      time.Time
	Count               int
	Window              time.Duration
	Threshold           int
	SuspiciousThreshold int
	Severity            Severity
	DryRun              bool
	Outcome             string
}

type Evaluation struct {
	RuleID      string
	GroupingID  string
	GroupKey    GroupKey
	GroupFields []GroupField
	GroupValues []string
	Count       int
	Severity    Severity
	Detection   *Detection
}

type Engine struct {
	rules       []compiledRule
	frontier    time.Time
	hasFrontier bool
	lastCleanup time.Time
}

type compiledRule struct {
	id                  string
	revision            string
	window              time.Duration
	threshold           int
	suspiciousThreshold int
	groupings           []compiledGrouping
}

type compiledGrouping struct {
	id     string
	fields []GroupField
	key    keyBuilder
	groups map[GroupKey]*timestampWindow
}

func New(rules []Rule) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}

	result := &Engine{rules: make([]compiledRule, 0, len(rules))}
	ruleIDs := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", index, err)
		}
		if _, exists := ruleIDs[compiled.id]; exists {
			return nil, fmt.Errorf("rule[%d]: duplicate id %q", index, compiled.id)
		}
		ruleIDs[compiled.id] = struct{}{}
		result.rules = append(result.rules, compiled)
	}
	return result, nil
}

func compileRule(rule Rule) (compiledRule, error) {
	if err := validID(rule.ID); err != nil {
		return compiledRule{}, fmt.Errorf("id: %w", err)
	}
	if rule.Window <= 0 {
		return compiledRule{}, fmt.Errorf("window must be positive")
	}
	if rule.Threshold < 1 {
		return compiledRule{}, fmt.Errorf("threshold must be at least 1")
	}
	if rule.SuspiciousThreshold < 0 || (rule.SuspiciousThreshold > 0 && rule.SuspiciousThreshold >= rule.Threshold) {
		return compiledRule{}, fmt.Errorf("suspicious threshold must be 0 or less than threshold")
	}
	if len(rule.Groupings) == 0 {
		return compiledRule{}, fmt.Errorf("at least one grouping is required")
	}

	compiled := compiledRule{
		id:                  rule.ID,
		window:              rule.Window,
		threshold:           rule.Threshold,
		suspiciousThreshold: rule.SuspiciousThreshold,
		groupings:           make([]compiledGrouping, 0, len(rule.Groupings)),
	}
	groupingIDs := make(map[string]struct{}, len(rule.Groupings))
	definitions := make(map[string]struct{}, len(rule.Groupings))
	for index, grouping := range rule.Groupings {
		if err := validID(grouping.ID); err != nil {
			return compiledRule{}, fmt.Errorf("grouping[%d].id: %w", index, err)
		}
		if len(grouping.Fields) == 0 {
			return compiledRule{}, fmt.Errorf("grouping[%d]: fields must not be empty", index)
		}
		if _, exists := groupingIDs[grouping.ID]; exists {
			return compiledRule{}, fmt.Errorf("grouping[%d]: duplicate id %q", index, grouping.ID)
		}
		seenFields := make(map[GroupField]struct{}, len(grouping.Fields))
		for _, field := range grouping.Fields {
			if _, exists := seenFields[field]; exists {
				return compiledRule{}, fmt.Errorf("grouping[%d]: duplicate field %q", index, field)
			}
			seenFields[field] = struct{}{}
		}
		definitionParts := make([]string, len(grouping.Fields))
		for fieldIndex, field := range grouping.Fields {
			definitionParts[fieldIndex] = string(field)
		}
		definition := strings.Join(definitionParts, "\x00")
		if _, exists := definitions[definition]; exists {
			return compiledRule{}, fmt.Errorf("grouping[%d]: duplicate grouping definition", index)
		}
		key, err := compileKeyBuilder(grouping.Fields)
		if err != nil {
			return compiledRule{}, fmt.Errorf("grouping[%d]: %w", index, err)
		}
		groupingIDs[grouping.ID] = struct{}{}
		definitions[definition] = struct{}{}
		compiled.groupings = append(compiled.groupings, compiledGrouping{
			id:     grouping.ID,
			fields: append([]GroupField(nil), grouping.Fields...),
			key:    key,
			groups: make(map[GroupKey]*timestampWindow),
		})
	}
	revision, err := ruleRevision(rule)
	if err != nil {
		return compiledRule{}, err
	}
	compiled.revision = revision
	return compiled, nil
}

func (engine *Engine) Process(event request.Event) ([]Evaluation, error) {
	timestamp := event.Timestamp.UTC()
	if engine.hasFrontier && timestamp.Before(engine.frontier) {
		return nil, fmt.Errorf("event timestamp %s is before engine frontier %s", timestamp.Format(time.RFC3339Nano), engine.frontier.Format(time.RFC3339Nano))
	}
	engine.frontier = timestamp
	engine.hasFrontier = true
	engine.cleanup(timestamp, false)

	if !IsHomepageRequest(event) {
		return nil, nil
	}

	evaluations := make([]Evaluation, 0)
	for ruleIndex := range engine.rules {
		rule := &engine.rules[ruleIndex]
		cutoff := timestamp.Add(-rule.window)
		for groupingIndex := range rule.groupings {
			grouping := &rule.groupings[groupingIndex]
			key, values := grouping.key(event)
			window := grouping.groups[key]
			if window == nil {
				window = &timestampWindow{}
				grouping.groups[key] = window
			}
			window.prune(cutoff)
			before := window.len()
			window.append(timestamp)
			count := window.len()
			severity := classify(count, rule.suspiciousThreshold, rule.threshold)
			evaluation := Evaluation{
				RuleID:      rule.id,
				GroupingID:  grouping.id,
				GroupKey:    key,
				GroupFields: append([]GroupField(nil), grouping.fields...),
				GroupValues: values,
				Count:       count,
				Severity:    severity,
			}
			if detectionSeverity := crossing(before, count, rule.suspiciousThreshold, rule.threshold); detectionSeverity != SeverityNormal {
				outcome := "would_flag"
				if detectionSeverity == SeverityThresholdExceeded {
					outcome = "would_trigger"
				}
				evaluation.Detection = &Detection{
					RuleID:              rule.id,
					RuleRevision:        rule.revision,
					GroupingID:          grouping.id,
					GroupFields:         append([]GroupField(nil), grouping.fields...),
					GroupValues:         append([]string(nil), values...),
					GroupKey:            key,
					EventTimestamp:      event.Timestamp,
					Count:               count,
					Window:              rule.window,
					Threshold:           rule.threshold,
					SuspiciousThreshold: rule.suspiciousThreshold,
					Severity:            detectionSeverity,
					DryRun:              true,
					Outcome:             outcome,
				}
			}
			evaluations = append(evaluations, evaluation)
		}
	}
	return evaluations, nil
}

func (engine *Engine) Cleanup() {
	if engine.hasFrontier {
		engine.cleanup(engine.frontier, true)
	}
}

func (engine *Engine) RuleRevisions() []string {
	revisions := make([]string, len(engine.rules))
	for index := range engine.rules {
		revisions[index] = engine.rules[index].revision
	}
	return revisions
}

func (engine *Engine) cleanup(frontier time.Time, force bool) {
	if !force && !engine.lastCleanup.IsZero() && frontier.Sub(engine.lastCleanup) < cleanupInterval {
		return
	}
	for ruleIndex := range engine.rules {
		rule := &engine.rules[ruleIndex]
		cutoff := frontier.Add(-rule.window)
		for groupingIndex := range rule.groupings {
			groups := rule.groupings[groupingIndex].groups
			for key, window := range groups {
				window.prune(cutoff)
				if window.len() == 0 {
					delete(groups, key)
				}
			}
		}
	}
	engine.lastCleanup = frontier
}

func IsHomepageRequest(event request.Event) bool {
	return event.Method == "GET" && event.Path == "/"
}

func AnalysisConfigID(ruleRevisions []string, allowedLateness time.Duration, maxPendingEvents int) string {
	canonical := struct {
		Version          string   `json:"version"`
		RuleRevisions    []string `json:"rule_revisions"`
		AllowedLateness  int64    `json:"allowed_lateness_ns"`
		MaxPendingEvents int      `json:"max_pending_events"`
	}{
		Version:          "analysis-v1-late-drop",
		RuleRevisions:    append([]string(nil), ruleRevisions...),
		AllowedLateness:  int64(allowedLateness),
		MaxPendingEvents: maxPendingEvents,
	}
	encoded, _ := json.Marshal(canonical)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func classify(count, suspicious, threshold int) Severity {
	if count >= threshold {
		return SeverityThresholdExceeded
	}
	if suspicious > 0 && count >= suspicious {
		return SeveritySuspicious
	}
	return SeverityNormal
}

func crossing(before, after, suspicious, threshold int) Severity {
	if before < threshold && after >= threshold {
		return SeverityThresholdExceeded
	}
	if suspicious > 0 && before < suspicious && after >= suspicious {
		return SeveritySuspicious
	}
	return SeverityNormal
}

func ruleRevision(rule Rule) (string, error) {
	type canonicalGrouping struct {
		ID     string       `json:"id"`
		Fields []GroupField `json:"fields"`
	}
	type canonicalRule struct {
		Version             string              `json:"version"`
		ID                  string              `json:"id"`
		WindowNS            int64               `json:"window_ns"`
		Threshold           int                 `json:"threshold"`
		SuspiciousThreshold int                 `json:"suspicious_threshold"`
		NotificationPolicy  string              `json:"notification_policy"`
		Groupings           []canonicalGrouping `json:"groupings"`
	}
	canonical := canonicalRule{
		Version:             ruleSemanticsVersion,
		ID:                  rule.ID,
		WindowNS:            int64(rule.Window),
		Threshold:           rule.Threshold,
		SuspiciousThreshold: rule.SuspiciousThreshold,
		NotificationPolicy:  "threshold-crossings",
		Groupings:           make([]canonicalGrouping, len(rule.Groupings)),
	}
	for index, grouping := range rule.Groupings {
		canonical.Groupings[index] = canonicalGrouping{
			ID:     grouping.ID,
			Fields: append([]GroupField(nil), grouping.Fields...),
		}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode rule revision: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func validID(id string) error {
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
