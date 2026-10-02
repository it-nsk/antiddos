package engine

import (
	"container/heap"
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
	minimumMapShrinkSize = 4096
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
	rules            []compiledRule
	frontier         time.Time
	hasFrontier      bool
	liveClock        bool
	maxEventLateness time.Duration
	wallWatermark    time.Time
	hasWallWatermark bool
}

// Options selects whether wall-clock expiration is safe for the input stream.
// Live tail mode requires a bounded event timestamp delay; replay mode should
// leave LiveClock disabled and advance expiration only through Process events.
type Options struct {
	LiveClock        bool
	MaxEventLateness time.Duration
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
	id          string
	fields      []GroupField
	key         keyBuilder
	groups      map[GroupKey]*timestampWindow
	expiry      expiryHeap
	peakGroups  int
	mapRebuilds int
}

func New(rules []Rule) (*Engine, error) {
	return NewWithOptions(rules, Options{})
}

func NewWithOptions(rules []Rule, options Options) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}
	if options.MaxEventLateness < 0 {
		return nil, fmt.Errorf("maximum event lateness must not be negative")
	}

	result := &Engine{
		rules:            make([]compiledRule, 0, len(rules)),
		liveClock:        options.LiveClock,
		maxEventLateness: options.MaxEventLateness,
	}
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

// Process and AdvanceWallClock must be called by the same owner goroutine.
func (engine *Engine) Process(event request.Event) ([]Evaluation, error) {
	timestamp := event.Timestamp.UTC()
	if engine.IsLate(timestamp) {
		return nil, fmt.Errorf("event timestamp %s is before the accepted event-time watermark", timestamp.Format(time.RFC3339Nano))
	}
	engine.frontier = timestamp
	engine.hasFrontier = true
	engine.cleanup(timestamp)

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
				window = &timestampWindow{key: key, expiryIndex: -1}
				grouping.groups[key] = window
				if len(grouping.groups) > grouping.peakGroups {
					grouping.peakGroups = len(grouping.groups)
				}
			}
			window.prune(cutoff)
			before := window.len()
			window.append(timestamp)
			grouping.schedule(window, timestamp.Add(rule.window))
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
			if detectionSeverity := classifyDetection(before, count, rule.suspiciousThreshold, rule.threshold); detectionSeverity != SeverityNormal {
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
				}
			}
			evaluations = append(evaluations, evaluation)
		}
	}
	return evaluations, nil
}

func (engine *Engine) Cleanup() {
	if engine.hasFrontier {
		engine.cleanup(engine.frontier)
	}
}

// AdvanceWallClock expires groups in live-tail mode without moving the
// event-time frontier. MaxEventLateness defines the minimum accepted event
// timestamp as now-MaxEventLateness; events older than that watermark are late.
func (engine *Engine) AdvanceWallClock(now time.Time) {
	if !engine.liveClock {
		return
	}
	watermark := now.Add(-engine.maxEventLateness).UTC()
	if engine.hasWallWatermark && !watermark.After(engine.wallWatermark) {
		return
	}
	engine.wallWatermark = watermark
	engine.hasWallWatermark = true
	engine.cleanup(watermark)
}

// IsLate reports whether an event would move backward from event time or
// precede the live-mode wall-clock watermark.
func (engine *Engine) IsLate(timestamp time.Time) bool {
	timestamp = timestamp.UTC()
	return (engine.hasFrontier && timestamp.Before(engine.frontier)) ||
		(engine.hasWallWatermark && timestamp.Before(engine.wallWatermark))
}

func (engine *Engine) RuleRevisions() []string {
	revisions := make([]string, len(engine.rules))
	for index := range engine.rules {
		revisions[index] = engine.rules[index].revision
	}
	return revisions
}

func (engine *Engine) cleanup(frontier time.Time) {
	for ruleIndex := range engine.rules {
		rule := &engine.rules[ruleIndex]
		for groupingIndex := range rule.groupings {
			grouping := &rule.groupings[groupingIndex]
			for grouping.expiry.Len() > 0 && !grouping.expiry[0].expiresAt.After(frontier) {
				window := heap.Pop(&grouping.expiry).(*timestampWindow)
				delete(grouping.groups, window.key)
				window.timestamps = nil
				window.head = 0
				grouping.shrinkIfNeeded()
			}
		}
	}
}

func (grouping *compiledGrouping) schedule(window *timestampWindow, expiresAt time.Time) {
	window.expiresAt = expiresAt
	if window.expiryIndex < 0 {
		heap.Push(&grouping.expiry, window)
		return
	}
	heap.Fix(&grouping.expiry, window.expiryIndex)
}

func (grouping *compiledGrouping) shrinkIfNeeded() {
	count := len(grouping.groups)
	if count == 0 {
		grouping.groups = make(map[GroupKey]*timestampWindow)
		grouping.expiry = nil
		grouping.peakGroups = 0
		grouping.mapRebuilds++
		return
	}
	if grouping.peakGroups < minimumMapShrinkSize || count > grouping.peakGroups/4 {
		return
	}
	groups := make(map[GroupKey]*timestampWindow, count)
	for key, window := range grouping.groups {
		groups[key] = window
	}
	grouping.groups = groups
	shrunkHeap := make(expiryHeap, len(grouping.expiry))
	copy(shrunkHeap, grouping.expiry)
	grouping.expiry = shrunkHeap
	heap.Init(&grouping.expiry)
	grouping.peakGroups = count
	grouping.mapRebuilds++
}

type expiryHeap []*timestampWindow

func (expiry expiryHeap) Len() int { return len(expiry) }
func (expiry expiryHeap) Less(left, right int) bool {
	return expiry[left].expiresAt.Before(expiry[right].expiresAt)
}
func (expiry expiryHeap) Swap(left, right int) {
	expiry[left], expiry[right] = expiry[right], expiry[left]
	expiry[left].expiryIndex = left
	expiry[right].expiryIndex = right
}
func (expiry *expiryHeap) Push(value any) {
	window := value.(*timestampWindow)
	window.expiryIndex = len(*expiry)
	*expiry = append(*expiry, window)
}
func (expiry *expiryHeap) Pop() any {
	old := *expiry
	last := len(old) - 1
	window := old[last]
	old[last] = nil
	window.expiryIndex = -1
	*expiry = old[:last]
	return window
}

func IsHomepageRequest(event request.Event) bool {
	return event.Method == "GET" && event.Path == "/"
}

func AnalysisConfigID(ruleRevisions []string) string {
	canonical := struct {
		Version       string   `json:"version"`
		RuleRevisions []string `json:"rule_revisions"`
	}{
		Version:       "analysis-v2-immediate",
		RuleRevisions: append([]string(nil), ruleRevisions...),
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

func classifyDetection(before, after, suspicious, threshold int) Severity {
	// Every request that leaves its group at or above the main threshold is a
	// violation and must be persisted. The count may rise or fall as the exact
	// sliding window advances; it remains a violation until it drops below the
	// threshold.
	if after >= threshold {
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
		NotificationPolicy:  "every-threshold-violation",
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
