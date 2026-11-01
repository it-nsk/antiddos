package engine

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/it-nsk/antiddos/internal/request"
)

const (
	ruleSemanticsVersion = "get-path-regex-v2-source-rule-whitelist"
	minimumMapShrinkSize = 4096
	ipv4MappedPrefixBits = 96
)

type Rule struct {
	ID         string
	Type       string
	Disabled   bool
	LogSource  string
	PathRegex  string
	QueryRegex string
	Statuses   []int
	UniqueBy   string
	Window     time.Duration
	Threshold  int
	GroupBy    GroupField
	IgnoreIPs  []string
}

type Detection struct {
	SiteID         string
	RuleID         string
	LogSource      string
	RuleRevision   string
	GroupField     GroupField
	GroupValue     string
	GroupKey       GroupKey
	EventTimestamp time.Time
	Count          int
	Window         time.Duration
	Threshold      int
	DryRun         bool
	Reason         string
}

type Evaluation struct {
	RuleID     string
	GroupField GroupField
	GroupValue string
	GroupKey   GroupKey
	Count      int
	Violated   bool
	Detection  *Detection
}

type Engine struct {
	rules           []compiledRule
	ignoreIPs       []netip.Prefix
	frontier        time.Time
	hasFrontier     bool
	liveClock       bool
	cleanupClock    time.Time
	hasCleanupClock bool
}

type Options struct {
	LiveClock bool
	IgnoreIPs []string
}

type compiledRule struct {
	id         string
	ruleType   string
	disabled   bool
	logSource  string
	revision   string
	pathRegex  *regexp.Regexp
	queryRegex *regexp.Regexp
	statuses   map[int]struct{}
	uniqueBy   string
	window     time.Duration
	threshold  int
	ignoreIPs  []netip.Prefix
	grouping   compiledGrouping
}

type compiledGrouping struct {
	field       GroupField
	key         keyBuilder
	groups      map[GroupKey]*timestampWindow
	expiry      expiryHeap
	peakGroups  int
	mapRebuilds int
}

func New(rules []Rule) (*Engine, error) { return NewWithOptions(rules, Options{}) }

func NewWithOptions(rules []Rule, options Options) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}
	result := &Engine{rules: make([]compiledRule, 0, len(rules)), liveClock: options.LiveClock}
	globalIgnoreIPs, err := parsePrefixes(options.IgnoreIPs, "ignore_ips")
	if err != nil {
		return nil, err
	}
	result.ignoreIPs = globalIgnoreIPs
	ruleIDs := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", index, err)
		}
		compiled.ignoreIPs, err = parsePrefixes(rule.IgnoreIPs, fmt.Sprintf("rule[%q].ignore_ips", rule.ID))
		if err != nil {
			return nil, err
		}
		if _, exists := ruleIDs[compiled.id]; exists {
			return nil, fmt.Errorf("rule[%d]: duplicate id %q", index, compiled.id)
		}
		ruleIDs[compiled.id] = struct{}{}
		result.rules = append(result.rules, compiled)
	}
	return result, nil
}

func parsePrefixes(values []string, field string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
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
			if prefix.Bits() < ipv4MappedPrefixBits {
				return nil, fmt.Errorf("%s[%d]: invalid IPv4-mapped prefix %q", field, index, value)
			}
			// The first 96 bits identify the IPv4-mapped IPv6 range; the
			// remaining prefix bits are the original IPv4 network mask.
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-ipv4MappedPrefixBits)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func compileRule(rule Rule) (compiledRule, error) {
	if err := validID(rule.ID); err != nil {
		return compiledRule{}, fmt.Errorf("id: %w", err)
	}
	pathRegex, err := regexp.Compile(rule.PathRegex)
	if err != nil {
		return compiledRule{}, fmt.Errorf("path regex: %w", err)
	}
	var queryRegex *regexp.Regexp
	if rule.QueryRegex != "" {
		queryRegex, err = regexp.Compile(rule.QueryRegex)
		if err != nil {
			return compiledRule{}, fmt.Errorf("query regex: %w", err)
		}
	}
	statuses := make(map[int]struct{}, len(rule.Statuses))
	for _, status := range rule.Statuses {
		statuses[status] = struct{}{}
	}
	if rule.Window <= 0 {
		return compiledRule{}, fmt.Errorf("window must be positive")
	}
	if rule.Threshold < 1 {
		return compiledRule{}, fmt.Errorf("threshold must be at least 1")
	}
	key, err := compileKeyBuilder(rule.GroupBy)
	if err != nil {
		return compiledRule{}, err
	}
	revision, err := ruleRevision(rule)
	if err != nil {
		return compiledRule{}, err
	}
	return compiledRule{
		id: rule.ID, ruleType: rule.Type, disabled: rule.Disabled, logSource: rule.LogSource, revision: revision, pathRegex: pathRegex, queryRegex: queryRegex, statuses: statuses, uniqueBy: rule.UniqueBy, window: rule.Window,
		threshold: rule.Threshold,
		grouping:  compiledGrouping{field: rule.GroupBy, key: key, groups: make(map[GroupKey]*timestampWindow)},
	}, nil
}

// Process and AdvanceWallClock must be called by the same owner goroutine.
func (engine *Engine) Process(event request.Event) ([]Evaluation, error) {
	evaluations, _, err := engine.ProcessWithMatch(event)
	return evaluations, err
}

// ProcessWithMatch evaluates each rule once and reports whether any rule's
// request selector matched. The match result includes rule-whitelisted events,
// which remain visible to traffic statistics but do not enter that rule's window.
func (engine *Engine) ProcessWithMatch(event request.Event) ([]Evaluation, bool, error) {
	if event.ResponseOrigin == "challenge" || event.ResponseOrigin == "service" {
		return nil, false, nil
	}
	if engine.IsIgnored(event) {
		return nil, engine.Matches(event), nil
	}
	timestamp := event.Timestamp.UTC()
	if engine.IsLate(timestamp) {
		return nil, engine.Matches(event), fmt.Errorf("event timestamp %s is before the accepted event-time watermark", timestamp.Format(time.RFC3339Nano))
	}
	engine.frontier = timestamp
	engine.hasFrontier = true
	engine.cleanup(timestamp)

	evaluations := make([]Evaluation, 0, len(engine.rules))
	matched := false
	for ruleIndex := range engine.rules {
		rule := &engine.rules[ruleIndex]
		if !rule.matches(event) {
			continue
		}
		matched = true
		if rule.ignores(event.IP) {
			continue
		}
		grouping := &rule.grouping
		key, value := grouping.key(event)
		window := grouping.groups[key]
		if window == nil {
			window = &timestampWindow{key: key, expiryIndex: -1}
			grouping.groups[key] = window
			if len(grouping.groups) > grouping.peakGroups {
				grouping.peakGroups = len(grouping.groups)
			}
		}
		window.prune(timestamp.Add(-rule.window))
		if rule.uniqueBy != "" {
			value := event.Path
			if rule.uniqueBy == "destination_port" {
				parts := strings.Split(event.Path, "/")
				value = parts[len(parts)-1]
			}
			window.appendValue(timestamp, value)
		} else {
			window.append(timestamp)
		}
		grouping.schedule(window, timestamp.Add(rule.window))
		count := window.len()
		if rule.uniqueBy != "" {
			count = window.uniqueLen()
		}
		violated := count >= rule.threshold
		evaluation := Evaluation{
			RuleID: rule.id, GroupField: grouping.field, GroupValue: value,
			GroupKey: key, Count: count, Violated: violated,
		}
		if violated {
			evaluation.Detection = &Detection{
				RuleID: rule.id, LogSource: rule.logSource, RuleRevision: rule.revision, GroupField: grouping.field,
				GroupValue: value, GroupKey: key, EventTimestamp: event.Timestamp,
				Count: count, Window: rule.window, Threshold: rule.threshold, DryRun: true,
				Reason: rule.detectionReason(event),
			}
		}
		evaluations = append(evaluations, evaluation)
	}
	return evaluations, matched, nil
}

func (rule *compiledRule) detectionReason(event request.Event) string {
	switch rule.ruleType {
	case "signature":
		if rule.queryRegex != nil {
			matched := rule.queryRegex.FindString(event.RawQuery)
			if matched == "" {
				matched = event.RawQuery
			}
			if decoded, err := url.QueryUnescape(matched); err == nil {
				matched = decoded
			}
			if strings.Contains(strings.ToLower(rule.id), "sqli") {
				return fmt.Sprintf("SQLi-сигнатура в query: %s", matched)
			}
			return fmt.Sprintf("Сигнатура в query: %s", matched)
		}
		matched := rule.pathRegex.FindString(event.Path)
		if matched == "" {
			matched = event.Path
		}
		return fmt.Sprintf("Сигнатура в URL: %s", matched)
	case "cardinality":
		if rule.uniqueBy == "destination_port" {
			return "Обнаружен перебор разных портов"
		}
		return "Обнаружен перебор разных URL"
	default:
		switch event.Method {
		case "SSH":
			return "Серия неудачных попыток входа по SSH"
		case "NGINX_ERROR":
			return "Серия ошибок аутентификации Nginx"
		case "GET":
			return "Частота HTTP-запросов превысила порог"
		default:
			return "Частота событий превысила порог"
		}
	}
}

func (engine *Engine) IsIgnored(event request.Event) bool {
	address := event.IP
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range engine.ignoreIPs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// IsIgnoredForRule reports whether an address is excluded globally or by the
// whitelist of the named rule. It is also used when restoring stored leases.
func (engine *Engine) IsIgnoredForRule(address netip.Addr, ruleID string) bool {
	event := request.Event{IP: address}
	if engine.IsIgnored(event) {
		return true
	}
	for index := range engine.rules {
		rule := &engine.rules[index]
		if rule.id == ruleID {
			return rule.ignores(address)
		}
	}
	return false
}

func (rule *compiledRule) ignores(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range rule.ignoreIPs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (engine *Engine) Matches(event request.Event) bool {
	for index := range engine.rules {
		if engine.rules[index].matches(event) {
			return true
		}
	}
	return false
}

func (rule *compiledRule) matches(event request.Event) bool {
	if rule.disabled {
		return false
	}
	// HTTP access rules retain the historical GET-only behavior. Security log
	// parsers use explicit non-HTTP methods and are matched by their normalized
	// event path (for example /ssh/failed or /port/tcp/22).
	switch event.Method {
	case "GET", "SSH", "NETFILTER", "NGINX_ERROR":
	default:
		return false
	}
	if !rule.pathRegex.MatchString(event.Path) {
		return false
	}
	if rule.queryRegex != nil && !rule.queryRegex.MatchString(event.RawQuery) {
		return false
	}
	if len(rule.statuses) > 0 {
		if _, ok := rule.statuses[event.Status]; !ok {
			return false
		}
	}
	return true
}

func (engine *Engine) Cleanup() {
	if engine.hasFrontier {
		engine.cleanup(engine.frontier)
	}
}

func (engine *Engine) AdvanceWallClock(now time.Time) {
	if !engine.liveClock {
		return
	}
	now = now.UTC()
	if engine.hasCleanupClock && !now.After(engine.cleanupClock) {
		return
	}
	engine.cleanupClock = now
	engine.hasCleanupClock = true
	engine.cleanup(now)
}

func (engine *Engine) IsLate(timestamp time.Time) bool {
	timestamp = timestamp.UTC()
	return engine.hasFrontier && timestamp.Before(engine.frontier)
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
		grouping := &engine.rules[ruleIndex].grouping
		for grouping.expiry.Len() > 0 && !grouping.expiry[0].expiresAt.After(frontier) {
			window := heap.Pop(&grouping.expiry).(*timestampWindow)
			delete(grouping.groups, window.key)
			window.timestamps = nil
			window.head = 0
			grouping.shrinkIfNeeded()
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

func AnalysisConfigID(ruleRevisions []string) string {
	canonical := struct {
		Version       string   `json:"version"`
		RuleRevisions []string `json:"rule_revisions"`
	}{Version: "analysis-v4-multi-source-rule-whitelist", RuleRevisions: append([]string(nil), ruleRevisions...)}
	encoded, _ := json.Marshal(canonical)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func ruleRevision(rule Rule) (string, error) {
	canonical := struct {
		Version   string     `json:"version"`
		ID        string     `json:"id"`
		LogSource string     `json:"log_source"`
		IgnoreIPs []string   `json:"ignore_ips"`
		PathRegex string     `json:"path_regex"`
		WindowNS  int64      `json:"window_ns"`
		Threshold int        `json:"threshold"`
		GroupBy   GroupField `json:"group_by"`
		Policy    string     `json:"notification_policy"`
	}{ruleSemanticsVersion, rule.ID, rule.LogSource, canonicalPrefixes(rule.IgnoreIPs), rule.PathRegex, int64(rule.Window), rule.Threshold, rule.GroupBy, "every-threshold-violation"}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode rule revision: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalPrefixes(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
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
