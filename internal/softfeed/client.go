package softfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxSnapshotBytes = 16 << 20
	MaxDecisions     = 50000
	StaleAfter       = 5 * time.Second
)

type State struct {
	mu          sync.RWMutex
	snapshot    *Snapshot
	lastSuccess time.Time
	index       map[string]map[netip.Addr]time.Time
}

type CheckResult struct {
	Challenge bool
	State     string
	Reason    string
}

func NewState() *State { return &State{index: map[string]map[netip.Addr]time.Time{}} }

// ApplyJSON validates the complete message before swapping any visible state.
// receivedAt must come from the local monotonic clock (normally time.Now()).
func (state *State) ApplyJSON(body []byte, receivedAt time.Time) error {
	if len(body) > MaxSnapshotBytes {
		return fmt.Errorf("feed snapshot exceeds %d bytes", MaxSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("decode feed response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("feed response must contain one JSON object")
	}
	if response.Protocol != 1 || response.Epoch == "" || len(response.Epoch) > 128 {
		return fmt.Errorf("invalid feed protocol or epoch")
	}
	if response.Unchanged {
		state.mu.Lock()
		defer state.mu.Unlock()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			return fmt.Errorf("decode unchanged feed fields: %w", err)
		}
		for _, key := range []string{"mode", "config_revision", "sites", "cookie_ttl", "decisions"} {
			if _, exists := fields[key]; exists {
				return fmt.Errorf("unchanged feed response contains %s", key)
			}
		}
		if response.Mode != "" || response.ConfigRevision != "" || response.Sites != nil || response.CookieTTL != "" || response.Decisions != nil {
			return fmt.Errorf("unchanged feed response contains snapshot data")
		}
		if state.snapshot == nil || state.snapshot.Epoch != response.Epoch || state.snapshot.Revision != response.Revision {
			return fmt.Errorf("unchanged response does not match a known epoch and revision")
		}
		state.lastSuccess = receivedAt
		return nil
	}
	if response.Sites == nil || response.Decisions == nil {
		return fmt.Errorf("full feed response must contain sites and decisions arrays")
	}
	snapshot := Snapshot{Protocol: response.Protocol, Epoch: response.Epoch, Revision: response.Revision, Mode: response.Mode, ConfigRevision: response.ConfigRevision, Sites: *response.Sites, CookieTTL: response.CookieTTL, Decisions: *response.Decisions}
	index, err := validateSnapshot(snapshot)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.snapshot != nil && state.snapshot.Epoch == snapshot.Epoch && snapshot.Revision < state.snapshot.Revision {
		return fmt.Errorf("feed revision moved backwards")
	}
	state.snapshot = &snapshot
	state.index = index
	state.lastSuccess = receivedAt
	return nil
}

func validateSnapshot(snapshot Snapshot) (map[string]map[netip.Addr]time.Time, error) {
	if snapshot.Protocol != 1 || snapshot.Epoch == "" || len(snapshot.Epoch) > 128 {
		return nil, fmt.Errorf("invalid feed protocol or epoch")
	}
	if snapshot.Mode != "dry_run" && snapshot.Mode != "nftables" && snapshot.Mode != "soft_block" && snapshot.Mode != "hybrid" {
		return nil, fmt.Errorf("invalid feed mode %q", snapshot.Mode)
	}
	if snapshot.ConfigRevision == "" || len(snapshot.ConfigRevision) > 128 {
		return nil, fmt.Errorf("invalid config revision")
	}
	if snapshot.Sites == nil || len(snapshot.Sites) > 32 {
		return nil, fmt.Errorf("site list is missing or exceeds 32 entries")
	}
	if snapshot.Decisions == nil || len(snapshot.Decisions) > MaxDecisions {
		return nil, fmt.Errorf("decision list is missing or exceeds %d entries", MaxDecisions)
	}
	if SnapshotUsesSoftBlock(snapshot) {
		if len(snapshot.Sites) == 0 {
			return nil, fmt.Errorf("soft-block feed has no sites")
		}
		ttl, err := time.ParseDuration(snapshot.CookieTTL)
		if err != nil || ttl < time.Minute || ttl > 24*time.Hour {
			return nil, fmt.Errorf("invalid cookie TTL")
		}
	} else if snapshot.CookieTTL != "" {
		if ttl, err := time.ParseDuration(snapshot.CookieTTL); err != nil || ttl < time.Minute || ttl > 24*time.Hour {
			return nil, fmt.Errorf("invalid cookie TTL")
		}
	}
	sites := map[string]bool{}
	hosts := map[string]bool{}
	for _, site := range snapshot.Sites {
		if !validID(site.ID) || sites[site.ID] || len(site.Hosts) == 0 {
			return nil, fmt.Errorf("invalid or duplicate site %q", site.ID)
		}
		sites[site.ID] = true
		for _, host := range site.Hosts {
			if !validHost(host) || hosts[host] {
				return nil, fmt.Errorf("invalid or duplicate site host %q", host)
			}
			hosts[host] = true
		}
	}
	index := map[string]map[netip.Addr]time.Time{}
	seen := map[string]bool{}
	for _, decision := range snapshot.Decisions {
		if !validID(decision.SiteID) || !validID(decision.RuleID) || !validID(decision.SourceID) || !sites[decision.SiteID] {
			return nil, fmt.Errorf("invalid decision identifiers")
		}
		ip, err := netip.ParseAddr(decision.IP)
		if err != nil || !ip.IsValid() || ip.Zone() != "" || ip.Unmap().String() != decision.IP {
			return nil, fmt.Errorf("invalid or noncanonical decision IP %q", decision.IP)
		}
		if decision.CreatedAt.IsZero() || !decision.ExpiresAt.After(decision.CreatedAt) {
			return nil, fmt.Errorf("invalid decision expiry")
		}
		key := decision.SiteID + "\x00" + decision.RuleID + "\x00" + decision.IP
		if seen[key] {
			return nil, fmt.Errorf("duplicate soft-block decision")
		}
		seen[key] = true
		if index[decision.SiteID] == nil {
			index[decision.SiteID] = map[netip.Addr]time.Time{}
		}
		if decision.ExpiresAt.After(index[decision.SiteID][ip]) {
			index[decision.SiteID][ip] = decision.ExpiresAt
		}
	}
	return index, nil
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ToLower(host) != host || strings.HasSuffix(host, ".") || strings.ContainsAny(host, ":/%") {
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

func (state *State) Health(now time.Time) string {
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.snapshot == nil {
		return "starting"
	}
	age := now.Sub(state.lastSuccess)
	if age < 0 || age > StaleAfter {
		return "degraded"
	}
	return "ready"
}

// Check is a bounded in-memory lookup. Starting, disabled, and stale states
// fail open. Expiry is enforced even if the next feed update is delayed.
func (state *State) Check(site string, ip netip.Addr, now time.Time) CheckResult {
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.snapshot == nil {
		return CheckResult{State: "starting", Reason: "no_snapshot"}
	}
	age := now.Sub(state.lastSuccess)
	if age < 0 || age > StaleAfter {
		return CheckResult{State: "degraded", Reason: "feed_stale"}
	}
	if !SnapshotUsesSoftBlock(*state.snapshot) {
		return CheckResult{State: "ready", Reason: "mode_disabled"}
	}
	if !ip.IsValid() || ip.Zone() != "" {
		return CheckResult{State: "ready", Reason: "invalid_ip"}
	}
	expires := state.index[site][ip.Unmap()]
	if expires.After(now) {
		return CheckResult{Challenge: true, State: "ready", Reason: "decision_active"}
	}
	return CheckResult{State: "ready", Reason: "no_decision"}
}

func ModeUsesSoftBlock(mode string) bool { return mode == "soft_block" || mode == "hybrid" }

// SnapshotUsesSoftBlock distinguishes a hybrid configuration that contains
// CAPTCHA rules from a valid hybrid configuration made only of dry-run and
// nftables rules. Older snapshots remain compatible because soft-enabled
// snapshots already carry at least one site.
func SnapshotUsesSoftBlock(snapshot Snapshot) bool {
	return ModeUsesSoftBlock(snapshot.Mode) && len(snapshot.Sites) > 0
}

func (state *State) Current() (*Snapshot, bool) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.snapshot == nil {
		return nil, false
	}
	copy := *state.snapshot
	copy.Sites = append([]Site(nil), state.snapshot.Sites...)
	for i := range copy.Sites {
		copy.Sites[i].Hosts = append([]string(nil), copy.Sites[i].Hosts...)
	}
	copy.Decisions = append([]Decision(nil), state.snapshot.Decisions...)
	return &copy, true
}

type Client struct {
	SocketPath string
	State      *State
}

func (client *Client) PollOnce(ctx context.Context) error {
	if client.State == nil {
		client.State = NewState()
	}
	if client.SocketPath == "" {
		return fmt.Errorf("feed socket path is empty")
	}
	query := url.Values{}
	if snapshot, ok := client.State.Current(); ok {
		query.Set("epoch", snapshot.Epoch)
		query.Set("revision", strconv.FormatUint(snapshot.Revision, 10))
		query.Set("wait", "1")
	}
	requestURL := "http://antiddos/v1/soft-decisions"
	if encoded := query.Encode(); encoded != "" {
		requestURL += "?" + encoded
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "unix", client.SocketPath)
	}}
	httpClient := &http.Client{Transport: transport, Timeout: FeedHeartbeat + time.Second}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("read soft-block feed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("soft-block feed returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxSnapshotBytes+1))
	if err != nil {
		return fmt.Errorf("read soft-block feed response: %w", err)
	}
	if len(body) > MaxSnapshotBytes {
		return fmt.Errorf("soft-block feed response exceeds %d bytes", MaxSnapshotBytes)
	}
	return client.State.ApplyJSON(body, time.Now())
}

func (client *Client) Run(ctx context.Context, onError func(error)) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		err := client.PollOnce(ctx)
		if err == nil {
			backoff = time.Second
			// An older feed server may ignore long-poll. Keep compatibility
			// without spinning while reconnecting immediately to current servers.
			if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
				timer := time.NewTimer(100*time.Millisecond - elapsed)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			continue
		}
		if onError != nil {
			onError(err)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 5*time.Second {
			backoff += time.Second
		}
	}
}

func BuildSnapshotJSON(snapshot Snapshot) ([]byte, error) {
	sort.Slice(snapshot.Sites, func(i, j int) bool { return snapshot.Sites[i].ID < snapshot.Sites[j].ID })
	return json.Marshal(snapshot)
}
