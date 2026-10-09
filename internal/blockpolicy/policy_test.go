package blockpolicy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/engine"
)

func TestEvaluateAllowsExactIPOnly(t *testing.T) {
	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	policy, err := New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		groupBy    engine.GroupField
		groupValue string
		wantIP     netip.Addr
		wantAllow  bool
	}{
		{name: "IPv4", groupBy: engine.GroupByIP, groupValue: "192.0.2.10", wantIP: netip.MustParseAddr("192.0.2.10"), wantAllow: true},
		{name: "IPv6", groupBy: engine.GroupByIP, groupValue: "2001:db8::10", wantIP: netip.MustParseAddr("2001:db8::10"), wantAllow: true},
		{name: "user agent", groupBy: engine.GroupByUserAgent, groupValue: "curl/8", wantAllow: false},
		{name: "path", groupBy: engine.GroupByPath, groupValue: "/login", wantAllow: false},
		{name: "method", groupBy: engine.GroupByMethod, groupValue: "POST", wantAllow: false},
		{name: "status", groupBy: engine.GroupByStatus, groupValue: "404", wantAllow: false},
		{name: "invalid IP group", groupBy: engine.GroupByIP, groupValue: "client.example", wantAllow: false},
		{name: "CIDR group", groupBy: engine.GroupByIP, groupValue: "192.0.2.0/24", wantAllow: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := policy.Evaluate(engine.Detection{GroupField: test.groupBy, GroupValue: test.groupValue}, now, nil)
			if err != nil {
				t.Fatal(err)
			}
			wantOutcome := OutcomeSkip
			if test.wantAllow {
				wantOutcome = OutcomeStartBlock
			}
			if decision.Outcome != wantOutcome {
				t.Fatalf("Outcome = %v, want %v (reason: %v)", decision.Outcome, wantOutcome, decision.Reason)
			}
			if test.wantAllow && decision.IP != test.wantIP {
				t.Fatalf("IP = %s, want %s", decision.IP, test.wantIP)
			}
			if test.wantAllow && !decision.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("ExpiresAt = %s, want %s", decision.ExpiresAt, now.Add(5*time.Minute))
			}
		})
	}
}

func TestEvaluateDoesNotExtendActiveBlock(t *testing.T) {
	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	policy, err := New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	existingUntil := now.Add(2 * time.Minute)
	active := &ActiveBlock{IP: netip.MustParseAddr("192.0.2.10"), ExpiresAt: existingUntil}
	decision, err := policy.Evaluate(engine.Detection{GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"}, now, active)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != OutcomeKeepExistingBlock {
		t.Fatalf("Outcome = %v, want keep existing block", decision.Outcome)
	}
	if !decision.ExpiresAt.Equal(existingUntil) {
		t.Fatalf("ExpiresAt = %s, want unchanged %s", decision.ExpiresAt, existingUntil)
	}
}

func TestEvaluateDoesNotReuseAnotherIPsExpiry(t *testing.T) {
	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	policy, err := New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	active := &ActiveBlock{IP: netip.MustParseAddr("192.0.2.11"), ExpiresAt: now.Add(2 * time.Minute)}
	decision, err := policy.Evaluate(engine.Detection{GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"}, now, active)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != OutcomeStartBlock || decision.IP.String() != "192.0.2.10" {
		t.Fatalf("another IP's active block affected decision: %#v", decision)
	}
}

func TestEvaluateRejectsInvalidActiveBlockAddress(t *testing.T) {
	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	policy, err := New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	active := &ActiveBlock{ExpiresAt: now.Add(time.Minute)}
	if _, err := policy.Evaluate(engine.Detection{GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"}, now, active); err == nil {
		t.Fatal("expected invalid active block address to fail")
	}
}

func TestEvaluateAllowsBlockAfterPreviousExpiry(t *testing.T) {
	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	policy, err := New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	active := &ActiveBlock{IP: netip.MustParseAddr("192.0.2.10"), ExpiresAt: now}
	decision, err := policy.Evaluate(engine.Detection{GroupField: engine.GroupByIP, GroupValue: "192.0.2.10"}, now, active)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != OutcomeStartBlock {
		t.Fatalf("expired block should permit a new decision: %#v", decision)
	}
}

func TestValidateDuration(t *testing.T) {
	for _, duration := range []time.Duration{time.Minute, 5 * time.Minute, time.Hour} {
		if err := ValidateDuration(duration); err != nil {
			t.Errorf("ValidateDuration(%s): %v", duration, err)
		}
	}
	for _, duration := range []time.Duration{0, time.Second, 90 * time.Second, 61 * time.Minute, 24 * time.Hour} {
		if err := ValidateDuration(duration); err == nil {
			t.Errorf("ValidateDuration(%s) unexpectedly succeeded", duration)
		}
	}
}
