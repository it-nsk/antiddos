package action

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBlockRequestValidation(t *testing.T) {
	valid := BlockRequest{IP: netip.MustParseAddr("192.0.2.10"), ExpiresAt: time.Now().Add(time.Minute), RuleID: "homepage"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for _, request := range []BlockRequest{
		{ExpiresAt: valid.ExpiresAt, RuleID: valid.RuleID},
		{IP: valid.IP, RuleID: valid.RuleID},
		{IP: valid.IP, ExpiresAt: valid.ExpiresAt},
	} {
		if err := request.Validate(); err == nil {
			t.Errorf("invalid request unexpectedly accepted: %#v", request)
		}
	}
}

func TestDryRunReportsWithoutApplying(t *testing.T) {
	request := BlockRequest{
		IP:        netip.MustParseAddr("2001:db8::10"),
		ExpiresAt: time.Date(2026, time.October, 9, 10, 5, 0, 0, time.UTC),
		RuleID:    "homepage",
	}
	result := (DryRun{}).Apply(context.Background(), request)
	if result.Status != StatusWouldApply || result.IP != request.IP || !result.ExpiresAt.Equal(request.ExpiresAt) {
		t.Fatalf("unexpected dry-run result: %#v", result)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("invalid dry-run result: %v", err)
	}
}

func TestDryRunRejectsInvalidRequest(t *testing.T) {
	result := (DryRun{}).Apply(context.Background(), BlockRequest{})
	if result.Status != StatusFailed || result.Err == nil {
		t.Fatalf("invalid request result = %#v, want failed", result)
	}
}

func TestNFTablesAddsExactIPv4AndIPv6WithRemainingExpiry(t *testing.T) {
	now := time.Date(2026, time.October, 9, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		ip   netip.Addr
		set  string
	}{
		{name: "IPv4", ip: netip.MustParseAddr("192.0.2.10"), set: NftIPv4Set},
		{name: "IPv6", ip: netip.MustParseAddr("2001:db8::10"), set: NftIPv6Set},
	} {
		t.Run(test.name, func(t *testing.T) {
			var gotBinary string
			var gotArgs []string
			action := NFTables{
				Binary: "/usr/sbin/nft",
				now:    func() time.Time { return now },
				run: func(_ context.Context, binary string, args ...string) ([]byte, error) {
					gotBinary, gotArgs = binary, args
					return nil, nil
				},
			}
			request := BlockRequest{IP: test.ip, ExpiresAt: now.Add(5*time.Minute + time.Millisecond), RuleID: "homepage"}
			result := action.Apply(context.Background(), request)
			if result.Status != StatusApplied {
				t.Fatalf("Status = %q, want %q (error: %v)", result.Status, StatusApplied, result.Err)
			}
			wantArgs := []string{"add", "element", NftFamily, NftTable, test.set, "{", test.ip.String(), "timeout", "300s", "}"}
			if gotBinary != "/usr/sbin/nft" || !reflect.DeepEqual(gotArgs, wantArgs) {
				t.Fatalf("command = %q %q, want %q %q", gotBinary, gotArgs, "/usr/sbin/nft", wantArgs)
			}
		})
	}
}

func TestNFTablesDuplicateDoesNotBecomeFailure(t *testing.T) {
	now := time.Now()
	action := NFTables{
		now: func() time.Time { return now },
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("Error: Could not process rule: File exists"), errors.New("exit status 1")
		},
	}
	request := BlockRequest{IP: netip.MustParseAddr("192.0.2.10"), ExpiresAt: now.Add(time.Minute), RuleID: "homepage"}
	result := action.Apply(context.Background(), request)
	if result.Status != StatusAlreadyActive {
		t.Fatalf("Status = %q, want %q (error: %v)", result.Status, StatusAlreadyActive, result.Err)
	}
	if result.Reason == "" {
		t.Fatal("duplicate result must explain that nftables timeout was left unchanged")
	}
	if !result.ExpiresAt.IsZero() {
		t.Fatalf("duplicate result must not claim an unknown expiry: %s", result.ExpiresAt)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("duplicate result is invalid: %v", err)
	}
}

func TestNFTablesReportsFirewallErrors(t *testing.T) {
	now := time.Now()
	action := NFTables{
		now: func() time.Time { return now },
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("Operation not permitted"), errors.New("exit status 1")
		},
	}
	request := BlockRequest{IP: netip.MustParseAddr("192.0.2.10"), ExpiresAt: now.Add(time.Minute), RuleID: "homepage"}
	result := action.Apply(context.Background(), request)
	if result.Status != StatusFailed || result.Err == nil {
		t.Fatalf("result = %#v, want failed result", result)
	}
}

func TestNFTablesRemoveDeletesOnlyRequestedIPv4OrIPv6Element(t *testing.T) {
	for _, test := range []struct {
		ip  netip.Addr
		set string
	}{
		{ip: netip.MustParseAddr("192.0.2.10"), set: NftIPv4Set},
		{ip: netip.MustParseAddr("2001:db8::10"), set: NftIPv6Set},
	} {
		var got []string
		nftAction := NFTables{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			got = args
			return nil, nil
		}}
		result := nftAction.Remove(context.Background(), test.ip)
		if result.Status != StatusRemoved || result.IP != test.ip {
			t.Fatalf("Remove(%s) = %#v", test.ip, result)
		}
		want := []string{"delete", "element", NftFamily, NftTable, test.set, "{", test.ip.String(), "}"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("command = %q, want %q", got, want)
		}
	}
}

func TestNFTablesRemoveTreatsMissingElementAsAlreadyAbsent(t *testing.T) {
	nftAction := NFTables{run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Error: No such file or directory"), errors.New("exit status 1")
	}}
	result := nftAction.Remove(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if result.Status != StatusAlreadyAbsent {
		t.Fatalf("Remove() = %#v, want already_absent", result)
	}
}

func TestNFTRuleLineIgnoresChainDeclarationHandle(t *testing.T) {
	if body, handle, ok := nftRuleLine("chain input { # handle 3"); ok || body != "" || handle != 0 {
		t.Fatalf("chain declaration parsed as rule: body=%q handle=%d ok=%t", body, handle, ok)
	}
	body, handle, ok := nftRuleLine(`tcp dport 443 ip saddr @blocked_ipv4 drop comment "antiddos-managed:input:ip:tcp:443" # handle 4`)
	if !ok || handle != 4 || !strings.Contains(body, "antiddos-managed:input:ip:tcp:443") {
		t.Fatalf("managed rule not parsed: body=%q handle=%d ok=%t", body, handle, ok)
	}
}

func TestNFTablesInitializeCreatesOnlyOwnedObjectsAndIsIdempotent(t *testing.T) {
	objects := make(map[string]string)
	rules := make(map[string][]string)
	var calls [][]string
	nextHandle := 1
	runner := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) >= 6 && args[0] == "-a" && args[1] == "list" && args[2] == "chain" {
			chain := args[5]
			return []byte("chain " + chain + " {\n" + strings.Join(rules[chain], "\n") + "\n}\n"), nil
		}
		key := strings.Join(args[1:], " ")
		switch args[0] {
		case "list":
			if value, ok := objects[key]; ok {
				return []byte(value), nil
			}
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		case "add":
			if len(args) > 1 && args[1] == "rule" {
				chain := args[4]
				rules[chain] = append(rules[chain], strings.Join(args[5:], " ")+" # handle "+strconv.Itoa(nextHandle))
				nextHandle++
				return nil, nil
			}
			objects[key] = strings.Join(args, " ")
			if len(args) > 1 && args[1] == "table" {
				objects["table inet antiddos"] = `table inet antiddos { comment "managed by antiddos" }`
			}
			if len(args) > 1 && args[1] == "set" && args[4] == NftIPv4Set {
				objects["set inet antiddos blocked_ipv4"] = "set blocked_ipv4 { type ipv4_addr; flags timeout; size 65535; }"
			}
			if len(args) > 1 && args[1] == "set" && args[4] == NftIPv6Set {
				objects["set inet antiddos blocked_ipv6"] = "set blocked_ipv6 { type ipv6_addr; flags timeout; size 65535; }"
			}
			if len(args) > 1 && args[1] == "chain" && args[4] == "input" {
				objects["chain inet antiddos input"] = "chain input { type filter hook input priority -10; policy accept; }"
			}
			if len(args) > 1 && args[1] == "chain" && args[4] == "forward" {
				objects["chain inet antiddos forward"] = "chain forward { type filter hook forward priority -10; policy accept; }"
			}
			return nil, nil
		case "delete":
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected command: %q", args)
		}
	}
	nftAction := NFTables{run: runner}
	if err := nftAction.Initialize(context.Background()); err != nil {
		t.Fatalf("first initialization failed: %v", err)
	}
	firstCallCount := len(calls)
	if err := nftAction.Initialize(context.Background()); err != nil {
		t.Fatalf("second initialization failed: %v", err)
	}
	if firstCallCount == 0 || len(calls) <= firstCallCount {
		t.Fatal("expected startup inspection commands on both initializations")
	}
	for _, args := range calls {
		if args[0] == "flush" || args[0] == "replace" || (args[0] == "delete" && len(args) > 1 && args[1] != "rule") {
			t.Fatalf("initializer must not destroy or replace firewall state: %q", args)
		}
	}
}

func TestNFTablesPortRestrictionRemovesLegacyAllPortRule(t *testing.T) {
	var calls [][]string
	nftAction := NFTables{BlockTCPPorts: []uint16{80, 443}, run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) >= 6 && args[0] == "-a" {
			return []byte("chain input {\n ip saddr @blocked_ipv4 drop # handle 7\n tcp dport 8080 ip saddr @blocked_ipv4 drop comment \"antiddos-managed:input:ip:tcp:8080\" # handle 8\n}\n"), nil
		}
		return nil, nil
	}}
	if err := nftAction.ensureRule(func(args ...string) ([]byte, error) { return nftAction.run(context.Background(), "nft", args...) }, "input", "ip", NftIPv4Set); err != nil {
		t.Fatal(err)
	}
	var added, removedLegacy, removedStale bool
	for _, args := range calls {
		joined := strings.Join(args, " ")
		if strings.HasPrefix(joined, "add rule ") {
			added = strings.Contains(joined, "tcp dport { 80, 443 }") && strings.Contains(joined, "ip saddr @blocked_ipv4 drop")
		}
		switch strings.Join(args, " ") {
		case "delete rule inet antiddos input handle 7":
			removedLegacy = true
		case "delete rule inet antiddos input handle 8":
			removedStale = true
		}
	}
	if !added || !removedLegacy || !removedStale {
		t.Fatalf("commands = %#v; expected TCP 80/443 rule and removal of old broad/stale rules", calls)
	}
}

func TestNFTablesInitializeRefusesUnownedTable(t *testing.T) {
	nftAction := NFTables{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "list" && args[1] == "table" {
			return []byte("table inet antiddos { }"), nil
		}
		return nil, nil
	}}
	if err := nftAction.Initialize(context.Background()); err == nil || !strings.Contains(err.Error(), "not marked as AntiDDoS-owned") {
		t.Fatalf("Initialize error = %v, want unowned-table rejection", err)
	}
}

func TestNFTablesRemoveOwnedTableValidatesSchemaBeforeExactDelete(t *testing.T) {
	table := `table inet antiddos {
 comment "managed by antiddos"
 set blocked_ipv4 {
 }
 set blocked_ipv6 {
 }
 chain input {
 }
 chain forward {
 }
}`
	var deleted bool
	runner := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "list table inet antiddos":
			return []byte(table), nil
		case "list set inet antiddos blocked_ipv4":
			return []byte("set blocked_ipv4 { type ipv4_addr; flags timeout; size 65535; }"), nil
		case "list set inet antiddos blocked_ipv6":
			return []byte("set blocked_ipv6 { type ipv6_addr; flags timeout; size 65535; }"), nil
		case "-a list chain inet antiddos input":
			return []byte("chain input { type filter hook input priority -10; policy accept;\n ip saddr @blocked_ipv4 drop # handle 1\n ip6 saddr @blocked_ipv6 drop # handle 2\n}"), nil
		case "-a list chain inet antiddos forward":
			return []byte("chain forward { type filter hook forward priority -10; policy accept;\n ip saddr @blocked_ipv4 drop comment \"antiddos-managed:forward:ip:all\" # handle 3\n ip6 saddr @blocked_ipv6 drop comment \"antiddos-managed:forward:ip6:all\" # handle 4\n}"), nil
		case "delete table inet antiddos":
			deleted = true
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected command %q", joined)
		}
	}
	removed, err := (&NFTables{run: runner}).RemoveOwnedTable(context.Background())
	if err != nil || !removed || !deleted {
		t.Fatalf("removed=%v deleted=%v err=%v", removed, deleted, err)
	}
}

func TestNFTablesRemoveOwnedTableRefusesUnexpectedObjectsAndRules(t *testing.T) {
	base := `table inet antiddos {
 comment "managed by antiddos"
 set blocked_ipv4 { }
 set blocked_ipv6 { }
 chain input { }
 chain forward { }
%s
}`
	for name, extra := range map[string]string{"extra chain": " chain foreign { }", "extra set": " set foreign { }"} {
		t.Run(name, func(t *testing.T) {
			deleted := false
			nftAction := NFTables{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "list table inet antiddos" {
					return []byte(fmt.Sprintf(base, extra)), nil
				}
				deleted = true
				return nil, nil
			}}
			if _, err := nftAction.RemoveOwnedTable(context.Background()); err == nil || !strings.Contains(err.Error(), "unexpected") {
				t.Fatalf("unexpected schema accepted: %v", err)
			}
			if deleted {
				t.Fatal("delete attempted after schema rejection")
			}
		})
	}
}

func TestNFTablesRemoveOwnedTableMissingIsNotClaimedAsRemoved(t *testing.T) {
	nftAction := NFTables{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		return []byte("Error: No such file or directory"), errors.New("exit status 1")
	}}
	removed, err := nftAction.RemoveOwnedTable(context.Background())
	if err != nil || removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
}

func TestResultValidation(t *testing.T) {
	validTarget := Result{Status: StatusApplied, IP: netip.MustParseAddr("192.0.2.10"), ExpiresAt: time.Now().Add(time.Minute)}
	validResults := []Result{
		{Status: StatusWouldApply, IP: validTarget.IP, ExpiresAt: validTarget.ExpiresAt},
		validTarget,
		{Status: StatusAlreadyActive, IP: validTarget.IP, ExpiresAt: validTarget.ExpiresAt},
		{Status: StatusWouldRemove, IP: validTarget.IP},
		{Status: StatusRemoved, IP: validTarget.IP},
		{Status: StatusAlreadyAbsent, IP: validTarget.IP},
		{Status: StatusSkipped, Reason: "group_by_not_ip"},
		{Status: StatusFailed, IP: validTarget.IP, Err: errors.New("nft command failed")},
	}
	for _, result := range validResults {
		if err := result.Validate(); err != nil {
			t.Errorf("valid result %#v rejected: %v", result, err)
		}
	}
	invalidResults := []Result{
		{},
		{Status: StatusApplied, IP: validTarget.IP},
		{Status: StatusApplied, IP: validTarget.IP, ExpiresAt: validTarget.ExpiresAt, Err: errors.New("unexpected error")},
		{Status: StatusSkipped},
		{Status: StatusFailed},
		{Status: "unknown"},
	}
	for _, result := range invalidResults {
		if err := result.Validate(); err == nil {
			t.Errorf("invalid result unexpectedly accepted: %#v", result)
		}
	}
}
