package action

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIPTablesReadManagedBlocksNeverEnumeratesForeignIPSets(t *testing.T) {
	var calls [][]string
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	backend := IPTables{IPSetBinary: "ipset-test", now: func() time.Time { return now }, run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[1] == IPSetIPv4 {
			return []byte("Warning: 127.0.0.2 is in set antiddos_blocked_ipv4.\ncreate antiddos_blocked_ipv4 hash:ip family inet timeout 3600\nadd antiddos_blocked_ipv4 192.0.2.1 timeout 30\n"), nil
		}
		return []byte("create antiddos_blocked_ipv6 hash:ip family inet6 timeout 3600\nadd antiddos_blocked_ipv6 2001:db8::1 timeout 30\n"), nil
	}}
	blocks, err := backend.ReadManagedBlocks(context.Background())
	if err != nil || len(blocks) != 2 {
		t.Fatalf("blocks=%+v err=%v", blocks, err)
	}
	for _, call := range calls {
		if len(call) != 2 || call[0] != "save" || !strings.HasPrefix(call[1], "antiddos_blocked_") {
			t.Fatalf("foreign/unexpected ipset read: %q", call)
		}
	}
}

func TestIPTablesAddsAddressToFamilySetWithRemainingTimeout(t *testing.T) {
	now := time.Date(2026, time.November, 9, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		ip  netip.Addr
		set string
	}{{netip.MustParseAddr("192.0.2.10"), IPSetIPv4}, {netip.MustParseAddr("2001:db8::10"), IPSetIPv6}} {
		var binary string
		var args []string
		backend := IPTables{IPSetBinary: "ipset-test", now: func() time.Time { return now }, run: func(_ context.Context, got string, values ...string) ([]byte, error) {
			binary, args = got, values
			return nil, nil
		}}
		request := BlockRequest{IP: test.ip, RuleID: "hard", ExpiresAt: now.Add(5*time.Minute + time.Millisecond)}
		result := backend.Apply(context.Background(), request)
		if result.Status != StatusApplied {
			t.Fatalf("Apply(%s) = %#v", test.ip, result)
		}
		want := []string{"add", test.set, test.ip.String(), "timeout", "300", "-exist"}
		if binary != "ipset-test" || !reflect.DeepEqual(args, want) {
			t.Fatalf("command = %q %q, want %q %q", binary, args, "ipset-test", want)
		}
	}
}

func TestIPTablesInitializeUsesOnlyTaggedRules(t *testing.T) {
	var commands [][]string
	backend := IPTables{IPTablesBinary: "iptables-test", IP6TablesBinary: "ip6tables-test", IPSetBinary: "ipset-test", BlockTCPPorts: []uint16{80, 443}, run: func(_ context.Context, binary string, args ...string) ([]byte, error) {
		commands = append(commands, append([]string{binary}, args...))
		if args[0] == "-C" {
			return []byte("rule absent"), context.DeadlineExceeded
		}
		return nil, nil
	}}
	if err := backend.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 18 {
		t.Fatalf("commands = %d, want 18: %#v", len(commands), commands)
	}
	for _, command := range commands {
		if command[0] != "ipset-test" {
			found := false
			for _, value := range command {
				if value == ipTablesComment {
					found = true
				}
			}
			if !found {
				t.Fatalf("iptables command is not ownership-tagged: %q", command)
			}
		}
	}
}

func TestIPTablesRemoveTreatsAbsentAddressAsSuccess(t *testing.T) {
	backend := IPTables{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("ipset v7: Element is not added to the set"), context.DeadlineExceeded
	}}
	if result := backend.Remove(context.Background(), netip.MustParseAddr("192.0.2.10")); result.Status != StatusAlreadyAbsent {
		t.Fatalf("result = %#v", result)
	}
}
