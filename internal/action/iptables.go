package action

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	IPSetIPv4       = "antiddos_blocked_ipv4"
	IPSetIPv6       = "antiddos_blocked_ipv6"
	ipTablesComment = "antiddos-managed"
)

// IPTables uses ipset for expiring address membership and iptables/ip6tables
// only for stable match rules. It is intended for legacy hosts such as CentOS
// 7 where nftables is not available. Commands are always executed directly,
// never through a shell.
type IPTables struct {
	IPTablesBinary  string
	IP6TablesBinary string
	IPSetBinary     string
	BlockTCPPorts   []uint16
	run             func(context.Context, string, ...string) ([]byte, error)
	now             func() time.Time
}

func (iptables *IPTables) Apply(ctx context.Context, request BlockRequest) Result {
	if err := ctx.Err(); err != nil {
		return Result{Status: StatusFailed, IP: request.IP, Err: err}
	}
	if err := request.Validate(); err != nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: err}
	}
	if iptables == nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: fmt.Errorf("iptables action is not configured")}
	}
	now := time.Now()
	if iptables.now != nil {
		now = iptables.now()
	}
	seconds := int64(request.ExpiresAt.Sub(now) / time.Second)
	if seconds < 1 {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: fmt.Errorf("block request has less than one second remaining")}
	}
	ip := request.IP.Unmap()
	set, err := ipSetForAddress(ip)
	if err != nil {
		return Result{Status: StatusFailed, IP: ip, ExpiresAt: request.ExpiresAt, Err: err}
	}
	output, err := iptables.command(ctx, iptables.ipsetBinary(), "add", set, ip.String(), "timeout", strconv.FormatInt(seconds, 10), "-exist")
	if err != nil {
		return Result{Status: StatusFailed, IP: ip, ExpiresAt: request.ExpiresAt, Err: commandError("ipset add", err, output)}
	}
	return Result{Status: StatusApplied, IP: ip, ExpiresAt: request.ExpiresAt}
}

func (iptables *IPTables) Remove(ctx context.Context, ip netip.Addr) Result {
	if err := ctx.Err(); err != nil {
		return Result{Status: StatusFailed, IP: ip, Err: err}
	}
	if iptables == nil {
		return Result{Status: StatusFailed, IP: ip, Err: fmt.Errorf("iptables action is not configured")}
	}
	if !ip.IsValid() {
		return Result{Status: StatusFailed, IP: ip, Err: fmt.Errorf("IP address is invalid")}
	}
	ip = ip.Unmap()
	set, err := ipSetForAddress(ip)
	if err != nil {
		return Result{Status: StatusFailed, IP: ip, Err: err}
	}
	output, err := iptables.command(ctx, iptables.ipsetBinary(), "del", set, ip.String())
	if err == nil {
		return Result{Status: StatusRemoved, IP: ip}
	}
	if strings.Contains(strings.ToLower(string(output)), "not") && strings.Contains(strings.ToLower(string(output)), "set") || strings.Contains(strings.ToLower(string(output)), "not added") {
		return Result{Status: StatusAlreadyAbsent, IP: ip, Reason: "address is absent from the ipset"}
	}
	return Result{Status: StatusFailed, IP: ip, Err: commandError("ipset del", err, output)}
}

// Initialize creates namespaced ipsets and inserts only rules tagged as owned
// by AntiDDoS. Existing foreign rules are never modified or flushed.
func (iptables *IPTables) Initialize(ctx context.Context) error {
	if iptables == nil {
		return fmt.Errorf("iptables action is not configured")
	}
	for _, definition := range []struct{ name, family string }{{IPSetIPv4, "inet"}, {IPSetIPv6, "inet6"}} {
		output, err := iptables.command(ctx, iptables.ipsetBinary(), "create", definition.name, "hash:ip", "family", definition.family, "timeout", "3600", "-exist")
		if err != nil {
			return commandError("create ipset "+definition.name, err, output)
		}
	}
	for _, table := range []struct{ binary, set string }{{iptables.iptablesBinary(), IPSetIPv4}, {iptables.ip6tablesBinary(), IPSetIPv6}} {
		for _, chain := range []string{"INPUT", "FORWARD"} {
			for _, rule := range iptables.rules(table.set) {
				check := append([]string{"-C", chain}, rule...)
				output, err := iptables.command(ctx, table.binary, check...)
				if err == nil {
					continue
				}
				add := append([]string{"-I", chain, "1"}, rule...)
				if output, err = iptables.command(ctx, table.binary, add...); err != nil {
					return commandError("install iptables rule in "+chain, err, output)
				}
			}
		}
	}
	return nil
}

func (iptables *IPTables) rules(set string) [][]string {
	base := []string{"-m", "set", "--match-set", set, "src"}
	if len(iptables.BlockTCPPorts) == 0 {
		return [][]string{append(base, "-m", "comment", "--comment", ipTablesComment, "-j", "DROP")}
	}
	rules := make([][]string, 0, len(iptables.BlockTCPPorts))
	for _, port := range iptables.BlockTCPPorts {
		rules = append(rules, append(append([]string{}, base...), "-p", "tcp", "--dport", strconv.Itoa(int(port)), "-m", "comment", "--comment", ipTablesComment, "-j", "DROP"))
	}
	return rules
}

func (iptables *IPTables) command(ctx context.Context, binary string, args ...string) ([]byte, error) {
	run := iptables.run
	if run == nil {
		run = runIPTablesCommand
	}
	return run(ctx, binary, args...)
}
func (iptables *IPTables) iptablesBinary() string {
	if iptables.IPTablesBinary != "" {
		return iptables.IPTablesBinary
	}
	return "iptables"
}
func (iptables *IPTables) ip6tablesBinary() string {
	if iptables.IP6TablesBinary != "" {
		return iptables.IP6TablesBinary
	}
	return "ip6tables"
}
func (iptables *IPTables) ipsetBinary() string {
	if iptables.IPSetBinary != "" {
		return iptables.IPSetBinary
	}
	return "ipset"
}
func ipSetForAddress(ip netip.Addr) (string, error) {
	if ip.Is4() {
		return IPSetIPv4, nil
	}
	if ip.Is6() {
		return IPSetIPv6, nil
	}
	return "", fmt.Errorf("unsupported IP address %q", ip)
}
func runIPTablesCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}
func commandError(operation string, err error, output []byte) error {
	return fmt.Errorf("%s failed: %w: %s", operation, err, strings.TrimSpace(string(output)))
}
