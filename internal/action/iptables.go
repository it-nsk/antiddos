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

// ReadManagedBlocks uses ipset save on exactly the two namespaced set names;
// it does not enumerate or inspect any foreign ipset.
func (iptables *IPTables) ReadManagedBlocks(ctx context.Context) ([]ManagedBlock, error) {
	if iptables == nil {
		return nil, fmt.Errorf("iptables action is not configured")
	}
	now := time.Now()
	if iptables.now != nil {
		now = iptables.now()
	}
	var result []ManagedBlock
	for _, set := range []string{IPSetIPv4, IPSetIPv6} {
		output, err := iptables.command(ctx, iptables.ipsetBinary(), "save", set)
		if err != nil {
			return nil, commandError("read managed ipset "+set, err, output)
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			// ipset versions may print a membership diagnostic to stdout while
			// serving `save <set>`. It is not a save command and has no state.
			if fields[0] == "create" {
				if len(fields) < 3 || fields[1] != set || fields[2] != "hash:ip" {
					return nil, fmt.Errorf("unexpected set definition while reading managed ipset %s", set)
				}
				continue
			}
			if fields[0] != "add" {
				if strings.HasPrefix(strings.ToLower(line), "warning:") || strings.HasPrefix(strings.ToLower(line), "error:") {
					continue
				}
				return nil, fmt.Errorf("unexpected output while reading managed ipset %s: %s", set, line)
			}
			if len(fields) < 5 || fields[1] != set {
				return nil, fmt.Errorf("unexpected entry while reading managed ipset %s", set)
			}
			ip, e := netip.ParseAddr(fields[2])
			if e != nil {
				return nil, fmt.Errorf("invalid address %q in managed ipset", fields[2])
			}
			timeout := -1
			for i := 3; i+1 < len(fields); i++ {
				if fields[i] == "timeout" {
					timeout, e = strconv.Atoi(fields[i+1])
					if e != nil {
						return nil, fmt.Errorf("invalid timeout for %s", ip)
					}
					break
				}
			}
			if timeout < 1 {
				return nil, fmt.Errorf("managed ipset entry %s has no usable timeout", ip)
			}
			result = append(result, ManagedBlock{IP: ip.Unmap(), ExpiresAt: now.Add(time.Duration(timeout) * time.Second)})
		}
	}
	return result, nil
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
