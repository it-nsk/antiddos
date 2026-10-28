package action

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var nftObjectDeclaration = regexp.MustCompile(`(?m)^\s*(set|chain)\s+([A-Za-z0-9_-]+)\s+\{`)

const (
	NftFamily       = "inet"
	NftTable        = "antiddos"
	NftIPv4Set      = "blocked_ipv4"
	NftIPv6Set      = "blocked_ipv6"
	NftSetMaxSize   = 65535
	nftTableComment = "managed by antiddos"
	nftRuleComment  = "antiddos-managed"
)

// NFTables manages the AntiDDoS-owned table, sets, chains, and block elements.
// It never modifies other tables or invokes a shell.
type NFTables struct {
	// Binary may override the nft executable path. Empty uses "nft" from PATH.
	Binary        string
	BlockTCPPorts []uint16
	run           func(context.Context, string, ...string) ([]byte, error)
	now           func() time.Time
}

func (nftAction *NFTables) Apply(ctx context.Context, request BlockRequest) Result {
	if err := ctx.Err(); err != nil {
		return Result{Status: StatusFailed, IP: request.IP, Err: err}
	}
	if err := request.Validate(); err != nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: err}
	}
	if nftAction == nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: fmt.Errorf("nftables action is not configured")}
	}

	now := time.Now()
	if nftAction.now != nil {
		now = nftAction.now()
	}
	remaining := request.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: fmt.Errorf("block request has expired")}
	}
	timeoutSeconds := int64(remaining / time.Second)
	if timeoutSeconds < 1 {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: fmt.Errorf("block request has less than one second remaining")}
	}
	address := request.IP.Unmap()
	setName, err := nftSetForAddress(address)
	if err != nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: err}
	}

	binary := nftAction.Binary
	if binary == "" {
		binary = "nft"
	}
	args := []string{
		"add", "element", NftFamily, NftTable, setName,
		"{", address.String(), "timeout", strconv.FormatInt(timeoutSeconds, 10) + "s", "}",
	}
	run := nftAction.run
	if run == nil {
		run = runNFTCommand
	}
	output, runErr := run(ctx, binary, args...)
	if runErr == nil {
		return Result{Status: StatusApplied, IP: address, ExpiresAt: request.ExpiresAt}
	}
	if isExistingNFTElement(output) {
		return Result{
			Status: StatusAlreadyActive, IP: address,
			Reason: "nftables set element already exists; its timeout was not changed",
		}
	}
	return Result{
		Status: StatusFailed, IP: address, ExpiresAt: request.ExpiresAt,
		Err: fmt.Errorf("nft add element failed: %w: %s", runErr, strings.TrimSpace(string(output))),
	}
}

// Remove deletes one address from the AntiDDoS-owned set. It never flushes a set.
func (nftAction *NFTables) Remove(ctx context.Context, ip netip.Addr) Result {
	if err := ctx.Err(); err != nil {
		return Result{Status: StatusFailed, IP: ip, Err: err}
	}
	if nftAction == nil {
		return Result{Status: StatusFailed, IP: ip, Err: fmt.Errorf("nftables action is not configured")}
	}
	if !ip.IsValid() {
		return Result{Status: StatusFailed, IP: ip, Err: fmt.Errorf("IP address is invalid")}
	}
	ip = ip.Unmap()
	setName, err := nftSetForAddress(ip)
	if err != nil {
		return Result{Status: StatusFailed, IP: ip, Err: err}
	}
	binary := nftAction.Binary
	if binary == "" {
		binary = "nft"
	}
	run := nftAction.run
	if run == nil {
		run = runNFTCommand
	}
	output, runErr := run(ctx, binary, "delete", "element", NftFamily, NftTable, setName, "{", ip.String(), "}")
	if runErr == nil {
		return Result{Status: StatusRemoved, IP: ip}
	}
	if isMissingNFTObject(output) {
		return Result{Status: StatusAlreadyAbsent, IP: ip, Reason: "address is already absent from the nftables set"}
	}
	return Result{Status: StatusFailed, IP: ip, Err: fmt.Errorf("nft delete element failed: %w: %s", runErr, strings.TrimSpace(string(output)))}
}

// Initialize creates only the AntiDDoS-owned table, sets, chains, and rules.
// Existing objects are validated and never flushed or replaced.
func (nftAction *NFTables) Initialize(ctx context.Context) error {
	if nftAction == nil {
		return fmt.Errorf("nftables action is not configured")
	}
	binary := nftAction.Binary
	if binary == "" {
		binary = "nft"
	}
	run := nftAction.run
	if run == nil {
		run = runNFTCommand
	}
	command := func(args ...string) ([]byte, error) {
		return run(ctx, binary, args...)
	}

	table, err := command("list", "table", NftFamily, NftTable)
	if err != nil {
		if !isMissingNFTObject(table) {
			return fmt.Errorf("inspect nftables table %s %s: %w: %s", NftFamily, NftTable, err, strings.TrimSpace(string(table)))
		}
		if output, addErr := command("add", "table", NftFamily, NftTable, "{", "comment", `"`+nftTableComment+`"`, ";", "}"); addErr != nil {
			return fmt.Errorf("create nftables table %s %s: %w: %s", NftFamily, NftTable, addErr, strings.TrimSpace(string(output)))
		}
		table, err = command("list", "table", NftFamily, NftTable)
		if err != nil {
			return fmt.Errorf("verify nftables table: %w: %s", err, strings.TrimSpace(string(table)))
		}
	}
	if !strings.Contains(string(table), `comment "`+nftTableComment+`"`) {
		return fmt.Errorf("nftables table %s %s already exists and is not marked as AntiDDoS-owned", NftFamily, NftTable)
	}

	if err := nftAction.ensureSet(command, NftIPv4Set, "ipv4_addr"); err != nil {
		return err
	}
	if err := nftAction.ensureSet(command, NftIPv6Set, "ipv6_addr"); err != nil {
		return err
	}
	for _, chain := range []struct{ name, hook string }{{"input", "input"}, {"forward", "forward"}} {
		if err := nftAction.ensureChain(command, chain.name, chain.hook); err != nil {
			return err
		}
		for _, rule := range []struct{ family, set string }{{"ip", NftIPv4Set}, {"ip6", NftIPv6Set}} {
			if err := nftAction.ensureRule(command, chain.name, rule.family, rule.set); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateOwnedTable checks the complete AntiDDoS-owned schema without changing
// firewall state. A false result means the table is absent.
func (nftAction *NFTables) ValidateOwnedTable(ctx context.Context) (bool, error) {
	return nftAction.validateOwnedTable(ctx, false)
}

// RemoveOwnedTable validates the complete AntiDDoS-owned schema before deleting
// its table. It never flushes a ruleset or touches any other nftables object.
func (nftAction *NFTables) RemoveOwnedTable(ctx context.Context) (bool, error) {
	return nftAction.validateOwnedTable(ctx, true)
}

func (nftAction *NFTables) validateOwnedTable(ctx context.Context, remove bool) (bool, error) {
	if nftAction == nil {
		return false, fmt.Errorf("nftables action is not configured")
	}
	binary := nftAction.Binary
	if binary == "" {
		binary = "nft"
	}
	run := nftAction.run
	if run == nil {
		run = runNFTCommand
	}
	command := func(args ...string) ([]byte, error) { return run(ctx, binary, args...) }
	table, err := command("list", "table", NftFamily, NftTable)
	if err != nil {
		if isMissingNFTObject(table) {
			return false, nil
		}
		return false, fmt.Errorf("inspect nftables table %s %s: %w: %s", NftFamily, NftTable, err, strings.TrimSpace(string(table)))
	}
	if !strings.Contains(string(table), `comment "`+nftTableComment+`"`) {
		return false, fmt.Errorf("nftables table %s %s is not marked as AntiDDoS-owned", NftFamily, NftTable)
	}
	wantObjects := map[string]bool{"set:" + NftIPv4Set: false, "set:" + NftIPv6Set: false, "chain:input": false, "chain:forward": false}
	for _, match := range nftObjectDeclaration.FindAllStringSubmatch(string(table), -1) {
		key := match[1] + ":" + match[2]
		if _, ok := wantObjects[key]; !ok {
			return false, fmt.Errorf("AntiDDoS nftables table contains unexpected %s %q", match[1], match[2])
		}
		wantObjects[key] = true
	}
	for object, found := range wantObjects {
		if !found {
			return false, fmt.Errorf("AntiDDoS nftables table is missing %s", strings.Replace(object, ":", " ", 1))
		}
	}
	for _, set := range []struct{ name, addressType string }{{NftIPv4Set, "ipv4_addr"}, {NftIPv6Set, "ipv6_addr"}} {
		data, inspectErr := command("list", "set", NftFamily, NftTable, set.name)
		if inspectErr != nil {
			return false, fmt.Errorf("inspect nftables set %s: %w: %s", set.name, inspectErr, strings.TrimSpace(string(data)))
		}
		text := string(data)
		if !strings.Contains(text, "type "+set.addressType) || !strings.Contains(text, "flags timeout") || !strings.Contains(text, fmt.Sprintf("size %d", NftSetMaxSize)) {
			return false, fmt.Errorf("nftables set %s has incompatible type, flags, or size limit", set.name)
		}
	}
	for _, chain := range []struct{ name, hook string }{{"input", "input"}, {"forward", "forward"}} {
		data, inspectErr := command("-a", "list", "chain", NftFamily, NftTable, chain.name)
		if inspectErr != nil {
			return false, fmt.Errorf("inspect nftables chain %s: %w: %s", chain.name, inspectErr, strings.TrimSpace(string(data)))
		}
		text := string(data)
		if !strings.Contains(text, "type filter") || !strings.Contains(text, "hook "+chain.hook) || !strings.Contains(text, "policy accept") {
			return false, fmt.Errorf("nftables chain %s has incompatible type, hook, or policy", chain.name)
		}
		rules := 0
		for _, line := range strings.Split(text, "\n") {
			body, _, ok := nftRuleLine(line)
			if !ok {
				continue
			}
			rules++
			managedPrefix := `comment "` + nftRuleComment + `:` + chain.name + `:`
			legacy := body == nftRuleExpression("ip", NftIPv4Set, "", "") || body == nftRuleExpression("ip6", NftIPv6Set, "", "")
			if !legacy && !strings.Contains(body, managedPrefix) {
				return false, fmt.Errorf("nftables chain %s contains an unmanaged rule", chain.name)
			}
		}
		if rules != 2 {
			return false, fmt.Errorf("nftables chain %s contains %d rules, expected 2 managed rules", chain.name, rules)
		}
	}
	if !remove {
		return true, nil
	}
	output, err := command("delete", "table", NftFamily, NftTable)
	if err != nil {
		return false, fmt.Errorf("delete AntiDDoS nftables table: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return true, nil
}

func (nftAction *NFTables) ensureSet(command func(...string) ([]byte, error), name, addressType string) error {
	output, err := command("list", "set", NftFamily, NftTable, name)
	if err == nil {
		text := string(output)
		if !strings.Contains(text, "type "+addressType) || !strings.Contains(text, "flags timeout") || !strings.Contains(text, fmt.Sprintf("size %d", NftSetMaxSize)) {
			return fmt.Errorf("nftables set %s has incompatible type, flags, or size limit", name)
		}
		return nil
	}
	if !isMissingNFTObject(output) {
		return fmt.Errorf("inspect nftables set %s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	output, err = command("add", "set", NftFamily, NftTable, name, "{", "type", addressType, ";", "flags", "timeout", ";", "size", strconv.Itoa(NftSetMaxSize), ";", "}")
	if err != nil {
		return fmt.Errorf("create nftables set %s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (nftAction *NFTables) ensureChain(command func(...string) ([]byte, error), name, hook string) error {
	output, err := command("list", "chain", NftFamily, NftTable, name)
	if err == nil {
		text := string(output)
		if !strings.Contains(text, "type filter") || !strings.Contains(text, "hook "+hook) {
			return fmt.Errorf("nftables chain %s has incompatible type or hook", name)
		}
		return nil
	}
	if !isMissingNFTObject(output) {
		return fmt.Errorf("inspect nftables chain %s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	output, err = command("add", "chain", NftFamily, NftTable, name, "{", "type", "filter", "hook", hook, "priority", "-10", ";", "policy", "accept", ";", "}")
	if err != nil {
		return fmt.Errorf("create nftables chain %s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (nftAction *NFTables) ensureRule(command func(...string) ([]byte, error), chain, family, set string) error {
	output, err := command("-a", "list", "chain", NftFamily, NftTable, chain)
	if err != nil {
		return fmt.Errorf("inspect nftables chain %s: %w: %s", chain, err, strings.TrimSpace(string(output)))
	}
	lines := strings.Split(string(output), "\n")
	ports := formatPorts(nftAction.BlockTCPPorts)
	marker := nftRuleMarker(chain, family, ports)
	hasDesired := false
	for _, line := range lines {
		body, _, ok := nftRuleLine(line)
		if !ok {
			continue
		}
		if strings.Contains(body, `comment "`+marker+`"`) || (ports == "" && body == nftRuleExpression(family, set, "", "")) {
			hasDesired = true
		}
	}
	if !hasDesired {
		args := []string{"add", "rule", NftFamily, NftTable, chain}
		if ports != "" {
			args = append(args, "tcp", "dport", "{")
			for index, port := range nftAction.BlockTCPPorts {
				value := strconv.Itoa(int(port))
				if index != len(nftAction.BlockTCPPorts)-1 {
					value += ","
				}
				args = append(args, value)
			}
			args = append(args, "}")
		}
		args = append(args, family, "saddr", "@"+set, "drop", "comment", `"`+marker+`"`)
		output, err = command(args...)
		if err != nil {
			return fmt.Errorf("add nftables block rule to %s: %w: %s", chain, err, strings.TrimSpace(string(output)))
		}
	}

	// Rules from older AntiDDoS versions had no comment and blocked all traffic.
	// Remove those when a port restriction is configured, and replace stale
	// commented AntiDDoS rules after a configuration change.
	for _, line := range lines {
		body, handle, ok := nftRuleLine(line)
		if !ok {
			continue
		}
		managedPrefix := `comment "` + nftRuleComment + ":" + chain + ":" + family + ":"
		managedForTarget := strings.Contains(body, managedPrefix)
		legacyBroad := ports != "" && body == nftRuleExpression(family, set, "", "")
		if (managedForTarget && !strings.Contains(body, `comment "`+marker+`"`)) || legacyBroad {
			output, err = command("delete", "rule", NftFamily, NftTable, chain, "handle", strconv.Itoa(handle))
			if err != nil {
				return fmt.Errorf("remove obsolete AntiDDoS rule from %s: %w: %s", chain, err, strings.TrimSpace(string(output)))
			}
		}
	}
	return nil
}

func formatPorts(ports []uint16) string {
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = strconv.Itoa(int(port))
	}
	return strings.Join(values, ",")
}

func nftRuleMarker(chain, family, ports string) string {
	scope := "all"
	if ports != "" {
		scope = "tcp:" + ports
	}
	return nftRuleComment + ":" + chain + ":" + family + ":" + scope
}

func nftRuleExpression(family, set, ports, marker string) string {
	expression := ""
	if ports != "" {
		formatted := strings.ReplaceAll(ports, ",", ", ")
		if strings.Contains(formatted, ",") {
			expression = "tcp dport { " + formatted + " } "
		} else {
			expression = "tcp dport " + formatted + " "
		}
	}
	expression += family + " saddr @" + set + " drop"
	if marker != "" {
		expression += ` comment "` + marker + `"`
	}
	return expression
}

func nftRuleLine(line string) (body string, handle int, ok bool) {
	const handleMarker = "# handle "
	index := strings.LastIndex(line, handleMarker)
	if index < 0 {
		return "", 0, false
	}
	body = strings.TrimSpace(line[:index])
	// `nft -a list chain` annotates the chain declaration itself with a
	// handle. It is metadata, not a rule, and must not participate in the
	// managed-rule count or ownership checks.
	if strings.HasPrefix(body, "chain ") && strings.HasSuffix(body, "{") {
		return "", 0, false
	}
	handle, err := strconv.Atoi(strings.TrimSpace(line[index+len(handleMarker):]))
	if err != nil {
		return "", 0, false
	}
	return body, handle, true
}

func isMissingNFTObject(output []byte) bool {
	text := strings.ToLower(string(output))
	return strings.Contains(text, "no such file or directory") || strings.Contains(text, "does not exist")
}

func nftSetForAddress(address netip.Addr) (string, error) {
	switch {
	case address.Is4():
		return NftIPv4Set, nil
	case address.Is6():
		return NftIPv6Set, nil
	default:
		return "", fmt.Errorf("unsupported IP address %q", address)
	}
}

func isExistingNFTElement(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "file exists") || strings.Contains(message, "element already exists")
}

func runNFTCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}
