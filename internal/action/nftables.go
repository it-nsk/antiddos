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
	NftFamily       = "inet"
	NftTable        = "antiddos"
	NftIPv4Set      = "blocked_ipv4"
	NftIPv6Set      = "blocked_ipv6"
	NftSetMaxSize   = 65535
	nftTableComment = "managed by antiddos"
)

// NFTables manages the AntiDDoS-owned table, sets, chains, and block elements.
// It never modifies other tables or invokes a shell.
type NFTables struct {
	// Binary may override the nft executable path. Empty uses "nft" from PATH.
	Binary string
	run    func(context.Context, string, ...string) ([]byte, error)
	now    func() time.Time
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
	output, err := command("list", "chain", NftFamily, NftTable, chain)
	if err != nil {
		return fmt.Errorf("inspect nftables chain %s: %w: %s", chain, err, strings.TrimSpace(string(output)))
	}
	if strings.Contains(string(output), family+" saddr @"+set+" drop") {
		return nil
	}
	output, err = command("add", "rule", NftFamily, NftTable, chain, family, "saddr", "@"+set, "drop")
	if err != nil {
		return fmt.Errorf("add nftables block rule to %s: %w: %s", chain, err, strings.TrimSpace(string(output)))
	}
	return nil
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
