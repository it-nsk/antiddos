package action

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// Custom invokes an administrator-configured absolute binary without a shell.
// Command is whitespace-separated; only {ip} and {duration} are expanded.
type Custom struct{ Command string }

func (c Custom) Apply(ctx context.Context, r BlockRequest) Result {
	if err := r.Validate(); err != nil {
		return Result{Status: StatusFailed, IP: r.IP, ExpiresAt: r.ExpiresAt, Err: err}
	}
	parts := strings.Fields(c.Command)
	stripped := strings.ReplaceAll(strings.ReplaceAll(c.Command, "{ip}", ""), "{duration}", "")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "/") || strings.ContainsAny(c.Command, "\x00\r\n") || strings.ContainsAny(stripped, "{}") {
		return Result{Status: StatusFailed, IP: r.IP, ExpiresAt: r.ExpiresAt, Err: fmt.Errorf("invalid custom command")}
	}
	duration := time.Until(r.ExpiresAt).Round(time.Second).String()
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "{ip}", r.IP.String()), "{duration}", duration)
	}
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(runCtx, parts[0], parts[1:]...).CombinedOutput(); err != nil {
		return Result{Status: StatusFailed, IP: r.IP, ExpiresAt: r.ExpiresAt, Err: fmt.Errorf("custom command: %w: %s", err, strings.TrimSpace(string(out)))}
	}
	return Result{Status: StatusApplied, IP: r.IP, ExpiresAt: r.ExpiresAt}
}
func (c Custom) Remove(context.Context, netip.Addr) Result {
	return Result{Status: StatusAlreadyAbsent, Reason: "custom action has no automatic removal"}
}
