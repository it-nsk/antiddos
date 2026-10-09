package action

import (
	"context"
	"fmt"
	"net/netip"
)

// DryRun reports approved block requests without changing the system firewall.
type DryRun struct{}

func (DryRun) Apply(ctx context.Context, request BlockRequest) Result {
	if err := ctx.Err(); err != nil {
		return Result{Status: StatusFailed, IP: request.IP, Err: err}
	}
	if err := request.Validate(); err != nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: err}
	}
	return Result{
		Status:    StatusWouldApply,
		IP:        request.IP,
		ExpiresAt: request.ExpiresAt,
		Reason:    "dry-run; firewall unchanged",
	}
}

func (DryRun) Remove(ctx context.Context, ip netip.Addr) Result {
	if err := ctx.Err(); err != nil {
		return Result{Status: StatusFailed, IP: ip, Err: err}
	}
	if !ip.IsValid() {
		return Result{Status: StatusFailed, IP: ip, Err: fmt.Errorf("IP address is invalid")}
	}
	return Result{Status: StatusWouldRemove, IP: ip, Reason: "dry-run; firewall unchanged"}
}
