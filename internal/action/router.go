package action

import (
	"context"
	"fmt"
	"net/netip"
)

// Router selects the enforcement backend from the already validated rule ID.
// It keeps blockmanager independent of concrete firewall implementations while
// still allowing a hybrid policy to use more than one backend.
type Router struct {
	ByRule map[string]Action
	All    []Action
}

func (router Router) Apply(ctx context.Context, request BlockRequest) Result {
	backend := router.ByRule[request.RuleID]
	if backend == nil {
		return Result{Status: StatusFailed, IP: request.IP, ExpiresAt: request.ExpiresAt, Err: fmt.Errorf("no block backend configured for rule %q", request.RuleID)}
	}
	return backend.Apply(ctx, request)
}

// Remove attempts every configured backend because an unblock request has only
// an address, not the originating rule. Each backend is required to leave
// foreign firewall state untouched, so this is safe and idempotent.
func (router Router) Remove(ctx context.Context, ip netip.Addr) Result {
	if len(router.All) == 0 {
		return Result{Status: StatusAlreadyAbsent, IP: ip, Reason: "no firewall backend is configured"}
	}
	removed := false
	for _, backend := range router.All {
		result := backend.Remove(ctx, ip)
		if result.Status == StatusRemoved {
			removed = true
			continue
		}
		if result.Status != StatusAlreadyAbsent {
			return result
		}
	}
	if removed {
		return Result{Status: StatusRemoved, IP: ip}
	}
	return Result{Status: StatusAlreadyAbsent, IP: ip, Reason: "address is absent from all configured firewall backends"}
}
