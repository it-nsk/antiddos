// Package action defines the boundary between a validated block request and
// the component that applies it.
package action

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

type Status string

const (
	StatusWouldApply    Status = "would_apply"
	StatusApplied       Status = "applied"
	StatusAlreadyActive Status = "already_active"
	StatusWouldRemove   Status = "would_remove"
	StatusRemoved       Status = "removed"
	StatusAlreadyAbsent Status = "already_absent"
	StatusSkipped       Status = "skipped"
	StatusFailed        Status = "failed"
)

// BlockRequest contains only the target and expiry approved by blockpolicy.
// Actions must not reinterpret the originating detection or choose another IP.
type BlockRequest struct {
	IP        netip.Addr
	ExpiresAt time.Time
	RuleID    string
}

func (request BlockRequest) Validate() error {
	if !request.IP.IsValid() {
		return fmt.Errorf("block request IP is invalid")
	}
	if request.ExpiresAt.IsZero() {
		return fmt.Errorf("block request expiry is required")
	}
	if request.RuleID == "" {
		return fmt.Errorf("block request rule ID is required")
	}
	return nil
}

// Result reports what happened. WouldApply is for observe/dry-run mode and
// must never be reported as Applied. Err is set only for StatusFailed.
type Result struct {
	Status    Status
	IP        netip.Addr
	ExpiresAt time.Time
	Reason    string
	Err       error
}

func (result Result) Validate() error {
	switch result.Status {
	case StatusWouldApply, StatusApplied:
		if !result.IP.IsValid() {
			return fmt.Errorf("action result IP is invalid for status %q", result.Status)
		}
		if result.ExpiresAt.IsZero() {
			return fmt.Errorf("action result expiry is required for status %q", result.Status)
		}
		if result.Err != nil {
			return fmt.Errorf("action result status %q must not include an error", result.Status)
		}
	case StatusAlreadyActive:
		if !result.IP.IsValid() {
			return fmt.Errorf("action result IP is invalid for status %q", result.Status)
		}
		if result.Err != nil {
			return fmt.Errorf("action result status %q must not include an error", result.Status)
		}
	case StatusWouldRemove, StatusRemoved, StatusAlreadyAbsent:
		if !result.IP.IsValid() {
			return fmt.Errorf("action result IP is invalid for status %q", result.Status)
		}
		if result.Err != nil {
			return fmt.Errorf("action result status %q must not include an error", result.Status)
		}
	case StatusSkipped:
		if result.Reason == "" {
			return fmt.Errorf("skipped action result requires a reason")
		}
		if result.Err != nil {
			return fmt.Errorf("skipped action result must not include an error")
		}
	case StatusFailed:
		if result.Err == nil {
			return fmt.Errorf("failed action result requires an error")
		}
	default:
		return fmt.Errorf("unsupported action result status %q", result.Status)
	}
	return nil
}

// Action applies a policy-approved block or removes one exact IP. Implementations
// report outcomes explicitly; callers must not infer enforcement from an action's name.
type Action interface {
	Apply(context.Context, BlockRequest) Result
	Remove(context.Context, netip.Addr) Result
}
