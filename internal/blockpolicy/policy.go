// Package blockpolicy defines which detections can produce an IP block and
// the lifetime rules for those blocks. It does not perform firewall actions.
package blockpolicy

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/it-nsk/antiddos/internal/engine"
)

const (
	MinDurationMinutes = 1
	MaxDurationMinutes = 60
)

type Outcome string

const (
	OutcomeSkip              Outcome = "skip"
	OutcomeStartBlock        Outcome = "start_block"
	OutcomeKeepExistingBlock Outcome = "keep_existing_block"
)

type Reason string

const (
	ReasonNone           Reason = ""
	ReasonGroupByNotIP   Reason = "group_by_not_ip"
	ReasonInvalidIP      Reason = "invalid_ip"
	ReasonAlreadyBlocked Reason = "already_blocked"
)

// ActiveBlock identifies the address as well as its expiry so a caller cannot
// accidentally apply one IP's active deadline to another IP's detection.
type ActiveBlock struct {
	IP        netip.Addr
	ExpiresAt time.Time
}

// Decision is the policy result for one detection. KeepExistingBlock carries
// the original expiry unchanged, so repeated detections cannot extend a ban.
type Decision struct {
	Outcome   Outcome
	Reason    Reason
	RuleID    string
	IP        netip.Addr
	ExpiresAt time.Time
}

// Policy holds the validated settings used to evaluate detections.
type Policy struct {
	duration time.Duration
}

// ValidateDuration accepts whole-minute block durations in the supported
// range. The one-hour maximum keeps the initial policy focused on short bans.
func ValidateDuration(duration time.Duration) error {
	if duration%time.Minute != 0 {
		return fmt.Errorf("block duration must be a whole number of minutes")
	}
	if duration < MinDuration() || duration > MaxDuration() {
		return fmt.Errorf("block duration must be between %d and %d minutes", MinDurationMinutes, MaxDurationMinutes)
	}
	return nil
}

func MinDuration() time.Duration { return time.Duration(MinDurationMinutes) * time.Minute }

func MaxDuration() time.Duration { return time.Duration(MaxDurationMinutes) * time.Minute }

// New validates the block duration once when the service starts.
func New(duration time.Duration) (*Policy, error) {
	if err := ValidateDuration(duration); err != nil {
		return nil, err
	}
	return &Policy{duration: duration}, nil
}

// Evaluate applies the block eligibility and expiry policy to a detection.
// active is the currently recorded block for the detected IP, if any.
func (policy *Policy) Evaluate(detection engine.Detection, now time.Time, active *ActiveBlock) (Decision, error) {
	if policy == nil {
		return Decision{}, fmt.Errorf("block policy is not configured")
	}
	if detection.GroupField != engine.GroupByIP {
		return Decision{Outcome: OutcomeSkip, Reason: ReasonGroupByNotIP, RuleID: detection.RuleID}, nil
	}
	address, err := netip.ParseAddr(detection.GroupValue)
	if err != nil || !address.IsValid() {
		return Decision{Outcome: OutcomeSkip, Reason: ReasonInvalidIP, RuleID: detection.RuleID}, nil
	}
	address = address.Unmap()
	if active != nil {
		if !active.IP.IsValid() {
			return Decision{}, fmt.Errorf("active block has an invalid IP address")
		}
		if active.IP.Unmap() == address && active.ExpiresAt.After(now) {
			return Decision{Outcome: OutcomeKeepExistingBlock, Reason: ReasonAlreadyBlocked, RuleID: detection.RuleID, IP: address, ExpiresAt: active.ExpiresAt}, nil
		}
	}
	return Decision{Outcome: OutcomeStartBlock, Reason: ReasonNone, RuleID: detection.RuleID, IP: address, ExpiresAt: now.Add(policy.duration)}, nil
}
