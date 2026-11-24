package action

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestCustomRejectsUnsafeCommandBeforeExecution(t *testing.T) {
	req := BlockRequest{IP: netip.MustParseAddr("192.0.2.1"), RuleID: "r", ExpiresAt: time.Now().Add(time.Minute)}
	for _, command := range []string{"echo bad", "/bin/echo {unknown}", "/bin/echo\nwhoami"} {
		result := (Custom{Command: command}).Apply(context.Background(), req)
		if result.Status != StatusFailed {
			t.Fatalf("%q status = %s", command, result.Status)
		}
	}
}
