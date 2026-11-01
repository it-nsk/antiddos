// Package request contains the normalized request data shared by the parser,
// rule engine, and metrics collector.
package request

import (
	"net/netip"
	"net/url"
	"time"
)

// Event is one request observed in the Nginx access log.
type Event struct {
	Timestamp time.Time
	IP        netip.Addr
	Method    string
	Path      string
	RawQuery  string
	// RawLine is the complete source-log line that produced the event. It is
	// attached by the application after parsing so a detection always retains
	// the exact request or security event that caused it.
	RawLine        string
	Query          url.Values
	Protocol       string
	Status         int
	ResponseOrigin string
	ResponseBytes  *int64
	UserAgent      string
}
