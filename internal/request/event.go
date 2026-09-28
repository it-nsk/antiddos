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
	Timestamp     time.Time
	IP            netip.Addr
	Method        string
	Path          string
	RawQuery      string
	Query         url.Values
	Protocol      string
	Status        int
	ResponseBytes *int64
	UserAgent     string
}
