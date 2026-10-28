package parser

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/it-nsk/antiddos/internal/request"
)

var (
	nginxErrorTimeRE  = regexp.MustCompile(`^([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	nginxErrorIPRE    = regexp.MustCompile(`client: ([0-9a-fA-F:.]+)`)
	sshTimeRE         = regexp.MustCompile(`^([A-Z][a-z]{2})\s+([ 0-9][0-9])\s+([0-9]{2}:[0-9]{2}:[0-9]{2})`)
	securityISOTimeRE = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+)`)
	sshIPRE           = regexp.MustCompile(`\bfrom ([0-9a-fA-F:.]+)\b`)
	netfilterIPRE     = regexp.MustCompile(`\bSRC=([0-9a-fA-F:.]+)\b`)
	netfilterPortRE   = regexp.MustCompile(`\bDPT=([0-9]{1,5})\b`)
	netfilterProtoRE  = regexp.MustCompile(`\bPROTO=([A-Za-z0-9]+)\b`)
)

type nginxErrorParser struct{}

func (nginxErrorParser) Parse(line string) (request.Event, error) {
	timeMatch := nginxErrorTimeRE.FindStringSubmatch(line)
	ipMatch := nginxErrorIPRE.FindStringSubmatch(line)
	if timeMatch == nil || ipMatch == nil {
		return request.Event{}, fmt.Errorf("parse nginx error: expected timestamp and client IP")
	}
	timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", timeMatch[1], time.Local)
	if err != nil {
		return request.Event{}, fmt.Errorf("parse nginx error timestamp: %w", err)
	}
	ip, err := netip.ParseAddr(ipMatch[1])
	if err != nil {
		return request.Event{}, fmt.Errorf("parse nginx error IP %q: %w", ipMatch[1], err)
	}
	path := "/nginx/error"
	lower := strings.ToLower(line)
	if strings.Contains(lower, "password mismatch") || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "auth failed") {
		path = "/auth/basic/failure"
	}
	return request.Event{Timestamp: timestamp, IP: ip, Method: "NGINX_ERROR", Path: path, Protocol: "-", Status: 500, UserAgent: line}, nil
}

type syslogSSHDParser struct{}

func (syslogSSHDParser) Parse(line string) (request.Event, error) {
	ipMatch := sshIPRE.FindStringSubmatch(line)
	if ipMatch == nil {
		return request.Event{}, fmt.Errorf("parse ssh auth: expected syslog timestamp and remote IP")
	}
	timestamp, err := parseSecuritySyslogTimestamp(line)
	if err != nil {
		return request.Event{}, fmt.Errorf("parse ssh auth timestamp: %w", err)
	}
	ip, err := netip.ParseAddr(ipMatch[1])
	if err != nil {
		return request.Event{}, fmt.Errorf("parse ssh auth IP %q: %w", ipMatch[1], err)
	}
	lower := strings.ToLower(line)
	path := ""
	switch {
	case strings.Contains(lower, "invalid user"):
		path = "/ssh/invalid-user"
	case strings.Contains(lower, "failed password"), strings.Contains(lower, "failed publickey"), strings.Contains(lower, "authentication failure"):
		path = "/ssh/failed"
	default:
		return request.Event{}, fmt.Errorf("ignore non-failed SSH authentication record")
	}
	return request.Event{Timestamp: timestamp, IP: ip, Method: "SSH", Path: path, Protocol: "-", Status: 401, UserAgent: line}, nil
}

type netfilterLogParser struct{}

func (netfilterLogParser) Parse(line string) (request.Event, error) {
	ipMatch, portMatch, protoMatch := netfilterIPRE.FindStringSubmatch(line), netfilterPortRE.FindStringSubmatch(line), netfilterProtoRE.FindStringSubmatch(line)
	if ipMatch == nil || portMatch == nil || protoMatch == nil {
		return request.Event{}, fmt.Errorf("parse netfilter log: expected SRC, DPT, and PROTO")
	}
	ip, err := netip.ParseAddr(ipMatch[1])
	if err != nil {
		return request.Event{}, fmt.Errorf("parse netfilter source IP %q: %w", ipMatch[1], err)
	}
	if _, err := strconv.Atoi(portMatch[1]); err != nil {
		return request.Event{}, fmt.Errorf("parse netfilter destination port %q: %w", portMatch[1], err)
	}
	timestamp, err := parseSecuritySyslogTimestamp(line)
	if err != nil {
		return request.Event{}, err
	}
	proto := strings.ToLower(protoMatch[1])
	return request.Event{Timestamp: timestamp, IP: ip, Method: "NETFILTER", Path: "/port/" + proto + "/" + portMatch[1], Protocol: proto, Status: 403, UserAgent: line}, nil
}

func parseSecuritySyslogTimestamp(line string) (time.Time, error) {
	if match := securityISOTimeRE.FindStringSubmatch(line); match != nil {
		timestamp, err := time.Parse(time.RFC3339Nano, match[1])
		if err != nil {
			return time.Time{}, fmt.Errorf("parse security ISO timestamp: %w", err)
		}
		return timestamp, nil
	}
	timeMatch := sshTimeRE.FindStringSubmatch(line)
	if timeMatch == nil {
		return time.Time{}, fmt.Errorf("parse security log timestamp: expected syslog timestamp")
	}
	timestamp, err := time.ParseInLocation("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s %s %s", time.Now().Year(), timeMatch[1], strings.TrimSpace(timeMatch[2]), timeMatch[3]), time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse security log timestamp: %w", err)
	}
	return timestamp, nil
}
