// Package parser converts supported Nginx access-log lines into request events.
package parser

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/it-nsk/antiddos/internal/request"
)

const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// ParseNginx parses the combined-format fields used by the configured website.
// Quoted fields after User-Agent are accepted because the real log contains
// both the base format and variants extended with request time and host.
func ParseNginx(line string) (request.Event, error) {
	fields := fieldScanner{line: line}

	ipText, err := fields.bare("client IP")
	if err != nil {
		return request.Event{}, err
	}
	if _, err := fields.bare("remote identity"); err != nil {
		return request.Event{}, err
	}
	if _, err := fields.bare("remote user"); err != nil {
		return request.Event{}, err
	}
	timestampText, err := fields.delimited('[', ']', "timestamp")
	if err != nil {
		return request.Event{}, err
	}
	requestText, err := fields.quoted("request")
	if err != nil {
		return request.Event{}, err
	}
	statusText, err := fields.bare("status")
	if err != nil {
		return request.Event{}, err
	}
	bytesText, err := fields.bare("response bytes")
	if err != nil {
		return request.Event{}, err
	}
	if _, err := fields.quoted("referer"); err != nil {
		return request.Event{}, err
	}
	userAgent, err := fields.quoted("User-Agent")
	if err != nil {
		return request.Event{}, err
	}
	for !fields.done() {
		if _, err := fields.quoted("extension field"); err != nil {
			return request.Event{}, err
		}
	}

	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return request.Event{}, fmt.Errorf("parse client IP %q: %w", ipText, err)
	}
	timestamp, err := time.Parse(nginxTimeLayout, timestampText)
	if err != nil {
		return request.Event{}, fmt.Errorf("parse timestamp %q: %w", timestampText, err)
	}

	requestParts := strings.Fields(requestText)
	if len(requestParts) != 3 {
		return request.Event{}, fmt.Errorf("parse request %q: expected method, target, and protocol", requestText)
	}
	requestURL, err := url.ParseRequestURI(requestParts[1])
	if err != nil {
		return request.Event{}, fmt.Errorf("parse request target %q: %w", requestParts[1], err)
	}
	// Query keeps all safely decoded pairs. RawQuery remains available when a
	// malformed pair is skipped, so an unusual query never discards the event.
	query := requestURL.Query()

	status, err := strconv.Atoi(statusText)
	if err != nil || status < 100 || status > 999 {
		return request.Event{}, fmt.Errorf("parse status %q: expected a three-digit HTTP status", statusText)
	}

	responseBytes, err := parseOptionalBytes(bytesText)
	if err != nil {
		return request.Event{}, err
	}

	return request.Event{
		Timestamp:     timestamp,
		IP:            ip,
		Method:        requestParts[0],
		Path:          requestURL.EscapedPath(),
		RawQuery:      requestURL.RawQuery,
		Query:         query,
		Protocol:      requestParts[2],
		Status:        status,
		ResponseBytes: responseBytes,
		UserAgent:     unescapeNginx(userAgent),
	}, nil
}

func parseOptionalBytes(value string) (*int64, error) {
	if value == "-" {
		return nil, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return nil, fmt.Errorf("parse response bytes %q: expected a non-negative integer or '-'", value)
	}
	return &parsed, nil
}

type fieldScanner struct {
	line string
	pos  int
}

func (s *fieldScanner) bare(name string) (string, error) {
	s.skipSpaces()
	start := s.pos
	for s.pos < len(s.line) && s.line[s.pos] != ' ' && s.line[s.pos] != '\t' {
		s.pos++
	}
	if start == s.pos {
		return "", fmt.Errorf("parse %s at byte %d: expected a value", name, s.pos)
	}
	return s.line[start:s.pos], nil
}

func (s *fieldScanner) quoted(name string) (string, error) {
	return s.delimited('"', '"', name)
}

func (s *fieldScanner) delimited(open, close byte, name string) (string, error) {
	s.skipSpaces()
	if s.pos >= len(s.line) || s.line[s.pos] != open {
		return "", fmt.Errorf("parse %s at byte %d: expected %q", name, s.pos, open)
	}
	s.pos++
	start := s.pos
	for s.pos < len(s.line) {
		if open == '"' && s.line[s.pos] == '\\' {
			s.pos++
			if s.pos < len(s.line) {
				s.pos++
			}
			continue
		}
		if s.line[s.pos] == close {
			value := s.line[start:s.pos]
			s.pos++
			return value, nil
		}
		s.pos++
	}
	return "", fmt.Errorf("parse %s at byte %d: missing closing %q", name, start-1, close)
}

func (s *fieldScanner) done() bool {
	s.skipSpaces()
	return s.pos == len(s.line)
}

func (s *fieldScanner) skipSpaces() {
	for s.pos < len(s.line) && (s.line[s.pos] == ' ' || s.line[s.pos] == '\t') {
		s.pos++
	}
}

func unescapeNginx(value string) string {
	if !strings.Contains(value, "\\") {
		return value
	}

	var result strings.Builder
	result.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			result.WriteByte(value[i])
			continue
		}

		switch value[i+1] {
		case '\\', '"':
			result.WriteByte(value[i+1])
			i++
		case 'x':
			if i+3 < len(value) {
				decoded, err := strconv.ParseUint(value[i+2:i+4], 16, 8)
				if err == nil {
					result.WriteByte(byte(decoded))
					i += 3
					continue
				}
			}
			result.WriteByte(value[i])
		default:
			result.WriteByte(value[i])
		}
	}
	return result.String()
}
