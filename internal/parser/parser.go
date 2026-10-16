package parser

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/it-nsk/antiddos/internal/request"
)

const (
	FormatNginxCombined = "nginx_combined"
	FormatNginxCustom   = "nginx_custom"
)

// Parser converts one source line into one normalized HTTP request event.
// Parser instances are compiled once during startup and reused for every line.
type Parser interface {
	Parse(string) (request.Event, error)
}

type nginxCombinedParser struct{}

func (nginxCombinedParser) Parse(line string) (request.Event, error) { return ParseNginx(line) }

// New constructs a parser for one log source. logFormat may be the complete
// Nginx log_format directive or its quoted format string(s).
func New(format, logFormat string) (Parser, error) {
	switch format {
	case "", FormatNginxCombined:
		if logFormat != "" {
			return nil, fmt.Errorf("log_format is only valid for %s", FormatNginxCustom)
		}
		return nginxCombinedParser{}, nil
	case FormatNginxCustom:
		return newCustomNginxParser(logFormat)
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
}

type customNginxParser struct {
	linePattern *regexp.Regexp
	fields      map[string]string // normalized event field -> Nginx variable
	fieldGroups map[string]int    // normalized event field -> regexp subexpression
}

func newCustomNginxParser(directive string) (Parser, error) {
	template, err := extractNginxFormat(directive)
	if err != nil {
		return nil, err
	}
	variables, literals, err := splitNginxTemplate(template)
	if err != nil {
		return nil, err
	}
	if len(variables) == 0 {
		return nil, fmt.Errorf("log_format has no Nginx variables")
	}

	var pattern strings.Builder
	pattern.WriteByte('^')
	fields := make(map[string]string)
	for index, variable := range variables {
		pattern.WriteString(regexp.QuoteMeta(literals[index]))
		capture := "(?P<f" + strconv.Itoa(index) + ">.*?)"
		if strings.HasPrefix(literals[index+1], `"`) {
			// A quoted Nginx value may contain escaped quotes. Keep those inside
			// the field rather than treating them as the closing delimiter.
			capture = "(?P<f" + strconv.Itoa(index) + ">([^\\\"]|\\\\.)*)"
		}
		pattern.WriteString(capture)
		if field := normalizedField(variable); field != "" {
			if previous, exists := fields[field]; exists {
				return nil, fmt.Errorf("log_format maps both $%s and $%s to the same event field", previous, variable)
			}
			fields[field] = variable
		}
	}
	pattern.WriteString(regexp.QuoteMeta(literals[len(literals)-1]))
	pattern.WriteByte('$')
	compiled, err := regexp.Compile(pattern.String())
	if err != nil {
		return nil, fmt.Errorf("compile log_format: %w", err)
	}
	groupByName := make(map[string]int)
	for index, name := range compiled.SubexpNames() {
		if name != "" {
			groupByName[name] = index
		}
	}
	fieldGroups := make(map[string]int, len(fields))
	for field, variable := range fields {
		for index, name := range variables {
			if name == variable {
				fieldGroups[field] = groupByName["f"+strconv.Itoa(index)]
				break
			}
		}
	}
	if _, ok := fields["ip"]; !ok {
		return nil, fmt.Errorf("log_format must include $remote_addr")
	}
	if _, local := fields["time_local"]; !local {
		if _, iso := fields["time_iso8601"]; !iso {
			if _, msec := fields["msec"]; !msec {
				return nil, fmt.Errorf("log_format must include $time_local, $time_iso8601, or $msec")
			}
		}
	}
	if _, ok := fields["status"]; !ok {
		return nil, fmt.Errorf("log_format must include $status")
	}
	if _, requestLine := fields["request"]; !requestLine {
		if _, method := fields["method"]; !method {
			return nil, fmt.Errorf("log_format must include $request or both $request_method and $uri/$request_uri")
		}
		if _, uri := fields["uri"]; !uri {
			if _, requestURI := fields["request_uri"]; !requestURI {
				return nil, fmt.Errorf("log_format must include $request or both $request_method and $uri/$request_uri")
			}
		}
	}
	return &customNginxParser{linePattern: compiled, fields: fields, fieldGroups: fieldGroups}, nil
}

func (parser *customNginxParser) Parse(line string) (request.Event, error) {
	match := parser.linePattern.FindStringSubmatch(line)
	if match == nil {
		return request.Event{}, fmt.Errorf("line does not match configured Nginx log_format")
	}
	values := make(map[string]string, len(parser.fields))
	for field, group := range parser.fieldGroups {
		if group >= 0 && group < len(match) {
			values[field] = match[group]
		}
	}
	return eventFromFields(values)
}

func eventFromFields(values map[string]string) (request.Event, error) {
	address, err := netip.ParseAddr(values["ip"])
	if err != nil {
		return request.Event{}, fmt.Errorf("parse client IP %q: %w", values["ip"], err)
	}
	timestamp, err := parseNginxTimestamp(values)
	if err != nil {
		return request.Event{}, err
	}
	method, target, protocol := values["method"], "", ""
	if requestLine := values["request"]; requestLine != "" {
		parts := strings.Fields(requestLine)
		if len(parts) != 3 {
			return request.Event{}, fmt.Errorf("parse request %q: expected method, target, and protocol", requestLine)
		}
		method, target, protocol = parts[0], parts[1], parts[2]
	} else {
		target = values["request_uri"]
		if target == "" {
			target = values["uri"]
		}
	}
	requestURL, err := url.ParseRequestURI(target)
	if err != nil {
		return request.Event{}, fmt.Errorf("parse request target %q: %w", target, err)
	}
	status, err := strconv.Atoi(values["status"])
	if err != nil || status < 100 || status > 999 {
		return request.Event{}, fmt.Errorf("parse status %q: expected a three-digit HTTP status", values["status"])
	}
	var responseBytes *int64
	bytesField := values["body_bytes_sent"]
	if bytesField == "" {
		bytesField = values["bytes_sent"]
	}
	if bytesField != "" {
		responseBytes, err = parseOptionalBytes(bytesField)
		if err != nil {
			return request.Event{}, err
		}
	}
	if protocol == "" {
		protocol = "-"
	}
	return request.Event{
		Timestamp: timestamp, IP: address, Method: method, Path: requestURL.EscapedPath(),
		RawQuery: requestURL.RawQuery, Query: requestURL.Query(), Protocol: protocol,
		Status: status, ResponseBytes: responseBytes,
		UserAgent: unescapeNginx(values["http_user_agent"]),
	}, nil
}

func normalizedField(variable string) string {
	switch variable {
	case "remote_addr":
		return "ip"
	case "time_local":
		return "time_local"
	case "time_iso8601":
		return "time_iso8601"
	case "msec":
		return "msec"
	case "request":
		return "request"
	case "request_method":
		return "method"
	case "uri":
		return "uri"
	case "request_uri":
		return "request_uri"
	case "status":
		return "status"
	case "body_bytes_sent":
		return "body_bytes_sent"
	case "bytes_sent":
		return "bytes_sent"
	case "http_user_agent":
		return "http_user_agent"
	default:
		return ""
	}
}

func parseNginxTimestamp(values map[string]string) (time.Time, error) {
	if value := values["time_local"]; value != "" {
		timestamp, err := time.Parse(nginxTimeLayout, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse timestamp %q: %w", value, err)
		}
		return timestamp, nil
	}
	if value := values["time_iso8601"]; value != "" {
		timestamp, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse timestamp %q: %w", value, err)
		}
		return timestamp, nil
	}
	seconds, err := strconv.ParseFloat(values["msec"], 64)
	if err != nil || seconds < 0 {
		return time.Time{}, fmt.Errorf("parse timestamp %q: expected Unix seconds", values["msec"])
	}
	whole, fraction := int64(seconds), seconds-float64(int64(seconds))
	return time.Unix(whole, int64(fraction*float64(time.Second))), nil
}

func splitNginxTemplate(template string) ([]string, []string, error) {
	variables := make([]string, 0, 10)
	literals := make([]string, 0, 11)
	var literal strings.Builder
	for index := 0; index < len(template); {
		if template[index] != '$' {
			literal.WriteByte(template[index])
			index++
			continue
		}
		if index+1 < len(template) && template[index+1] == '$' {
			literal.WriteByte('$')
			index += 2
			continue
		}
		start := index
		index++
		var name string
		if index < len(template) && template[index] == '{' {
			close := strings.IndexByte(template[index+1:], '}')
			if close < 0 {
				return nil, nil, fmt.Errorf("log_format: unterminated ${variable}")
			}
			name = template[index+1 : index+1+close]
			index += close + 2
		} else {
			for index < len(template) && (template[index] == '_' || template[index] >= '0' && template[index] <= '9' || template[index] >= 'A' && template[index] <= 'Z' || template[index] >= 'a' && template[index] <= 'z') {
				index++
			}
			name = template[start+1 : index]
		}
		if name == "" {
			literal.WriteByte('$')
			continue
		}
		literals = append(literals, literal.String())
		literal.Reset()
		variables = append(variables, name)
	}
	literals = append(literals, literal.String())
	for index := 1; index < len(literals)-1; index++ {
		if literals[index] == "" {
			return nil, nil, fmt.Errorf("log_format has adjacent variables without a delimiter")
		}
	}
	return variables, literals, nil
}

func extractNginxFormat(input string) (string, error) {
	text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(input), ";"))
	fromDirective := strings.HasPrefix(text, "log_format")
	if fromDirective {
		text = strings.TrimSpace(strings.TrimPrefix(text, "log_format"))
		space := strings.IndexAny(text, " \t\r\n")
		if space <= 0 {
			return "", fmt.Errorf("log_format directive must include a format name and quoted body")
		}
		text = strings.TrimSpace(text[space:])
		if strings.HasPrefix(text, "escape=") {
			space = strings.IndexAny(text, " \t\r\n")
			if space < 0 {
				return "", fmt.Errorf("log_format directive is missing its body")
			}
			text = strings.TrimSpace(text[space:])
		}
	}
	parseQuotedParts := fromDirective || strings.HasPrefix(text, "'") || strings.HasPrefix(text, `"`)
	if !parseQuotedParts {
		return text, nil
	}
	var result strings.Builder
	for index := 0; index < len(text); {
		for index < len(text) && (text[index] == ' ' || text[index] == '\t' || text[index] == '\r' || text[index] == '\n') {
			index++
		}
		if index == len(text) {
			break
		}
		quote := text[index]
		if quote != '\'' && quote != '"' {
			return "", fmt.Errorf("log_format: expected quoted body near %q", text[index:])
		}
		index++
		closed := false
		for index < len(text) {
			char := text[index]
			index++
			if char == quote {
				closed = true
				break
			}
			if char == '\\' && index < len(text) {
				next := text[index]
				if next == quote || next == '\\' || next == '\'' || next == '"' {
					result.WriteByte(next)
					index++
					continue
				}
				// Nginx ignores a backslash before an ordinary character in
				// configuration strings.
				index++
				result.WriteByte(next)
				continue
			}
			result.WriteByte(char)
		}
		if !closed {
			return "", fmt.Errorf("log_format: unterminated quoted body")
		}
	}
	if result.Len() == 0 {
		return "", fmt.Errorf("log_format body is empty")
	}
	return result.String(), nil
}
