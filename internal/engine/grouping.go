package engine

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/it-nsk/antiddos/internal/request"
)

type GroupField string

const (
	GroupByIP        GroupField = "ip"
	GroupByUserAgent GroupField = "user_agent"
	GroupByMethod    GroupField = "method"
	GroupByPath      GroupField = "path"
	GroupByStatus    GroupField = "status"
)

type Grouping struct {
	ID     string
	Fields []GroupField
}

type GroupKey string

type keyBuilder func(request.Event) (GroupKey, []string)

func compileKeyBuilder(fields []GroupField) (keyBuilder, error) {
	extractors := make([]func(request.Event) string, len(fields))
	for index, field := range fields {
		switch field {
		case GroupByIP:
			extractors[index] = func(event request.Event) string {
				return event.IP.Unmap().String()
			}
		case GroupByUserAgent:
			extractors[index] = func(event request.Event) string { return event.UserAgent }
		case GroupByMethod:
			extractors[index] = func(event request.Event) string { return event.Method }
		case GroupByPath:
			extractors[index] = func(event request.Event) string { return event.Path }
		case GroupByStatus:
			extractors[index] = func(event request.Event) string { return strconv.Itoa(event.Status) }
		default:
			return nil, fmt.Errorf("unsupported group field %q", field)
		}
	}

	return func(event request.Event) (GroupKey, []string) {
		values := make([]string, len(extractors))
		for index, extract := range extractors {
			values[index] = extract(event)
		}
		encoded, _ := json.Marshal(values)
		return GroupKey(encoded), values
	}, nil
}
