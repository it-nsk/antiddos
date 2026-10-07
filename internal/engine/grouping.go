package engine

import (
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

type GroupKey string
type keyBuilder func(request.Event) (GroupKey, string)

func compileKeyBuilder(field GroupField) (keyBuilder, error) {
	var extract func(request.Event) string
	switch field {
	case GroupByIP:
		extract = func(event request.Event) string { return event.IP.Unmap().String() }
	case GroupByUserAgent:
		extract = func(event request.Event) string { return event.UserAgent }
	case GroupByMethod:
		extract = func(event request.Event) string { return event.Method }
	case GroupByPath:
		extract = func(event request.Event) string { return event.Path }
	case GroupByStatus:
		extract = func(event request.Event) string { return strconv.Itoa(event.Status) }
	default:
		return nil, fmt.Errorf("unsupported group field %q", field)
	}
	return func(event request.Event) (GroupKey, string) {
		value := extract(event)
		return GroupKey(value), value
	}, nil
}
