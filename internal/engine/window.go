package engine

import "time"

const compactWindowHead = 1024

type timestampWindow struct {
	timestamps  []time.Time
	values      []string
	head        int
	key         GroupKey
	expiresAt   time.Time
	expiryIndex int
}

func (window *timestampWindow) prune(cutoff time.Time) {
	for window.head < len(window.timestamps) && !window.timestamps[window.head].After(cutoff) {
		window.timestamps[window.head] = time.Time{}
		if len(window.values) > window.head {
			window.values[window.head] = ""
		}
		window.head++
	}

	remaining := len(window.timestamps) - window.head
	if remaining == 0 {
		window.timestamps = nil
		window.values = nil
		window.head = 0
		return
	}
	if window.head >= compactWindowHead && window.head >= len(window.timestamps)/2 {
		compacted := make([]time.Time, remaining)
		copy(compacted, window.timestamps[window.head:])
		window.timestamps = compacted
		if len(window.values) > 0 {
			values := make([]string, remaining)
			copy(values, window.values[window.head:])
			window.values = values
		}
		window.head = 0
	}
}

func (window *timestampWindow) append(timestamp time.Time) {
	window.timestamps = append(window.timestamps, timestamp)
	window.values = append(window.values, "")
}

func (window *timestampWindow) appendValue(timestamp time.Time, value string) {
	window.timestamps = append(window.timestamps, timestamp)
	window.values = append(window.values, value)
}
func (window *timestampWindow) uniqueLen() int {
	seen := map[string]struct{}{}
	for _, v := range window.values[window.head:] {
		seen[v] = struct{}{}
	}
	return len(seen)
}

func (window *timestampWindow) len() int {
	return len(window.timestamps) - window.head
}
