package engine

import "time"

const compactWindowHead = 1024

type timestampWindow struct {
	timestamps []time.Time
	head       int
}

func (window *timestampWindow) prune(cutoff time.Time) {
	for window.head < len(window.timestamps) && !window.timestamps[window.head].After(cutoff) {
		window.timestamps[window.head] = time.Time{}
		window.head++
	}

	remaining := len(window.timestamps) - window.head
	if remaining == 0 {
		window.timestamps = nil
		window.head = 0
		return
	}
	if window.head >= compactWindowHead && window.head >= len(window.timestamps)/2 {
		compacted := make([]time.Time, remaining)
		copy(compacted, window.timestamps[window.head:])
		window.timestamps = compacted
		window.head = 0
	}
}

func (window *timestampWindow) append(timestamp time.Time) {
	window.timestamps = append(window.timestamps, timestamp)
}

func (window *timestampWindow) len() int {
	return len(window.timestamps) - window.head
}
