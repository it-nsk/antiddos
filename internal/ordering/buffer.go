package ordering

import (
	"container/heap"
	"fmt"
	"time"

	"github.com/it-nsk/antiddos/internal/request"
)

type PushResult struct {
	Ready        []request.Event
	Immediate    request.Event
	HasImmediate bool
	Late         bool
}

type Buffer struct {
	allowedLateness time.Duration
	maxPending      int
	pending         eventHeap
	sequence        uint64
	maxSeen         time.Time
	hasMaxSeen      bool
	lastEmitted     time.Time
	hasLastEmitted  bool
}

type pendingEvent struct {
	event      request.Event
	sequence   uint64
	receivedAt time.Time
}

type eventHeap []pendingEvent

func New(allowedLateness time.Duration, maxPending int) (*Buffer, error) {
	if allowedLateness < 0 {
		return nil, fmt.Errorf("allowed lateness must not be negative")
	}
	if maxPending < 1 {
		return nil, fmt.Errorf("max pending events must be at least 1")
	}
	return &Buffer{allowedLateness: allowedLateness, maxPending: maxPending}, nil
}

func (buffer *Buffer) Push(event request.Event, now time.Time) (PushResult, error) {
	if buffer.allowedLateness == 0 {
		timestamp := event.Timestamp.UTC()
		if buffer.hasLastEmitted && timestamp.Before(buffer.lastEmitted) {
			return PushResult{Late: true}, nil
		}
		buffer.lastEmitted = timestamp
		buffer.hasLastEmitted = true
		buffer.maxSeen = timestamp
		buffer.hasMaxSeen = true
		return PushResult{Immediate: event, HasImmediate: true}, nil
	}

	result := PushResult{Ready: buffer.DrainReady(now)}
	timestamp := event.Timestamp.UTC()
	if buffer.hasLastEmitted && timestamp.Before(buffer.lastEmitted) {
		result.Late = true
		return result, nil
	}
	if len(buffer.pending) >= buffer.maxPending {
		return result, fmt.Errorf("ordering buffer reached max_pending_events=%d", buffer.maxPending)
	}

	buffer.sequence++
	heap.Push(&buffer.pending, pendingEvent{
		event:      event,
		sequence:   buffer.sequence,
		receivedAt: now,
	})
	if !buffer.hasMaxSeen || timestamp.After(buffer.maxSeen) {
		buffer.maxSeen = timestamp
		buffer.hasMaxSeen = true
	}
	result.Ready = append(result.Ready, buffer.DrainReady(now)...)
	return result, nil
}

func (buffer *Buffer) DrainReady(now time.Time) []request.Event {
	var ready []request.Event
	for len(buffer.pending) > 0 {
		oldest := buffer.pending[0]
		timestamp := oldest.event.Timestamp.UTC()
		readyByEventTime := buffer.hasMaxSeen && !timestamp.After(buffer.maxSeen.Add(-buffer.allowedLateness))
		readyByAge := !now.Before(oldest.receivedAt.Add(buffer.allowedLateness))
		if !readyByEventTime && !readyByAge {
			break
		}
		item := heap.Pop(&buffer.pending).(pendingEvent)
		buffer.lastEmitted = item.event.Timestamp.UTC()
		buffer.hasLastEmitted = true
		ready = append(ready, item.event)
	}
	return ready
}

func (buffer *Buffer) Flush() []request.Event {
	ready := make([]request.Event, 0, len(buffer.pending))
	for len(buffer.pending) > 0 {
		item := heap.Pop(&buffer.pending).(pendingEvent)
		buffer.lastEmitted = item.event.Timestamp.UTC()
		buffer.hasLastEmitted = true
		ready = append(ready, item.event)
	}
	return ready
}

func (buffer *Buffer) Pending() int {
	return len(buffer.pending)
}

func (events eventHeap) Len() int { return len(events) }

func (events eventHeap) Less(left, right int) bool {
	leftTime := events[left].event.Timestamp
	rightTime := events[right].event.Timestamp
	if leftTime.Equal(rightTime) {
		return events[left].sequence < events[right].sequence
	}
	return leftTime.Before(rightTime)
}

func (events eventHeap) Swap(left, right int) {
	events[left], events[right] = events[right], events[left]
}

func (events *eventHeap) Push(value any) {
	*events = append(*events, value.(pendingEvent))
}

func (events *eventHeap) Pop() any {
	old := *events
	last := len(old) - 1
	item := old[last]
	old[last] = pendingEvent{}
	*events = old[:last]
	return item
}
