// Package metrics accumulates request totals into event-time buckets.
package metrics

import (
	"context"
	"sort"
	"time"

	"github.com/it-nsk/antiddos/internal/request"
)

const SampleInterval = 15 * time.Second

type Sample struct {
	BucketStartUnix       int64
	IntervalSeconds       int64
	Requests              int64
	MatchedRequests       int64
	ResponseBytes         int64
	KnownResponseByteRows int64
}

type SampleWriter interface {
	WriteTrafficSamples(context.Context, []Sample) error
}

type Collector struct {
	samples map[int64]Sample
}

func NewCollector() *Collector {
	return &Collector{samples: make(map[int64]Sample)}
}

func (collector *Collector) Add(event request.Event, matched bool) {
	intervalSeconds := int64(SampleInterval / time.Second)
	bucketStart := event.Timestamp.Unix() / intervalSeconds * intervalSeconds
	sample := collector.samples[bucketStart]
	sample.BucketStartUnix = bucketStart
	sample.IntervalSeconds = intervalSeconds
	sample.Requests++
	if matched {
		sample.MatchedRequests++
	}
	if event.ResponseBytes != nil {
		sample.ResponseBytes += *event.ResponseBytes
		sample.KnownResponseByteRows++
	}
	collector.samples[bucketStart] = sample
}

func (collector *Collector) Flush(ctx context.Context, writer SampleWriter) error {
	if len(collector.samples) == 0 {
		return nil
	}

	bucketStarts := make([]int64, 0, len(collector.samples))
	for bucketStart := range collector.samples {
		bucketStarts = append(bucketStarts, bucketStart)
	}
	sort.Slice(bucketStarts, func(left, right int) bool {
		return bucketStarts[left] < bucketStarts[right]
	})

	samples := make([]Sample, 0, len(bucketStarts))
	for _, bucketStart := range bucketStarts {
		samples = append(samples, collector.samples[bucketStart])
	}
	if err := writer.WriteTrafficSamples(ctx, samples); err != nil {
		return err
	}
	clear(collector.samples)
	return nil
}
