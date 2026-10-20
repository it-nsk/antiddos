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
	SourceID              string
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
	samples map[sampleKey]Sample
}

type sampleKey struct {
	sourceID string
	bucket   int64
}

func NewCollector() *Collector {
	return &Collector{samples: make(map[sampleKey]Sample)}
}

func (collector *Collector) Add(sourceID string, event request.Event, matched bool) {
	intervalSeconds := int64(SampleInterval / time.Second)
	bucketStart := event.Timestamp.Unix() / intervalSeconds * intervalSeconds
	key := sampleKey{sourceID: sourceID, bucket: bucketStart}
	sample := collector.samples[key]
	sample.SourceID = sourceID
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
	collector.samples[key] = sample
}

func (collector *Collector) Flush(ctx context.Context, writer SampleWriter) error {
	if len(collector.samples) == 0 {
		return nil
	}

	keys := make([]sampleKey, 0, len(collector.samples))
	for key := range collector.samples {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].bucket == keys[right].bucket {
			return keys[left].sourceID < keys[right].sourceID
		}
		return keys[left].bucket < keys[right].bucket
	})

	samples := make([]Sample, 0, len(keys))
	for _, key := range keys {
		samples = append(samples, collector.samples[key])
	}
	if err := writer.WriteTrafficSamples(ctx, samples); err != nil {
		return err
	}
	clear(collector.samples)
	return nil
}
