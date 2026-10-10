package modelgateway

import "sync"

// Fixed bucket bounds for the hold histograms (#2454). Seconds span a quick
// answer to the 120 s write ceiling and beyond; bytes span a short reply to
// the default 8 MiB hold limit.
var (
	holdSecondsBounds = []float64{1, 5, 15, 30, 60, 120, 300}
	holdBytesBounds   = []float64{1 << 10, 64 << 10, 1 << 20, 4 << 20, 8 << 20}
)

// HistBucket is one cumulative bucket: Count observations were <= Le.
type HistBucket struct {
	Le    float64 `json:"le"`
	Count uint64  `json:"count"`
}

// Histogram is a cumulative histogram snapshot. Count includes observations
// above the last bound.
type Histogram struct {
	Buckets []HistBucket `json:"buckets"`
	Count   uint64       `json:"count"`
	Sum     float64      `json:"sum"`
	Max     float64      `json:"max"`
}

type histogram struct {
	mu     sync.Mutex
	bounds []float64
	counts []uint64 // per bound; observations above the last bound only raise count
	count  uint64
	sum    float64
	max    float64
}

func newHistogram(bounds []float64) *histogram {
	return &histogram{bounds: bounds, counts: make([]uint64, len(bounds))}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	h.sum += v
	if v > h.max {
		h.max = v
	}
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i]++
			return
		}
	}
}

func (h *histogram) snapshot() Histogram {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := Histogram{Buckets: make([]HistBucket, len(h.bounds)), Count: h.count, Sum: h.sum, Max: h.max}
	var cum uint64
	for i, b := range h.bounds {
		cum += h.counts[i]
		out.Buckets[i] = HistBucket{Le: b, Count: cum}
	}
	return out
}
