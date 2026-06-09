package reqrate

import (
	"bufio"
	"io"
	"sync"
	"time"
)

// Counter accumulates per-host request counts for the current interval. The
// live tailer feeds it via Add from a single goroutine while the collector
// drains it via Snapshot on each tick; the mutex makes that hand-off safe.
type Counter struct {
	mu     sync.Mutex
	counts map[string]int64
}

// NewCounter returns an empty per-host counter.
func NewCounter() *Counter {
	return &Counter{counts: make(map[string]int64)}
}

// Add records one request against host.
func (c *Counter) Add(host string) {
	c.mu.Lock()
	c.counts[host]++
	c.mu.Unlock()
}

// Snapshot returns per-host requests-per-second over interval and resets the
// counter for the next window. It returns nil (and still resets) when there is
// nothing to report or interval is non-positive — the latter guards against a
// div-by-zero from a misconfigured tick.
func (c *Counter) Snapshot(interval time.Duration) map[string]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.counts
	c.counts = make(map[string]int64)
	if interval <= 0 || len(prev) == 0 {
		return nil
	}
	secs := interval.Seconds()
	out := make(map[string]float64, len(prev))
	for h, n := range prev {
		out[h] = float64(n) / secs
	}
	return out
}

// Scan reads newline-delimited JSON access-log records from r, extracting each
// record's host and adding it to counter. Lines that aren't access records (or
// carry no host) are skipped. Returns the number of records counted.
//
// The live tailer (a later slice) calls Scan on the growing access-log file;
// tests call it on an in-memory reader of captured lines. Either way the
// parsing/counting path is identical.
func Scan(r io.Reader, counter *Counter) (int, error) {
	sc := bufio.NewScanner(r)
	// Access-log lines can be long (full request/response detail); raise the
	// scanner's max token size well above the 64 KiB default.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	n := 0
	for sc.Scan() {
		host, ok := ParseHost(sc.Bytes())
		if !ok {
			continue
		}
		counter.Add(host)
		n++
	}
	return n, sc.Err()
}
