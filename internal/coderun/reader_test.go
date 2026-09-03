package coderun

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a mutex-guarded bytes.Buffer: StreamOutput writes from its
// own goroutine while tests poll the accumulated output from the test
// goroutine, and bytes.Buffer alone isn't safe for that.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// fakeReader is a deterministic, seeded stand-in for a real tail_log
// transport (#1674 design doc, Part B1: "that seam is the whole design for
// testability"). It serves a fixed underlying byte string from an
// in-memory offset, optionally failing on a seeded schedule and optionally
// capping reads to simulate tail_log's 256 KiB truncation.
type fakeReader struct {
	data []byte

	// failEveryN, when > 0, fails (a transient transport error) every Nth
	// call rather than serving data — the seed for a reproducible drop
	// schedule.
	failEveryN int
	calls      int

	// capBytes, when > 0, caps a single successful read to at most this
	// many bytes and reports truncated=true when more data remains —
	// simulating tailLogOutputLimit.
	capBytes int
}

func (f *fakeReader) Read(_ context.Context, _ string, startOffset int64, _ time.Duration) ([]byte, int64, bool, error) {
	f.calls++
	if f.failEveryN > 0 && f.calls%f.failEveryN == 0 {
		return nil, startOffset, false, errors.New("simulated transport failure")
	}
	if startOffset >= int64(len(f.data)) {
		return nil, startOffset, false, nil // caught up, nothing new yet
	}
	end := int64(len(f.data))
	truncated := false
	if f.capBytes > 0 && end-startOffset > int64(f.capBytes) {
		end = startOffset + int64(f.capBytes)
		truncated = true
	}
	return f.data[startOffset:end], end, truncated, nil
}

func TestStreamOutput_CleanRead(t *testing.T) {
	r := &fakeReader{data: []byte("hello world")}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := StreamOutput(ctx, r, &out, "log", 0, 10*time.Millisecond, nil)
		done <- err
	}()

	waitForContent(t, &out, "hello world")
	cancel()
	<-done

	if out.String() != "hello world" {
		t.Errorf("out = %q, want %q", out.String(), "hello world")
	}
}

// TestStreamOutput_RetriesFromSameOffsetOnTransportError is the core
// north-star property: a transport failure must never skip ahead or
// duplicate — the next successful read after N failures resumes at
// EXACTLY the offset the last successful read left off at.
func TestStreamOutput_RetriesFromSameOffsetOnTransportError(t *testing.T) {
	r := &fakeReader{data: []byte("no bytes lost or duplicated"), failEveryN: 3}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())

	var errCount int
	done := make(chan error, 1)
	go func() {
		_, err := StreamOutput(ctx, r, &out, "log", 0, 10*time.Millisecond, func(error) { errCount++ })
		done <- err
	}()

	waitForContent(t, &out, "no bytes lost or duplicated")
	cancel()
	<-done

	if out.String() != "no bytes lost or duplicated" {
		t.Errorf("out = %q, want exact content with no loss/duplication", out.String())
	}
	if errCount == 0 {
		t.Error("expected at least one simulated transport error to have been observed")
	}
}

// TestStreamOutput_SurvivesTwentyForcedDrops pins the PRD's own north-star
// metric directly: "0 bytes missing or duplicated across >= 20 forced
// mid-run disconnects."
func TestStreamOutput_SurvivesTwentyForcedDrops(t *testing.T) {
	// A generator that is NOT a repeating/constant pattern — per the design
	// doc, a constant stream can't distinguish loss from duplication.
	rng := rand.New(rand.NewSource(1))
	var want bytes.Buffer
	for i := 0; i < 4000; i++ {
		want.WriteByte("abcdefghijklmnopqrstuvwxyz"[rng.Intn(26)])
	}

	// capBytes forces many small reads to drain 4000 bytes (rather than one
	// big read), so failEveryN actually gets enough opportunities to fire
	// >=20 times, matching "across >=20 forced mid-run disconnects".
	r := &fakeReader{data: want.Bytes(), failEveryN: 7, capBytes: 100}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := StreamOutput(ctx, r, &out, "log", 0, time.Millisecond, nil)
		done <- err
	}()

	waitForContent(t, &out, want.String())
	cancel()
	<-done

	if out.String() != want.String() {
		// Report the first divergent byte offset, not the whole (large) strings.
		got := out.String()
		i := 0
		for i < len(got) && i < want.Len() && got[i] == want.String()[i] {
			i++
		}
		t.Fatalf("diverges at byte %d: got %q..., want %q...", i, safeSlice(got, i), safeSlice(want.String(), i))
	}
	if r.calls < 20 {
		t.Errorf("only %d Read calls; want enough to actually exercise repeated drops", r.calls)
	}
}

func safeSlice(s string, from int) string {
	end := from + 20
	if end > len(s) {
		end = len(s)
	}
	if from > len(s) {
		from = len(s)
	}
	return s[from:end]
}

// TestStreamOutput_TruncatedRereadsImmediately is the explicit AC: on
// truncated:true the client re-reads immediately rather than sleeping the
// poll interval. Uses a long follow/poll duration and a small capBytes —
// if StreamOutput slept between the capped reads, catching up would take
// several multiples of that duration; asserts it doesn't.
func TestStreamOutput_TruncatedRereadsImmediately(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 10_000)
	r := &fakeReader{data: data, capBytes: 500}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())

	longPoll := 2 * time.Second
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := StreamOutput(ctx, r, &out, "log", 0, longPoll, nil)
		done <- err
	}()

	waitForContentLen(t, &out, len(data))
	elapsed := time.Since(start)
	cancel()
	<-done

	if elapsed > 500*time.Millisecond {
		t.Errorf("catching up 20 capped reads took %s — truncated:true must re-read immediately, not sleep %s each time", elapsed, longPoll)
	}
	if out.Len() != len(data) {
		t.Errorf("out.Len() = %d, want %d (nothing silently dropped at the cap)", out.Len(), len(data))
	}
}

func waitForContent(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for output to contain %q, got %q", want, out.String())
}

func waitForContentLen(t *testing.T, out *syncBuffer, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if out.Len() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d bytes of output, got %d", n, out.Len())
}
