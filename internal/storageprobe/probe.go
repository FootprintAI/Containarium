// Package storageprobe measures whether one tenant's writeback stalls another
// tenant's fsync on a shared backend.
//
// It exists because the obvious health check is worse than useless here. On
// the failure in #1206 — every tenant rootfs on one filesystem, so every
// tenant on one ext4 jbd2 journal — an idle latency probe reports the affected
// containers as the *fastest* storage in the fleet:
//
//	affected tenant, idle .................... 17 ms
//	physical host, same partition ............ 46 ms
//	a ZFS-backed backend, busy .............. 196 ms
//	affected tenant, under co-tenant load .. 11,885 ms
//
// Only the baseline-to-under-load ratio distinguishes them, which is why
// Classify reports a ratio and why a single number from Probe is not a health
// signal on its own.
//
// The second trap is in the load generator. The trigger is co-tenant
// dirty-page *volume*, not fsync frequency: four tight fsync loops writing
// 4 KiB moved the probe to 32 ms, while eight workers writing 64 MiB buffered
// then syncing produced 11,885 ms. Load therefore writes at volume between
// syncs, and a test pins that ratio so the generator cannot quietly regress
// into the pattern that does not reproduce the bug.
package storageprobe

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Result is one probe run: how many write+fsync operations, and how long they
// took in total.
type Result struct {
	Ops   int
	Total time.Duration
}

// PerOp is the mean latency of a single write+fsync. Zero when nothing ran.
func (r Result) PerOp() time.Duration {
	if r.Ops <= 0 {
		return 0
	}
	return r.Total / time.Duration(r.Ops)
}

// Verdict is the classification of a baseline/under-load pair.
type Verdict int

const (
	// VerdictUnknown means the pair could not be classified — typically an
	// unusable baseline. Deliberately not "isolated": a failed measurement
	// must not read as a clean bill of health.
	VerdictUnknown Verdict = iota

	// VerdictIsolated: co-tenant load did not meaningfully affect this
	// tenant's fsync latency.
	VerdictIsolated

	// VerdictDegraded: a real slowdown under co-tenant load, short of the
	// order-of-magnitude collapse a shared journal produces.
	VerdictDegraded

	// VerdictSevere: fsync latency collapsed under co-tenant load. The
	// signature of tenants sharing one filesystem journal.
	VerdictSevere
)

func (v Verdict) String() string {
	switch v {
	case VerdictIsolated:
		return "isolated"
	case VerdictDegraded:
		return "degraded"
	case VerdictSevere:
		return "severe"
	default:
		return "unknown"
	}
}

// Ratio thresholds. Set from the measurements in #1206: the tight-fsync load
// that did NOT reproduce the stall reached ~1.9x and must stay "isolated", so
// degradedRatio sits well above it; the real stall was ~700x, far past
// severeRatio. The gap between them is deliberately wide — a probe that
// flagged ordinary load variance would be one operators learn to ignore.
const (
	degradedRatio = 3.0
	severeRatio   = 20.0
)

// Assessment is the outcome of comparing a baseline to an under-load run.
type Assessment struct {
	Baseline  Result
	UnderLoad Result

	// Ratio is under-load per-op latency divided by baseline per-op latency.
	// This is the signal; neither input means anything alone.
	Ratio   float64
	Verdict Verdict
}

// Classify compares a baseline probe against one taken while a co-tenant
// generates dirty pages.
func Classify(baseline, underLoad Result) Assessment {
	a := Assessment{Baseline: baseline, UnderLoad: underLoad}

	base := baseline.PerOp()
	if base <= 0 {
		a.Verdict = VerdictUnknown
		return a
	}

	a.Ratio = float64(underLoad.PerOp()) / float64(base)
	switch {
	case a.Ratio >= severeRatio:
		a.Verdict = VerdictSevere
	case a.Ratio >= degradedRatio:
		a.Verdict = VerdictDegraded
	default:
		a.Verdict = VerdictIsolated
	}
	return a
}

// probeBlockSize is the write size per operation. Small on purpose: the
// measurement is of fsync commit latency, not throughput.
const probeBlockSize = 4096

// Probe measures ops × (4 KiB write + fsync) in dir and returns the total
// elapsed time. The scratch file is removed before returning, including on
// error — the probe runs inside a tenant's box, and one that leaks a file per
// invocation is one operators stop running.
func Probe(dir string, ops int) (Result, error) {
	if ops <= 0 {
		return Result{}, fmt.Errorf("ops must be positive, got %d", ops)
	}

	f, err := os.CreateTemp(dir, "containarium-storage-probe-*")
	if err != nil {
		return Result{}, fmt.Errorf("create probe file in %s: %w", dir, err)
	}
	defer func() {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
	}()

	buf := make([]byte, probeBlockSize)
	start := time.Now()
	for i := 0; i < ops; i++ {
		if _, err := f.Write(buf); err != nil {
			return Result{}, fmt.Errorf("write: %w", err)
		}
		if err := f.Sync(); err != nil {
			return Result{}, fmt.Errorf("fsync: %w", err)
		}
	}
	return Result{Ops: ops, Total: time.Since(start)}, nil
}

// LoadConfig describes the dirty-page generator.
type LoadConfig struct {
	// BlockSize is one buffered write.
	BlockSize int

	// BlocksPerSync is how many blocks are written before a single fsync.
	// BlockSize × BlocksPerSync is the dirty-page volume per commit, and
	// volume is what reproduces the stall — not sync frequency.
	BlocksPerSync int

	// Cycles caps the number of write-then-sync cycles. Zero means run until
	// the context is cancelled.
	Cycles int
}

// DefaultLoadConfig mirrors the reproduction in #1206: 64 MiB of buffered
// writes per fsync. Do not lower the volume per sync without re-measuring —
// the small-write, high-sync-rate variant does not reproduce the stall.
func DefaultLoadConfig() LoadConfig {
	return LoadConfig{
		BlockSize:     1 << 20, // 1 MiB
		BlocksPerSync: 64,      // -> 64 MiB per fsync
	}
}

// VolumePerSync is the dirty-page volume committed per fsync.
func (c LoadConfig) VolumePerSync() int64 {
	return int64(c.BlockSize) * int64(c.BlocksPerSync)
}

// loadTarget is the subset of *os.File the generator needs, so the write
// pattern can be observed in tests without touching disk.
type loadTarget interface {
	Write(p []byte) (int, error)
	Sync() error
	Truncate(size int64) error
}

// Load generates co-tenant dirty pages in dir until ctx is cancelled. Run it
// in one box while probing from another on the same backend.
//
// The scratch file is removed on return, including on cancellation.
func Load(ctx context.Context, dir string, cfg LoadConfig) error {
	f, err := os.CreateTemp(dir, "containarium-storage-load-*")
	if err != nil {
		return fmt.Errorf("create load file in %s: %w", dir, err)
	}
	defer func() {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
	}()

	return runLoad(ctx, f, cfg)
}

// runLoad is the generator loop, separated from file setup so tests can
// observe the write/sync pattern.
func runLoad(ctx context.Context, w loadTarget, cfg LoadConfig) error {
	if cfg.BlockSize <= 0 || cfg.BlocksPerSync <= 0 {
		return fmt.Errorf("invalid load config: BlockSize=%d BlocksPerSync=%d",
			cfg.BlockSize, cfg.BlocksPerSync)
	}

	buf := make([]byte, cfg.BlockSize)
	for i := 0; cfg.Cycles == 0 || i < cfg.Cycles; i++ {
		// Checked once per cycle rather than per block: an operator running
		// this against a live tenant's neighbours must be able to stop it.
		if err := ctx.Err(); err != nil {
			return nil
		}

		for b := 0; b < cfg.BlocksPerSync; b++ {
			if _, err := w.Write(buf); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
		if err := w.Sync(); err != nil {
			return fmt.Errorf("fsync: %w", err)
		}
		// Reuse the same extents rather than growing without bound; the goal
		// is dirty pages, not disk consumption.
		if err := w.Truncate(0); err != nil {
			return fmt.Errorf("truncate: %w", err)
		}
	}
	return nil
}
