package poolcapacity

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// ZpoolDeadline bounds one `zpool list`. A pool in trouble is exactly when
// zpool can hang, and the read must keep reporting Incus's own numbers then.
const ZpoolDeadline = 3 * time.Second

// CommandRunner runs a command and returns its stdout. ExecRunner in
// production; a stub in tests.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs name with args under ctx. A binary that is not installed
// comes back wrapping exec.ErrNotFound, which WithZpool treats as "this host
// has no ZFS tools", not as a failure.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	// #nosec G204 -- the only caller is WithZpool: name is the fixed string
	// "zpool", the arguments are a fixed list plus a pool name that passed
	// validZpoolName (no leading '-', no shell, no path).
	out, err := exec.CommandContext(ctx, path, args...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// zpool says why on stderr; keep the first line, capped, for the log.
		msg := strings.TrimSpace(string(ee.Stderr))
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

// validZpoolName is what ZFS allows in a pool name, minus anything that could
// read as an option or a path.
var validZpoolName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

// WithZpool wraps a Reader so each ZFS pool also carries its raw zpool numbers
// (#2853). Only pools with driver zfs and a derivable zpool name are asked;
// every other pool, and every pool whose zpool read fails, keeps exactly the
// reading Incus gave. The zpool reads run in parallel, each under deadline, so
// the added time is one deadline at worst, and a hung zpool never delays or
// fails the capacity read.
func WithZpool(read Reader, run CommandRunner, deadline time.Duration) Reader {
	return withZpool(read, run, deadline, log.Printf)
}

func withZpool(read Reader, run CommandRunner, deadline time.Duration, logf func(string, ...any)) Reader {
	if deadline <= 0 {
		deadline = ZpoolDeadline
	}
	z := &zpoolReader{run: run, deadline: deadline, logf: logf, inflight: map[string]bool{}, failing: map[string]bool{}}
	return func() ([]incus.StoragePoolUsage, error) {
		pools, err := read()
		if err != nil {
			return nil, err
		}
		z.annotate(pools)
		return pools, nil
	}
}

type zpoolReader struct {
	run      CommandRunner
	deadline time.Duration
	logf     func(string, ...any)

	mu       sync.Mutex
	inflight map[string]bool // zpool name -> a previous read is still running
	failing  map[string]bool // incus pool name -> already logged this failure streak
}

func (z *zpoolReader) annotate(pools []incus.StoragePoolUsage) {
	var wg sync.WaitGroup
	for i := range pools {
		if pools[i].Driver != "zfs" || !validZpoolName.MatchString(pools[i].ZpoolName) {
			continue
		}
		wg.Add(1)
		go func(p *incus.StoragePoolUsage) {
			defer wg.Done()
			stat, err := z.read(p.ZpoolName)
			if err != nil {
				z.noteFailure(p.Name, err)
				return
			}
			z.noteSuccess(p.Name)
			p.Zpool = stat
		}(&pools[i])
	}
	wg.Wait()
}

// read runs zpool for one pool. It does not trust the command to honour the
// deadline: a zpool stuck in uninterruptible I/O can outlive a kill, so the
// call returns when the deadline passes whatever the command is doing, and a
// pool whose previous run is still stuck is skipped rather than stacked with a
// second one.
func (z *zpoolReader) read(zpool string) (*incus.ZpoolStat, error) {
	z.mu.Lock()
	if z.inflight[zpool] {
		z.mu.Unlock()
		return nil, fmt.Errorf("the previous `zpool list` for %q has not returned", zpool)
	}
	z.inflight[zpool] = true
	z.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), z.deadline)
	defer cancel()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := z.run(ctx, "zpool", "list", "-Hp", "-o", "name,cap,frag", zpool)
		z.mu.Lock()
		delete(z.inflight, zpool)
		z.mu.Unlock()
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		return parseZpoolList(zpool, r.out)
	case <-ctx.Done():
		return nil, fmt.Errorf("`zpool list` for %q did not answer within %s", zpool, z.deadline)
	}
}

func (z *zpoolReader) noteFailure(pool string, err error) {
	if errors.Is(err, exec.ErrNotFound) {
		return // no ZFS tools on this host: normal, not worth a line
	}
	z.mu.Lock()
	first := !z.failing[pool]
	z.failing[pool] = true
	z.mu.Unlock()
	if first {
		z.logf("storage pool %q: zpool numbers unavailable (%v); keeping Incus's reading", pool, err)
	}
}

func (z *zpoolReader) noteSuccess(pool string) {
	z.mu.Lock()
	delete(z.failing, pool)
	z.mu.Unlock()
}

// parseZpoolList reads `zpool list -Hp -o name,cap,frag <pool>` output: one
// line, three whitespace-separated fields. cap is a 0..100 percentage; frag is
// the same or "-" when the pool does not report fragmentation. A line for a
// different pool, a wrong field count or an out-of-range number is an error:
// better no gauge than a wrong one.
func parseZpoolList(zpool string, out []byte) (*incus.ZpoolStat, error) {
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != zpool {
			continue
		}
		capPct, err := parsePercent(f[1])
		if err != nil {
			return nil, fmt.Errorf("zpool list %q: cap %q: %w", zpool, f[1], err)
		}
		stat := &incus.ZpoolStat{CapacityPercent: capPct}
		if f[2] != "-" {
			frag, err := parsePercent(f[2])
			if err != nil {
				return nil, fmt.Errorf("zpool list %q: frag %q: %w", zpool, f[2], err)
			}
			stat.FragmentationPercent, stat.FragmentationKnown = frag, true
		}
		return stat, nil
	}
	return nil, fmt.Errorf("zpool list printed no line for %q", zpool)
}

func parsePercent(s string) (int64, error) {
	// -p asks for plain numbers, but accept a trailing % too: the column is a
	// percentage either way, and a build that keeps the sign must not turn
	// every pool's gauge off.
	s = strings.TrimSuffix(s, "%")
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 100 {
		return 0, fmt.Errorf("%d is not a percentage", n)
	}
	return n, nil
}
