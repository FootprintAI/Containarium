package poolcapacity

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
)

// Headroom floor (#3128). A pool that fills to 0 B stops Incus, core Postgres
// and then the daemon itself (#3043). Past the floor, the daemon refuses the
// work that grows a pool the fastest — container creates and snapshots — with
// an error naming the pool and the headroom left, instead of filling it.
//
// The floor is percent used against the Incus-reported total, the same unit
// as WarnPercent and CritPercent. It is configured per pool with the daemon's
// repeatable --pool-headroom-floor=<pool>=<percent> flag (decision Q6 on
// #3128). It moves only the refusal: host status and the built-in alert keep
// the fixed WarnPercent/CritPercent.

// DefaultFloorPercent is the floor for a pool not named on the flag.
const DefaultFloorPercent = 95

// A configured floor must lie in [minFloorPercent, maxFloorPercent] and above
// WarnPercent, so "pool nearly full" in host status always shows before work
// starts being refused.
const (
	minFloorPercent = 50
	maxFloorPercent = 99
)

// Floors maps a pool name to its floor in percent used. It implements
// pflag.Value, so the daemon flag is repeatable and validated at parse time.
// A nil Floors is valid: every pool gets DefaultFloorPercent.
type Floors map[string]int

// Set parses one "<pool>=<percent>" spec.
func (f Floors) Set(spec string) error {
	name, pctStr, ok := strings.Cut(spec, "=")
	if !ok {
		return fmt.Errorf("pool headroom floor %q: want <pool>=<percent>", spec)
	}
	name, pctStr = strings.TrimSpace(name), strings.TrimSpace(pctStr)
	if name == "" {
		return fmt.Errorf("pool headroom floor %q: pool name is empty", spec)
	}
	pct, err := strconv.Atoi(pctStr)
	if err != nil {
		return fmt.Errorf("pool headroom floor %q: percent must be a whole number", spec)
	}
	if pct < minFloorPercent || pct > maxFloorPercent {
		return fmt.Errorf("pool headroom floor %q: percent must be between %d and %d", spec, minFloorPercent, maxFloorPercent)
	}
	if pct <= WarnPercent {
		return fmt.Errorf("pool headroom floor %q: percent must be above the %d%% nearly-full mark, so host status warns before work is refused", spec, WarnPercent)
	}
	if _, dup := f[name]; dup {
		return fmt.Errorf("pool headroom floor: pool %q given more than once", name)
	}
	f[name] = pct
	return nil
}

// String renders the floors as sorted "pool=pct" pairs.
func (f Floors) String() string {
	names := make([]string, 0, len(f))
	for n := range f {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", n, f[n]))
	}
	return strings.Join(parts, ",")
}

// Type names the flag value in --help.
func (f Floors) Type() string { return "pool=percent" }

// For returns pool's floor.
func (f Floors) For(pool string) int {
	if pct, ok := f[pool]; ok {
		return pct
	}
	return DefaultFloorPercent
}

// Operation is the work a floor check guards.
type Operation int

const (
	OperationCreate Operation = iota + 1
	OperationSnapshot
)

func (o Operation) String() string {
	switch o {
	case OperationCreate:
		return "container create"
	case OperationSnapshot:
		return "snapshot"
	default:
		return "operation"
	}
}

// HeadroomError is a refusal: pool is at or past its floor.
type HeadroomError struct {
	Pool         string
	Op           Operation
	UsedBytes    int64
	TotalBytes   int64
	FreeBytes    int64
	FloorPercent int
}

func (e *HeadroomError) Error() string {
	return fmt.Sprintf("refusing %s: storage pool %q is %.1f%% used (floor %d%%), only %.1f GiB headroom left of %.1f GiB. "+
		"Free space on the pool (delete old snapshots or unused images) or grow it, then retry",
		e.Op, e.Pool, float64(e.UsedBytes)*100/float64(e.TotalBytes), e.FloorPercent,
		float64(e.FreeBytes)/(1<<30), float64(e.TotalBytes)/(1<<30))
}

// Guard checks a pool against its floor using the monitor's last snapshot,
// so a check never calls Incus. A nil *Guard admits everything.
type Guard struct {
	floors      Floors
	snapshot    func() Snapshot
	defaultPool func() string
	logf        func(format string, a ...any)
}

// NewGuard builds a Guard. defaultPool names the pool an empty pool name
// means (the daemon's --storage-pool); logf defaults to log.Printf.
func NewGuard(floors Floors, snapshot func() Snapshot, defaultPool func() string, logf func(format string, a ...any)) *Guard {
	if logf == nil {
		logf = log.Printf
	}
	return &Guard{floors: floors, snapshot: snapshot, defaultPool: defaultPool, logf: logf}
}

// Admit returns a *HeadroomError when pool is at or past its floor. A pool
// whose size has never been read is admitted with a warning: refusing on an
// unknown would turn a slow Incus read into a create outage.
func (g *Guard) Admit(pool string, op Operation) error {
	if g == nil {
		return nil
	}
	if pool == "" && g.defaultPool != nil {
		pool = g.defaultPool()
	}
	floor := g.floors.For(pool)
	for _, p := range g.snapshot().Pools {
		if p.Name != pool {
			continue
		}
		if p.TotalBytes <= 0 {
			break
		}
		// Integer percent, the same rounding as Classify.
		if p.UsedBytes*100/p.TotalBytes < int64(floor) {
			return nil
		}
		return &HeadroomError{
			Pool: pool, Op: op, UsedBytes: p.UsedBytes, TotalBytes: p.TotalBytes,
			FreeBytes: max(p.TotalBytes-p.UsedBytes, 0), FloorPercent: floor,
		}
	}
	g.logf("WARN: storage pool %q size has not been read; allowing %s without a headroom check (floor %d%%)", pool, op, floor)
	return nil
}
