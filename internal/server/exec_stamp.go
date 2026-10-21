package server

import "github.com/footprintai/containarium/internal/threatdetect"

// Exec stamps (#2765 follow-up). The exec watcher stamps every decoded exec
// with the boot clock instead of reading /proc/<pid>/stat for it: a stamp is
// one clock read, a stat read is open/fstat/read/close on procfs plus the
// kernel formatting ~50 fields, and the consumer drains the exec ring on
// every exec of every watched box. The kill reads the stat once, for the one
// process it is about to signal, and compares the two.
//
// Why the compare is sound. /proc/<pid>/stat field 22 is the process's fork
// time on CLOCK_BOOTTIME (task->start_boottime), floored to USER_HZ ticks
// (nsec_to_clock_t). The stamp is CLOCK_BOOTTIME read after the ring record
// was consumed, floored the same way. The matched process forked before it
// exec'd, and it exec'd before its record reached the ring, so its start
// time is <= the stamp. A process that holds the pid at kill time and
// started after the stamp is therefore not the matched process: refused as
// pid reused. Both values are read through the daemon's own time namespace
// (procfs adds the reader's boottime offset), so they stay comparable.
//
// The residual window is exec -> stamp: at most one ring drain
// (netbpf.ExecDrainInterval, 50 ms) plus the decode of the records ahead of
// it. For a newcomer to hide in it, the matched process must exit and the
// kernel must hand the same pid to a new process of the same box inside
// that window. Linux allocates pids cyclically (idr_alloc_cyclic: the next
// free pid after the last one handed out) up to kernel.pid_max and only then
// wraps, so the same pid comes back only after every other free pid has
// been handed out. pid_max is 32,768 by kernel default and 4,194,304 where
// systemd raises it (most current distributions). With the pid space
// mostly free, a reuse inside 50 ms needs ~650,000 to ~84 million forks a
// second across the whole host, against the tens of thousands a host can
// sustain. Pids still in use are skipped, so a host that already holds most
// of its pid space wraps sooner: the bound is (pid_max - pids in use) forks
// in 50 ms, still far out of reach unless the host is close to pid
// exhaustion, where fork itself starts failing. The #2867 design,
// which read the stat at decode, had the same window (exec -> read). The
// pidfd pin and the cgroup re-check stay in front of this compare and are
// unchanged: they cover reuse on the host and by another box at any time.

// execStampSlackTicks is how much later than the stamp the pinned process
// may have started and still be the matched one. Both sides are floored to
// the same tick, so the exact bound is 0; one tick (10 ms at USER_HZ=100)
// absorbs clocksource skew between the CPU that forked the process and the
// CPU that read the stamp. It widens the residual window by that tick, not
// more. It does not cover a wrong tick rate: the stamp's ticks must be the
// kernel's USER_HZ, which is why userHZ is read from AT_CLKTCK rather than
// assumed.
const execStampSlackTicks = 1

// bootTicksOf converts a CLOCK_BOOTTIME reading in nanoseconds to clock
// ticks since boot the way the kernel renders field 22 (nsec_to_clock_t:
// floor division by NSEC_PER_SEC/USER_HZ). 0 (unknown) for a non-positive
// reading or tick rate.
func bootTicksOf(ns int64, hz uint64) threatdetect.ProcStartTicks {
	if ns <= 0 || hz == 0 || hz > 1_000_000_000 {
		return 0
	}
	return threatdetect.ProcStartTicks(uint64(ns) / (1_000_000_000 / hz))
}

// startedAfterStamp reports whether a process whose stat start time is start
// cannot be the process an exec stamped at stamp belongs to.
func startedAfterStamp(start, stamp threatdetect.ProcStartTicks) bool {
	return uint64(start) > uint64(stamp)+execStampSlackTicks
}
