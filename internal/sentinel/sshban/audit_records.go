package sshban

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// AuditRecorder turns the guard's failure and ban events into session records
// for the audit shipper (#2419, ISO 27001 A.8.15): the evidence of probing and
// brute force that otherwise lives only in the sentinel's journal.
//
// Volume is bounded three ways, because a scan can generate failures faster
// than anything should be written:
//
//   - the guard already counts per source IP, so one AUTH_FAILED record is
//     written per source per ban window (with the count), not one per failure;
//   - at most MaxPerMinute of those summaries are written per minute; the rest
//     are folded into one overflow record per minute carrying the failures
//     they stood for, so the volume stays visible;
//   - BANNED records are exempt from that cap, and need no other: a ban takes
//     max-failures failures from one source, so their rate is bounded by the
//     attacker's effort and the guard's max-entries.
//
// Emit is called with the guard's mutex held and must not block SSH
// authentication, so it only enqueues; a full queue counts into the overflow
// record instead of waiting for disk.
type AuditRecorder struct {
	listener pb.SSHBanListener
	out      sshsession.Recorder
	max      int
	now      func() time.Time
	newID    func() string
	logf     func(format string, args ...any)

	queue     chan Event
	dropped   atomic.Uint64 // failures lost to a full queue since the last flush
	abort     chan struct{}
	abortOnce sync.Once
}

// AuditConfig configures an AuditRecorder.
type AuditConfig struct {
	Listener pb.SSHBanListener
	Out      sshsession.Recorder
	// MaxPerMinute caps individually written AUTH_FAILED records per flush
	// interval. 0 or negative means 600.
	MaxPerMinute int
	// QueueSize is the Emit buffer. 0 or negative means 1024.
	QueueSize int
	Now       func() time.Time
	// NewID returns a unique record id. Nil means a random one.
	NewID func() string
	Logf  func(format string, args ...any)
}

// NewAuditRecorder builds the recorder.
func NewAuditRecorder(c AuditConfig) *AuditRecorder {
	if c.MaxPerMinute <= 0 {
		c.MaxPerMinute = 600
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.NewID == nil {
		c.NewID = func() string { return "ssh-ban-" + rand.Text() }
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return &AuditRecorder{
		listener: c.Listener, out: c.Out, max: c.MaxPerMinute,
		now: c.Now, newID: c.NewID, logf: c.Logf,
		queue: make(chan Event, c.QueueSize),
		abort: make(chan struct{}),
	}
}

// Abort asks the recorder to skip pending work and finalization at its next
// checkpoint. It cannot interrupt a synchronous sweep or write already in
// progress. Use on shutdown deadline; queued records may be lost.
func (a *AuditRecorder) Abort() { a.abortOnce.Do(func() { close(a.abort) }) }

// Emit is a Config.Emit for the guard. It never blocks.
func (a *AuditRecorder) Emit(e Event) {
	if e.Kind != "ban" && e.Kind != EventWindowFailures {
		return
	}
	select {
	case a.queue <- e:
	default:
		a.dropped.Add(e.Failures)
	}
}

// Run writes queued events until ctx is done or Abort is called. On every tick it writes the
// overflow record (if any) and calls sweep, which should end the guard's
// finished windows so their summaries are queued even when no connection
// arrives. On exit it sweeps and reports any remaining failure windows before
// the final drain and flush. Abort skips that finalization when callbacks
// cannot be quiesced safely.
func (a *AuditRecorder) Run(ctx context.Context, ticks <-chan time.Time, sweep, flushWindows func()) {
	written := 0
	var suppressed uint64
	aborted := func() bool {
		select {
		case <-a.abort:
			return true
		default:
			return false
		}
	}
	handle := func(e Event) {
		switch e.Kind {
		case "ban":
			a.write(banRecord(a, e))
		case EventWindowFailures:
			if written >= a.max {
				suppressed += e.Failures
				return
			}
			if a.write(failedRecord(a, e)) {
				written++
			}
		}
	}
	flush := func() {
		suppressed += a.dropped.Swap(0)
		if suppressed > 0 {
			a.write(sshsession.Record{
				SessionID: a.newID(), Phase: sshsession.SessionPhaseAuthFailed, OccurredAt: a.now().UTC(),
				BanListener: a.listener, SuppressedCount: suppressed,
			})
		}
		written, suppressed = 0, 0
	}
	drain := func() {
		for {
			if aborted() {
				return
			}
			select {
			case e := <-a.queue:
				handle(e)
			default:
				return
			}
		}
	}
	for {
		if aborted() {
			return
		}
		select {
		case <-a.abort:
			return
		case <-ctx.Done():
			if aborted() {
				return
			}
			if sweep != nil {
				sweep()
			}
			if aborted() {
				return
			}
			if flushWindows != nil {
				flushWindows()
			}
			if aborted() {
				return
			}
			drain()
			if aborted() {
				return
			}
			flush()
			return
		case e := <-a.queue:
			handle(e)
		case <-ticks:
			if sweep != nil {
				sweep()
			}
			if aborted() {
				return
			}
			drain()
			if aborted() {
				return
			}
			flush()
		}
	}
}

func (a *AuditRecorder) write(r sshsession.Record) bool {
	if err := a.out.Record(r); err != nil {
		a.logf("ssh-ban audit record (%s): %v", r.Phase, err)
		return false
	}
	return true
}

func failedRecord(a *AuditRecorder, e Event) sshsession.Record {
	return sshsession.Record{
		SessionID: a.newID(), Phase: sshsession.SessionPhaseAuthFailed, OccurredAt: a.now().UTC(),
		ClientIP: e.IP, BanListener: a.listener, FailureCount: e.Failures,
	}
}

func banRecord(a *AuditRecorder, e Event) sshsession.Record {
	until := e.ExpiresAt.UTC()
	return sshsession.Record{
		SessionID: a.newID(), Phase: sshsession.SessionPhaseBanned, OccurredAt: a.now().UTC(),
		ClientIP: e.IP, BanListener: a.listener, FailureCount: e.Failures, BannedUntil: &until,
	}
}
