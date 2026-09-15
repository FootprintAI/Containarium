package audit

import (
	"sync/atomic"
	"time"
)

// persistFailures counts every audit entry this process failed to
// durably write — either the store's Log() call returned an error, or
// the writer's buffered channel was full and the entry was dropped
// before Log() was even attempted. Both are audit-trail gaps: an
// action happened and no row proves it.
//
// The write is always async (HTTPAuditMiddleware, GRPCInterceptor, and
// EventSubscriber all hand entries to a background writer, or in
// EventSubscriber's case run on their own goroutine off the event bus)
// specifically so a slow or unavailable audit store never adds latency
// to — or fails — the request that triggered the entry. That's the
// right trade-off for availability, but it means a write failure was
// previously observable only as a log.Printf line: invisible unless an
// operator happened to be tailing the daemon's stdout at the exact
// moment. This counter makes the failure mode observable without
// giving up the async trade-off.
var (
	persistFailures atomic.Int64
	firstFailureAt  atomic.Int64 // unix nanos; 0 = none recorded yet
)

// recordPersistFailure increments the failure counter and, on the
// first call, latches the time so PersistFailureReport can report
// "since when." Called from all three audit writers (HTTP middleware,
// gRPC interceptor, event subscriber) on both failure modes: a Log()
// error, and a channel-full drop.
func recordPersistFailure() {
	persistFailures.Add(1)
	firstFailureAt.CompareAndSwap(0, time.Now().UnixNano())
}

// PersistFailureReport is what GetPersistFailureReport returns.
type PersistFailureReport struct {
	// Count is the number of audit entries this process has failed to
	// durably write since startup (or since ResetPersistFailuresForTest).
	Count int64
	// Since is when the first failure was recorded. Zero if Count == 0.
	Since time.Time
}

// GetPersistFailureReport reports this process's audit persistence
// failures since startup. Exposed to operators via GET /v1/audit/health
// (admin role or audit:read scope, same gate as /v1/audit/logs).
func GetPersistFailureReport() PersistFailureReport {
	count := persistFailures.Load()
	var since time.Time
	if ns := firstFailureAt.Load(); ns != 0 {
		since = time.Unix(0, ns)
	}
	return PersistFailureReport{Count: count, Since: since}
}

// ResetPersistFailuresForTest clears the counter. Test-only — production
// code has no legitimate reason to reset a reliability counter mid-process.
func ResetPersistFailuresForTest() {
	persistFailures.Store(0)
	firstFailureAt.Store(0)
}

// RecordPersistFailureForTest lets other packages' tests (e.g.
// internal/gateway's /v1/audit/health handler test) simulate a persistence
// failure without going through a real write path. Test-only.
func RecordPersistFailureForTest() {
	recordPersistFailure()
}
