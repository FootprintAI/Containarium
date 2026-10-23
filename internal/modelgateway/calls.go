package modelgateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Per-run record of the model calls the gateway proxied (#2928).
//
// A failure at the gateway (an upstream 401 on a bad key, a refused call, a
// dial error) happens outside the box and never reaches the run's journal, so
// the run reads as "command exited with code 1". The gateway records one
// typed event per call here; TailRunLog returns them next to the journal and a
// client interleaves them by time. The in-box journal stays single-writer.
//
// An event carries who paid (the owner TYPE) and how the call ended. It never
// carries a key, a key id, the token, the key owner's id, or any prompt or
// response content: there is no field for them.

// CallRecorder receives one event per proxied call. Nil in Config means calls
// are not recorded.
type CallRecorder interface {
	RecordCall(runID string, c *pb.GatewayCall)
}

const (
	// DefaultCallLogPerRun bounds the events kept for one run; the oldest go first.
	DefaultCallLogPerRun = 500
	// DefaultCallLogRuns bounds how many runs are kept; the least recently
	// written go first.
	DefaultCallLogRuns = 2000
	// DefaultCallLogTTL is how long a run's events outlive its last call.
	DefaultCallLogTTL = 24 * time.Hour
)

// CallLog is an in-memory CallRecorder with a reader. It does not survive a
// daemon restart: a run that spans one loses the events from before it.
type CallLog struct {
	mu      sync.Mutex
	runs    map[string]*runCalls
	perRun  int
	maxRuns int
	ttl     time.Duration
	now     func() time.Time
}

type runCalls struct {
	next   int64
	events []*pb.GatewayCall
	last   time.Time
}

// NewCallLog builds a CallLog with the default bounds.
func NewCallLog() *CallLog {
	return &CallLog{runs: map[string]*runCalls{}, perRun: DefaultCallLogPerRun, maxRuns: DefaultCallLogRuns,
		ttl: DefaultCallLogTTL, now: func() time.Time { return time.Now().UTC() }}
}

// RecordCall appends c to the run's log, assigning its Seq. An empty runID (a
// token minted for something other than a run) records nothing.
func (l *CallLog) RecordCall(runID string, c *pb.GatewayCall) {
	if runID == "" || c == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.evict(now)
	r := l.runs[runID]
	if r == nil {
		r = &runCalls{}
		l.runs[runID] = r
	}
	r.next++
	e := proto.Clone(c).(*pb.GatewayCall) // never alias the caller's message
	e.Seq = r.next
	r.events = append(r.events, e)
	if len(r.events) > l.perRun {
		r.events = r.events[len(r.events)-l.perRun:]
	}
	r.last = now
}

func (l *CallLog) evict(now time.Time) {
	for id, r := range l.runs {
		if now.Sub(r.last) > l.ttl {
			delete(l.runs, id)
		}
	}
	for len(l.runs) >= l.maxRuns {
		oldest, at := "", time.Time{}
		for id, r := range l.runs {
			if oldest == "" || r.last.Before(at) {
				oldest, at = id, r.last
			}
		}
		delete(l.runs, oldest)
	}
}

// Since returns the run's events for skillID (all skills when empty) with Seq
// greater than after, oldest first, and the cursor to pass next time: the last
// Seq returned, or after when there was none.
func (l *CallLog) Since(runID, skillID string, after int64) ([]*pb.GatewayCall, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[runID]
	if r == nil {
		return nil, after
	}
	var out []*pb.GatewayCall
	next := after
	for _, e := range r.events {
		if e.Seq <= after {
			continue
		}
		next = max(next, e.Seq)
		if skillID != "" && e.SkillId != skillID {
			continue
		}
		out = append(out, proto.Clone(e).(*pb.GatewayCall))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, next
}

// newCall builds the event for a finished call.
func newCall(claims *GatewayClaims, provider, model string, owner pb.GatewayKeyOwner, status int32, terr pb.GatewayTransportError, started, ended time.Time) *pb.GatewayCall {
	now := time.Now().UTC()
	return &pb.GatewayCall{
		Time:           timestamppb.New(now),
		SkillId:        claims.SkillID,
		Provider:       provider,
		Model:          model,
		KeyOwner:       owner,
		Status:         status,
		TransportError: terr,
		LatencyMs:      ended.Sub(started).Milliseconds(),
	}
}

// classifyTransportError names why a proxied call produced no upstream
// response. Only the class is kept; the error text can carry addresses.
func classifyTransportError(err error) pb.GatewayTransportError {
	var netErr net.Error
	var opErr *net.OpError
	var certErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	switch {
	case errors.Is(err, context.Canceled):
		return pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_CANCELED
	case errors.Is(err, context.DeadlineExceeded):
		return pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_TIMEOUT
	case errors.As(err, &certErr), errors.As(err, &recordErr):
		return pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_TLS
	case errors.As(err, &netErr) && netErr.Timeout():
		return pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_TIMEOUT
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_DIAL
	}
	return pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_OTHER
}
