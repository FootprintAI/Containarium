// Package platformstats accumulates platform-domain facts the
// cloud-native metrics export platform group (#1082/#1083/#1084)
// observes at each export tick: API request/error counts today,
// provisioning outcomes and connectivity state in follow-up issues.
//
// Deliberately dependency-free and lock-free (atomic counters, not a
// mutex): this sits on the request hot path via a gRPC interceptor, so
// recording an event must cost nothing more than an atomic add, and the
// package must never import anything that could pull the daemon's own
// dependency graph back in — the whole point is a package the
// cloudexport collector (and its tests) can use without needing a real
// server.
package platformstats

import (
	"sync/atomic"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
)

// CodeClass is the coarse API outcome bucket every platform.api.* series
// is labeled with — deliberately not a raw gRPC code or HTTP status: the
// billed cost surface stays a fixed, small cardinality regardless of how
// many distinct gRPC codes a handler can return.
type CodeClass string

const (
	CodeClassOK          CodeClass = "ok"
	CodeClassClientError CodeClass = "client_error"
	CodeClassServerError CodeClass = "server_error"
)

// ClassifyCode buckets a gRPC status code into its CodeClass using
// grpc-gateway's own gRPC->HTTP status mapping — the same mapping a
// REST-via-gateway caller actually sees — so native gRPC and REST
// traffic land in the same bucket for the same logical outcome, and a
// future new gRPC code is classified by the same rule everything else
// is instead of needing a new case here.
func ClassifyCode(code codes.Code) CodeClass {
	switch status := runtime.HTTPStatusFromCode(code); {
	case status >= 500:
		return CodeClassServerError
	case status >= 400:
		return CodeClassClientError
	default:
		return CodeClassOK
	}
}

// APISnapshot is a point-in-time read of the API request/error counters
// by code_class, consumed by the cloudexport platform group at each
// export tick. RequestsByClass counts every completed call classified
// into that bucket; ErrorsByClass counts the subset of those that were
// errors (client_error and server_error only — "ok" is never an error).
type APISnapshot struct {
	RequestsByClass map[CodeClass]int64
	ErrorsByClass   map[CodeClass]int64
}

// Stats accumulates platform-domain facts for the lifetime of the
// daemon process. Every counter is a plain atomic.Int64: recording an
// event is a single atomic add, and a snapshot is a plain load — no
// lock, no allocation on the hot path.
type Stats struct {
	apiRequestsOK          atomic.Int64
	apiRequestsClientError atomic.Int64
	apiRequestsServerError atomic.Int64
	apiErrorsClientError   atomic.Int64
	apiErrorsServerError   atomic.Int64
}

// New returns a zeroed Stats. (atomic.Int64 is itself zero-value-usable,
// so &Stats{} works too — New exists for call-site clarity and to leave
// room for future non-zero defaults without an API break.)
func New() *Stats {
	return &Stats{}
}

// RecordAPIRequest classifies one completed API call and increments the
// matching counters: requests[class] always, plus errors[class] when
// class is a client or server error.
func (s *Stats) RecordAPIRequest(class CodeClass) {
	switch class {
	case CodeClassOK:
		s.apiRequestsOK.Add(1)
	case CodeClassClientError:
		s.apiRequestsClientError.Add(1)
		s.apiErrorsClientError.Add(1)
	case CodeClassServerError:
		s.apiRequestsServerError.Add(1)
		s.apiErrorsServerError.Add(1)
	}
}

// SnapshotAPI returns the current cumulative API counters. The result is
// a fresh map on every call — mutating it never affects Stats, and
// Stats is never affected by anything done to a previously returned
// snapshot.
func (s *Stats) SnapshotAPI() APISnapshot {
	return APISnapshot{
		RequestsByClass: map[CodeClass]int64{
			CodeClassOK:          s.apiRequestsOK.Load(),
			CodeClassClientError: s.apiRequestsClientError.Load(),
			CodeClassServerError: s.apiRequestsServerError.Load(),
		},
		ErrorsByClass: map[CodeClass]int64{
			CodeClassClientError: s.apiErrorsClientError.Load(),
			CodeClassServerError: s.apiErrorsServerError.Load(),
		},
	}
}
