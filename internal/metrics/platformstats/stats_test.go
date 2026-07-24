package platformstats

import (
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
)

func TestClassifyCode(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
		want CodeClass
	}{
		{"ok", codes.OK, CodeClassOK},
		{"invalid argument (400) is client error", codes.InvalidArgument, CodeClassClientError},
		{"not found (404) is client error", codes.NotFound, CodeClassClientError},
		{"permission denied (403) is client error", codes.PermissionDenied, CodeClassClientError},
		{"unauthenticated (401) is client error", codes.Unauthenticated, CodeClassClientError},
		{"internal (500) is server error", codes.Internal, CodeClassServerError},
		{"unavailable (503) is server error", codes.Unavailable, CodeClassServerError},
		{"unimplemented (501) is server error", codes.Unimplemented, CodeClassServerError},
		{"unknown (500-mapped) is server error", codes.Unknown, CodeClassServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyCode(tc.code); got != tc.want {
				t.Errorf("ClassifyCode(%v) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

func TestStats_RecordAndSnapshotAPI(t *testing.T) {
	s := New()

	snap := s.SnapshotAPI()
	if snap.RequestsByClass[CodeClassOK] != 0 || snap.ErrorsByClass[CodeClassClientError] != 0 {
		t.Fatalf("fresh Stats should snapshot all zero, got %+v", snap)
	}

	s.RecordAPIRequest(CodeClassOK)
	s.RecordAPIRequest(CodeClassOK)
	s.RecordAPIRequest(CodeClassClientError)
	s.RecordAPIRequest(CodeClassServerError)
	s.RecordAPIRequest(CodeClassServerError)
	s.RecordAPIRequest(CodeClassServerError)

	snap = s.SnapshotAPI()
	if snap.RequestsByClass[CodeClassOK] != 2 {
		t.Errorf("requests[ok] = %d, want 2", snap.RequestsByClass[CodeClassOK])
	}
	if snap.RequestsByClass[CodeClassClientError] != 1 {
		t.Errorf("requests[client_error] = %d, want 1", snap.RequestsByClass[CodeClassClientError])
	}
	if snap.RequestsByClass[CodeClassServerError] != 3 {
		t.Errorf("requests[server_error] = %d, want 3", snap.RequestsByClass[CodeClassServerError])
	}

	// "ok" is never an error — only client/server error classes ever
	// increment the errors counters, and requests[ok] never leaks into
	// errors[ok].
	if v, ok := snap.ErrorsByClass[CodeClassOK]; ok && v != 0 {
		t.Errorf("errors[ok] = %d, want absent or 0", v)
	}
	if snap.ErrorsByClass[CodeClassClientError] != 1 {
		t.Errorf("errors[client_error] = %d, want 1", snap.ErrorsByClass[CodeClassClientError])
	}
	if snap.ErrorsByClass[CodeClassServerError] != 3 {
		t.Errorf("errors[server_error] = %d, want 3", snap.ErrorsByClass[CodeClassServerError])
	}
}

// TestStats_SnapshotIsACopy guards against a future refactor handing out
// a live view: mutating the returned snapshot must never affect the
// Stats it came from, and a later snapshot must reflect only what was
// recorded after the first, not any tampering with the earlier copy.
func TestStats_SnapshotIsACopy(t *testing.T) {
	s := New()
	s.RecordAPIRequest(CodeClassOK)

	first := s.SnapshotAPI()
	first.RequestsByClass[CodeClassOK] = 9999

	second := s.SnapshotAPI()
	if second.RequestsByClass[CodeClassOK] != 1 {
		t.Errorf("mutating a returned snapshot leaked back into Stats: second snapshot = %d, want 1", second.RequestsByClass[CodeClassOK])
	}
}

// TestStats_ConcurrentRecordAPIRequest locks in the lock-free contract:
// concurrent recorders must never lose or double-count an increment.
// Run with -race.
func TestStats_ConcurrentRecordAPIRequest(t *testing.T) {
	s := New()
	const goroutines = 50
	const perGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				s.RecordAPIRequest(CodeClassOK)
			}
		}()
	}
	wg.Wait()

	snap := s.SnapshotAPI()
	want := int64(goroutines * perGoroutine)
	if snap.RequestsByClass[CodeClassOK] != want {
		t.Errorf("requests[ok] = %d, want %d (lost or duplicated increments under concurrency)", snap.RequestsByClass[CodeClassOK], want)
	}
}

func TestStats_RecordAndSnapshotProvision(t *testing.T) {
	s := New()

	snap := s.SnapshotProvision()
	if snap.Attempts[OperationCreate] != 0 || snap.Failures[OperationDelete] != 0 {
		t.Fatalf("fresh Stats should snapshot all zero, got %+v", snap)
	}

	s.RecordProvisionAttempt(OperationCreate, true, 2*time.Second)
	s.RecordProvisionAttempt(OperationCreate, true, 4*time.Second)
	s.RecordProvisionAttempt(OperationCreate, false, 1*time.Second)
	s.RecordProvisionAttempt(OperationDelete, true, 500*time.Millisecond)

	snap = s.SnapshotProvision()
	if snap.Attempts[OperationCreate] != 3 {
		t.Errorf("attempts[create] = %d, want 3", snap.Attempts[OperationCreate])
	}
	if snap.Failures[OperationCreate] != 1 {
		t.Errorf("failures[create] = %d, want 1", snap.Failures[OperationCreate])
	}
	// 2s + 4s + 1s = 7s across all three create attempts, success or not —
	// duration is measured regardless of outcome so a slow failure still
	// shows up in the mean-latency signal.
	if got, want := snap.DurationSecondsSum[OperationCreate], 7.0; got != want {
		t.Errorf("durationSecondsSum[create] = %v, want %v", got, want)
	}
	if snap.Attempts[OperationDelete] != 1 {
		t.Errorf("attempts[delete] = %d, want 1", snap.Attempts[OperationDelete])
	}
	if snap.Failures[OperationDelete] != 0 {
		t.Errorf("failures[delete] = %d, want 0 (the one delete succeeded)", snap.Failures[OperationDelete])
	}
	if got, want := snap.DurationSecondsSum[OperationDelete], 0.5; got != want {
		t.Errorf("durationSecondsSum[delete] = %v, want %v", got, want)
	}
}

// TestStats_ConcurrentRecordProvisionAttempt mirrors the API-counter
// concurrency guard for the provisioning counters — run with -race.
func TestStats_ConcurrentRecordProvisionAttempt(t *testing.T) {
	s := New()
	const goroutines = 50
	const perGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				s.RecordProvisionAttempt(OperationCreate, j%2 == 0, 10*time.Millisecond)
			}
		}()
	}
	wg.Wait()

	snap := s.SnapshotProvision()
	wantAttempts := int64(goroutines * perGoroutine)
	if snap.Attempts[OperationCreate] != wantAttempts {
		t.Errorf("attempts[create] = %d, want %d", snap.Attempts[OperationCreate], wantAttempts)
	}
	wantFailures := int64(goroutines * perGoroutine / 2)
	if snap.Failures[OperationCreate] != wantFailures {
		t.Errorf("failures[create] = %d, want %d", snap.Failures[OperationCreate], wantFailures)
	}
}
