package platformstats

import (
	"sync"
	"testing"

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
