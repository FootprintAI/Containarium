package server

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ttlMockCall is a single observed Set/UnsetConfig invocation. We
// capture both flavours into the same channel so the assertions can
// read "what calls did the handler make, in order" without juggling
// two slices.
type ttlMockCall struct {
	kind  string // "set" or "unset"
	name  string
	key   string
	value string
}

// newTTLTestServer wires a ContainerServer over a *MockBackend seeded
// with the given containers, and returns the captured-call slice the
// caller can inspect after a handler invocation. Mirrors the shape of
// newAutoSleepTestServer from toggle_auto_sleep_test.go so the two
// container-handler test files stay readable side-by-side.
func newTTLTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, *[]ttlMockCall, *incustest.MockBackend) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for name, info := range seed {
		mock.Containers[name] = info
	}
	var mu sync.Mutex
	calls := make([]ttlMockCall, 0, 4)
	mock.SetConfigFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, ttlMockCall{kind: "set", name: name, key: key, value: value})
		// Persist into the mock so subsequent Get reflects the change.
		if c, ok := mock.Containers[name]; ok && key == incus.TTLExpiresAtKey {
			if t2, err := time.Parse(time.RFC3339, value); err == nil {
				c.TTLExpiresAt = t2
			}
		}
		return nil
	}
	mock.UnsetConfigFunc = func(name, key string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, ttlMockCall{kind: "unset", name: name, key: key})
		if c, ok := mock.Containers[name]; ok && key == incus.TTLExpiresAtKey {
			c.TTLExpiresAt = time.Time{}
		}
		return nil
	}
	mgr := container.NewWithBackend(mock)
	return &ContainerServer{manager: mgr}, &calls, mock
}

// TestSetContainerTTL_ValidDurationStampsExpiry — happy path: a 1h TTL
// yields one SetConfig call with an RFC3339 value ~1h in the future,
// and the response echoes the same instant.
func TestSetContainerTTL_ValidDurationStampsExpiry(t *testing.T) {
	s, calls, _ := newTTLTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	before := time.Now().UTC()
	resp, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "alice",
		DurationSeconds: 3600,
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.TtlExpiresAt == nil {
		t.Fatalf("response missing TtlExpiresAt: %+v", resp)
	}
	got := resp.TtlExpiresAt.AsTime()
	lo := before.Add(1 * time.Hour).Add(-time.Second)
	hi := after.Add(1 * time.Hour).Add(time.Second)
	if got.Before(lo) || got.After(hi) {
		t.Errorf("response expiry %s outside [%s, %s]", got, lo, hi)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 SetConfig call, got %d: %+v", len(*calls), *calls)
	}
	c := (*calls)[0]
	if c.kind != "set" || c.name != "alice-container" || c.key != incus.TTLExpiresAtKey {
		t.Errorf("call = %+v, want set alice-container/%s", c, incus.TTLExpiresAtKey)
	}
	stamped, err := time.Parse(time.RFC3339, c.value)
	if err != nil {
		t.Fatalf("stamped value %q not RFC3339: %v", c.value, err)
	}
	// The stamped value must match the response (modulo nanosecond
	// truncation — RFC3339 has 1s resolution, the response carries
	// the original Time).
	if !stamped.Equal(got.Truncate(time.Second)) {
		t.Errorf("stamped %s != response %s (truncated)", stamped, got.Truncate(time.Second))
	}
}

// TestSetContainerTTL_DurationExceedsMax — the cap rejects 8 days.
func TestSetContainerTTL_DurationExceedsMax(t *testing.T) {
	s, calls, _ := newTTLTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	_, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "alice",
		DurationSeconds: 8 * 24 * 60 * 60, // 8 days
	})
	if err == nil {
		t.Fatal("expected error for duration > 7 days")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
	if len(*calls) != 0 {
		t.Errorf("rejected request must not call Set/UnsetConfig, got %d calls: %+v", len(*calls), *calls)
	}
}

// TestSetContainerTTL_NegativeDuration — negative values are rejected
// (vs. silently clamped to 0 = clear) so a typo doesn't accidentally
// nuke the existing TTL.
func TestSetContainerTTL_NegativeDuration(t *testing.T) {
	s, calls, _ := newTTLTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	_, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "alice",
		DurationSeconds: -1,
	})
	if err == nil {
		t.Fatal("expected error for negative duration")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
	if len(*calls) != 0 {
		t.Errorf("rejected request must not call Set/UnsetConfig, got %d calls: %+v", len(*calls), *calls)
	}
}

// TestSetContainerTTL_ZeroClearsKey — duration_seconds == 0 takes the
// unset path: one UnsetConfig call, response TtlExpiresAt unset.
func TestSetContainerTTL_ZeroClearsKey(t *testing.T) {
	existing := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	s, calls, _ := newTTLTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {
			Name:         "alice-container",
			State:        "Running",
			TTLExpiresAt: existing,
		},
	})
	resp, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "alice",
		DurationSeconds: 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.TtlExpiresAt != nil {
		t.Errorf("clear response should have nil TtlExpiresAt, got %v", resp.TtlExpiresAt)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 UnsetConfig call, got %d: %+v", len(*calls), *calls)
	}
	c := (*calls)[0]
	if c.kind != "unset" || c.name != "alice-container" || c.key != incus.TTLExpiresAtKey {
		t.Errorf("call = %+v, want unset alice-container/%s", c, incus.TTLExpiresAtKey)
	}
}

// TestSetContainerTTL_UnknownContainer — NotFound, not Internal.
func TestSetContainerTTL_UnknownContainer(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetContainerFunc = func(name string) (*incus.ContainerInfo, error) {
		return nil, errors.New("container not found: " + name)
	}
	s := &ContainerServer{manager: container.NewWithBackend(mock)}
	_, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "ghost",
		DurationSeconds: 3600,
	})
	if err == nil {
		t.Fatal("expected error for missing container")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Errorf("error = %v, want NotFound status", err)
	}
}

// TestSetContainerTTL_MissingName — universal precondition check.
func TestSetContainerTTL_MissingName(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{DurationSeconds: 3600})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
}

// TestSetContainerTTL_CoreContainerRejected — core containers must
// never carry a TTL (the autosleep handler enforces the same rule;
// keep the symmetry so an operator can't pin a 1h TTL on
// caddy-container by accident).
func TestSetContainerTTL_CoreContainerRejected(t *testing.T) {
	s, calls, _ := newTTLTestServer(t, map[string]*incus.ContainerInfo{
		"caddy-container": {
			Name:  "caddy-container",
			State: "Running",
			Role:  incus.RoleCaddy,
		},
	})
	_, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "caddy",
		DurationSeconds: 3600,
	})
	if err == nil {
		t.Fatal("expected error for core container")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
	if len(*calls) != 0 {
		t.Errorf("core rejection must not call Set/UnsetConfig, got %d calls: %+v", len(*calls), *calls)
	}
}

// TestSetContainerTTL_BoundaryMaxAccepted — exactly 7 days is OK; one
// second over is rejected (covered above). Locks the inclusive
// boundary so it doesn't drift on a future refactor.
func TestSetContainerTTL_BoundaryMaxAccepted(t *testing.T) {
	s, _, _ := newTTLTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	resp, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
		Name:            "alice",
		DurationSeconds: 7 * 24 * 60 * 60,
	})
	if err != nil {
		t.Fatalf("7d should be accepted, got error: %v", err)
	}
	if resp == nil || resp.TtlExpiresAt == nil {
		t.Errorf("7d accept should return TtlExpiresAt, got %+v", resp)
	}
}
