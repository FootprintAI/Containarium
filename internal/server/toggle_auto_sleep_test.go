package server

import (
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setConfigCall captures the args of one mocked SetConfig invocation.
type setConfigCall struct {
	name  string
	key   string
	value string
}

// newAutoSleepTestServer builds a ContainerServer wired to a mock
// incus.Backend + a real Manager, returning a slice the caller can
// inspect after handler invocation. seed populates the mock with
// initial container state.
func newAutoSleepTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, *[]setConfigCall, *incustest.MockBackend) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for name, info := range seed {
		mock.Containers[name] = info
	}
	var mu sync.Mutex
	calls := make([]setConfigCall, 0, 4)
	mock.SetConfigFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, setConfigCall{name: name, key: key, value: value})
		// Also persist into the mock state so subsequent Get() reflects
		// the change — mirrors real Incus semantics.
		if c, ok := mock.Containers[name]; ok {
			if key == incus.AutoSleepEnabledKey {
				c.AutoSleepEnabled = value == "true"
			}
			if key == incus.IdleThresholdMinutesKey {
				if n, err := strconv.Atoi(value); err == nil {
					c.IdleThresholdMinutes = safecast.I32(n)
				}
			}
		}
		return nil
	}
	mgr := container.NewWithBackend(mock)
	return &ContainerServer{manager: mgr}, &calls, mock
}

// TestToggleAutoSleep_EnableSetsFlagsAndThreshold — happy path: both
// the flag and an explicit threshold land in two SetConfig calls.
func TestToggleAutoSleep_EnableSetsFlagsAndThreshold(t *testing.T) {
	s, calls, _ := newAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	resp, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username:             "alice",
		Enabled:              true,
		IdleThresholdMinutes: 30,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.AutoSleepEnabled || resp.IdleThresholdMinutes != 30 {
		t.Errorf("response = %+v, want enabled=true, threshold=30", resp)
	}
	if len(*calls) != 2 {
		t.Fatalf("expected 2 SetConfig calls, got %d: %+v", len(*calls), *calls)
	}
	wantPairs := map[string]string{
		incus.AutoSleepEnabledKey:     "true",
		incus.IdleThresholdMinutesKey: "30",
	}
	for _, c := range *calls {
		if c.name != "alice-container" {
			t.Errorf("SetConfig name = %q, want alice-container", c.name)
		}
		if want, ok := wantPairs[c.key]; ok {
			if c.value != want {
				t.Errorf("SetConfig(%q) = %q, want %q", c.key, c.value, want)
			}
			delete(wantPairs, c.key)
		} else {
			t.Errorf("unexpected SetConfig key: %q", c.key)
		}
	}
	if len(wantPairs) != 0 {
		t.Errorf("missing SetConfig calls for: %v", wantPairs)
	}
}

// TestToggleAutoSleep_DisableSetsFlagOnly — disable writes only the
// enabled key. Threshold key is omitted so a re-enable restores
// whatever value the operator previously set.
func TestToggleAutoSleep_DisableSetsFlagOnly(t *testing.T) {
	s, calls, _ := newAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {
			Name: "alice-container", State: "Running",
			AutoSleepEnabled: true, IdleThresholdMinutes: 30,
		},
	})
	resp, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username: "alice",
		Enabled:  false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AutoSleepEnabled {
		t.Errorf("response.AutoSleepEnabled = true, want false")
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 SetConfig call on disable, got %d: %+v", len(*calls), *calls)
	}
	if (*calls)[0].key != incus.AutoSleepEnabledKey || (*calls)[0].value != "false" {
		t.Errorf("disable call = %+v, want %s=false", (*calls)[0], incus.AutoSleepEnabledKey)
	}
}

// TestToggleAutoSleep_DefaultThreshold — enable with idle=0 should
// apply the existing key (if present) or the package default.
func TestToggleAutoSleep_DefaultThreshold(t *testing.T) {
	s, calls, _ := newAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		// IdleThresholdMinutes set to default by parseIdleThresholdMinutes
		// when the mock omits the key — mirror that by setting the field.
		"alice-container": {
			Name: "alice-container", State: "Running",
			IdleThresholdMinutes: incus.DefaultIdleThresholdMinutes,
		},
	})
	resp, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username:             "alice",
		Enabled:              true,
		IdleThresholdMinutes: 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IdleThresholdMinutes != incus.DefaultIdleThresholdMinutes {
		t.Errorf("response threshold = %d, want default %d",
			resp.IdleThresholdMinutes, incus.DefaultIdleThresholdMinutes)
	}
	// Find the threshold SetConfig call — must encode the default.
	var sawThresholdSet bool
	for _, c := range *calls {
		if c.key == incus.IdleThresholdMinutesKey {
			sawThresholdSet = true
			if c.value != strconv.Itoa(incus.DefaultIdleThresholdMinutes) {
				t.Errorf("threshold SetConfig value = %q, want %d", c.value, incus.DefaultIdleThresholdMinutes)
			}
		}
	}
	if !sawThresholdSet {
		t.Errorf("expected threshold SetConfig with default; calls = %+v", *calls)
	}
}

// TestToggleAutoSleep_CoreContainerRejected — core containers are not
// user workloads; the handler must refuse and not call SetConfig.
func TestToggleAutoSleep_CoreContainerRejected(t *testing.T) {
	s, calls, _ := newAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"caddy-container": {
			Name: "caddy-container", State: "Running",
			Role: incus.RoleCaddy,
		},
	})
	_, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username: "caddy",
		Enabled:  true,
	})
	if err == nil {
		t.Fatal("expected error for core container")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
	if len(*calls) != 0 {
		t.Errorf("core container rejection must not call SetConfig, got %d calls", len(*calls))
	}
}

// TestToggleAutoSleep_NoSuchContainer — unknown username maps to a
// NotFound gRPC status code.
func TestToggleAutoSleep_NoSuchContainer(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetContainerFunc = func(name string) (*incus.ContainerInfo, error) {
		return nil, errors.New("container not found: " + name)
	}
	s := &ContainerServer{manager: container.NewWithBackend(mock)}
	_, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username: "ghost",
		Enabled:  true,
	})
	if err == nil {
		t.Fatal("expected error for missing container")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Errorf("error = %v, want NotFound status", err)
	}
}

// TestToggleAutoSleep_MissingUsername — universal precondition check.
func TestToggleAutoSleep_MissingUsername(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{Enabled: true})
	if err == nil {
		t.Fatal("expected error for empty username")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
}

// TestToggleAutoSleep_AcceptsStoppedContainer locks the brief's
// requirement: the toggle works on stopped containers too (Incus
// accepts config updates in either state).
func TestToggleAutoSleep_AcceptsStoppedContainer(t *testing.T) {
	s, calls, _ := newAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Stopped"},
	})
	resp, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username:             "alice",
		Enabled:              true,
		IdleThresholdMinutes: 20,
	})
	if err != nil {
		t.Fatalf("stopped container must be accepted, got error: %v", err)
	}
	if !resp.AutoSleepEnabled || resp.IdleThresholdMinutes != 20 {
		t.Errorf("response = %+v, want enabled=true threshold=20", resp)
	}
	if len(*calls) != 2 {
		t.Errorf("stopped container should still trigger both SetConfig calls, got %d", len(*calls))
	}
}

// TestToggleAutoSleep_NegativeThresholdClampsToDefault — current
// impl: negative `idle_threshold_minutes` falls through the `> 0`
// gate, so the stored container threshold (or default) wins. Lock
// that behavior.
func TestToggleAutoSleep_NegativeThresholdClampsToDefault(t *testing.T) {
	s, _, _ := newAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running",
			IdleThresholdMinutes: incus.DefaultIdleThresholdMinutes},
	})
	resp, err := s.ToggleAutoSleep(testCtx(), &pb.ToggleAutoSleepRequest{
		Username:             "alice",
		Enabled:              true,
		IdleThresholdMinutes: -5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IdleThresholdMinutes != incus.DefaultIdleThresholdMinutes {
		t.Errorf("threshold = %d, want default %d", resp.IdleThresholdMinutes, incus.DefaultIdleThresholdMinutes)
	}
}
