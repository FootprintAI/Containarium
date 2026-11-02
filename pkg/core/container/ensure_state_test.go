package container

import (
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func ensureStateMock(state string) *incustest.MockBackend {
	m := incustest.NewMockBackend()
	m.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: state}
	return m
}

func TestStopIfRunning(t *testing.T) {
	boom := errors.New("incus exploded")
	tests := []struct {
		name        string
		state       string
		stopErr     error
		stateAfter  string // state the instance has once the stop errored (race)
		wantChanged bool
		wantErr     bool
		wantStops   int
	}{
		{name: "running stops", state: "Running", wantChanged: true, wantStops: 1},
		{name: "already stopped is a no-op without an action", state: "Stopped", wantChanged: false, wantStops: 0},
		{name: "race: backend says already stopped and instance is Stopped", state: "Running",
			stopErr:    errors.New("failed to stop container (operation failed): The instance is already stopped"),
			stateAfter: "Stopped", wantChanged: false, wantStops: 1},
		{name: "genuine failure is not masked", state: "Running", stopErr: boom, stateAfter: "Running", wantErr: true, wantStops: 1},
		{name: "already-stopped text but instance still Running is an error", state: "Running",
			stopErr: errors.New("The instance is already stopped"), stateAfter: "Running", wantErr: true, wantStops: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := ensureStateMock(tc.state)
			stops := 0
			m.StopContainerFunc = func(name string, force bool) error {
				stops++
				if tc.stopErr != nil {
					m.Containers[name].State = tc.stateAfter
					return tc.stopErr
				}
				m.Containers[name].State = "Stopped"
				return nil
			}
			changed, err := NewWithBackend(m).StopIfRunning("alice", false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if stops != tc.wantStops {
				t.Errorf("backend stops = %d, want %d", stops, tc.wantStops)
			}
		})
	}
}

func TestStopIfRunning_LookupErrorPropagates(t *testing.T) {
	m := incustest.NewMockBackend()
	lookup := errors.New("lookup broke")
	m.GetContainerFunc = func(string) (*incus.ContainerInfo, error) { return nil, lookup }
	if _, err := NewWithBackend(m).StopIfRunning("alice", false); !errors.Is(err, lookup) {
		t.Fatalf("err = %v, want the lookup error", err)
	}
}

func TestStartIfStopped(t *testing.T) {
	boom := errors.New("incus exploded")
	tests := []struct {
		name        string
		state       string
		startErr    error
		stateAfter  string
		wantChanged bool
		wantErr     bool
		wantStarts  int
	}{
		{name: "stopped starts", state: "Stopped", wantChanged: true, wantStarts: 1},
		{name: "already running is a no-op", state: "Running", wantStarts: 0},
		{name: "race: already running", state: "Stopped", startErr: errors.New("The instance is already running"),
			stateAfter: "Running", wantStarts: 1},
		{name: "genuine failure is not masked", state: "Stopped", startErr: boom, stateAfter: "Stopped", wantErr: true, wantStarts: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := ensureStateMock(tc.state)
			starts := 0
			m.StartContainerFunc = func(name string) error {
				starts++
				if tc.startErr != nil {
					m.Containers[name].State = tc.stateAfter
					return tc.startErr
				}
				m.Containers[name].State = "Running"
				return nil
			}
			changed, err := NewWithBackend(m).StartIfStopped("alice")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if starts != tc.wantStarts {
				t.Errorf("backend starts = %d, want %d", starts, tc.wantStarts)
			}
		})
	}
}
