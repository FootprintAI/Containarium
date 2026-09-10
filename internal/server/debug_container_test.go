package server

import (
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/stretchr/testify/assert"
)

func TestDiagnose(t *testing.T) {
	type tc struct {
		name         string
		report       *pb.DebugContainerResponse
		wantCause    string
		wantActionCt int
		wantFirstHas string
	}
	cases := []tc{
		{
			name:         "missing container",
			report:       &pb.DebugContainerResponse{ContainerState: "missing"},
			wantCause:    "does not exist",
			wantActionCt: 2,
			wantFirstHas: "create the container",
		},
		{
			name:         "stopped container",
			report:       &pb.DebugContainerResponse{ContainerState: "stopped"},
			wantCause:    "stopped",
			wantActionCt: 2,
			wantFirstHas: "start",
		},
		{
			// Three actions since #1478: dry-run preview, the repair, then
			// delete+recreate LAST. The first must be non-destructive — the
			// container and its data are intact in this failure mode, so an
			// operator reading top-down must not meet "destroy the box" first.
			name: "running but host user missing",
			report: &pb.DebugContainerResponse{
				ContainerState: "running",
				HostUserExists: false,
			},
			wantCause:    "host-level Linux user is missing",
			wantActionCt: 3,
			wantFirstHas: "sync-accounts",
		},
		{
			name: "running, user exists, shell file missing",
			report: &pb.DebugContainerResponse{
				ContainerState:      "running",
				HostUserExists:      true,
				HostUserShell:       "/usr/local/bin/containarium-shell",
				HostUserShellExists: false,
			},
			wantCause:    "shell",
			wantActionCt: 2,
			wantFirstHas: "containarium-shell",
		},
		{
			// Sentinel-fronted backend (ssh_ingress_host advertised): the
			// diagnosis points at the sentinel-side state to check next (#1011).
			name: "running, all healthy, sentinel-fronted",
			report: &pb.DebugContainerResponse{
				ContainerState:      "running",
				HostUserExists:      true,
				HostUserShell:       "/usr/local/bin/containarium-shell",
				HostUserShellExists: true,
				SshIngressHost:      "asia-east1.containarium.dev",
			},
			wantCause:    "check sentinel-side state",
			wantActionCt: 4,
			wantFirstHas: "sshpiper",
		},
		{
			// Direct / in-network backend (no ssh_ingress_host): #1011 suppresses
			// the sentinel boilerplate — there is no sentinel hop to check.
			name: "running, all healthy, no ssh ingress host",
			report: &pb.DebugContainerResponse{
				ContainerState:      "running",
				HostUserExists:      true,
				HostUserShell:       "/usr/local/bin/containarium-shell",
				HostUserShellExists: true,
			},
			wantCause:    "no obvious host-side problem",
			wantActionCt: 3,
			wantFirstHas: "connect directly",
		},
		{
			name: "sshd accepted publickey recently",
			report: &pb.DebugContainerResponse{
				ContainerState:      "running",
				HostUserExists:      true,
				HostUserShell:       "/usr/local/bin/containarium-shell",
				HostUserShellExists: true,
				RecentSshdRejections: []string{
					"May 11 06:43:08 host sshd[11051]: Accepted publickey for alice from 1.2.3.4 port 37757 ssh2",
				},
			},
			wantCause:    "sshd accepted publickey",
			wantActionCt: 2,
		},
		{
			name:         "daemon error querying state",
			report:       &pb.DebugContainerResponse{ContainerState: "error: incus connection refused"},
			wantCause:    "daemon failed",
			wantActionCt: 1,
		},
		{
			// #1487: host user + shell both healthy, but the SAME username
			// was never created inside the container — containarium-shell's
			// `su` dies there, several layers past every check above this
			// one. Must fire BEFORE the sshd-journal/sentinel fallback
			// branches, not after — those would misdiagnose this as "no
			// obvious host-side problem".
			name: "running, host user healthy, in-container user missing",
			report: &pb.DebugContainerResponse{
				ContainerState:         "running",
				HostUserExists:         true,
				HostUserShell:          "/usr/local/bin/containarium-shell",
				HostUserShellExists:    true,
				InContainerUserMissing: true,
				SshIngressHost:         "asia-east1.containarium.dev",
			},
			wantCause:    "never created INSIDE the container",
			wantActionCt: 3,
			wantFirstHas: "incus exec",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cause, actions := Diagnose("alice", c.report)
			assert.Contains(t, cause, c.wantCause)
			assert.Len(t, actions, c.wantActionCt)
			if c.wantFirstHas != "" && len(actions) > 0 {
				assert.Contains(t, actions[0], c.wantFirstHas)
			}
		})
	}
}

// TestInContainerUserMissing exercises the exec-based check in isolation
// from the sshd/passwd inspection above — it should distinguish a genuine
// "id ran and found no such user" (exitCode != 0, err == nil) from "the
// exec itself couldn't run" (err != nil: transport/backend problem), the
// latter deliberately reported as false rather than a false-positive
// "missing".
func TestInContainerUserMissing(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
		execErr  error
		want     bool
	}{
		{name: "user exists — id exits 0", exitCode: 0, want: false},
		{name: "user missing — id exits non-zero, no error", exitCode: 1, want: true},
		{name: "exec transport error — unknown, not missing", execErr: errors.New("incus: connection refused"), want: false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			mock := incustest.NewMockBackend()
			mock.ExecWithExitCodeFunc = func(name string, cmd []string) (string, string, int, error) {
				if name != "alice-container" {
					t.Fatalf("unexpected container name: %s", name)
				}
				if len(cmd) != 2 || cmd[0] != "id" || cmd[1] != "alice" {
					t.Fatalf("unexpected command: %v", cmd)
				}
				return "", "", c.exitCode, c.execErr
			}
			cs := &ContainerServer{manager: container.NewWithBackend(mock)}

			got := cs.inContainerUserMissing("alice")
			if got != c.want {
				t.Fatalf("inContainerUserMissing() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestExtractReason(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"May 11 sshd[42]: User x not allowed because shell does not exist", "User x not allowed because shell does not exist"},
		{"no colon space line", "no colon space line"},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, extractReason(c.in))
	}
}
