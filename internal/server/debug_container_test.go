package server

import (
	"testing"

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
			name: "running but host user missing",
			report: &pb.DebugContainerResponse{
				ContainerState: "running",
				HostUserExists: false,
			},
			wantCause:    "host-level Linux user is missing",
			wantActionCt: 2,
			wantFirstHas: "recreate the container",
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
			name: "running, all healthy",
			report: &pb.DebugContainerResponse{
				ContainerState:      "running",
				HostUserExists:      true,
				HostUserShell:       "/usr/local/bin/containarium-shell",
				HostUserShellExists: true,
			},
			wantCause:    "no obvious host-side problem",
			wantActionCt: 3,
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
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cause, actions := diagnose("alice", c.report)
			assert.Contains(t, cause, c.wantCause)
			assert.Len(t, actions, c.wantActionCt)
			if c.wantFirstHas != "" && len(actions) > 0 {
				assert.Contains(t, actions[0], c.wantFirstHas)
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
