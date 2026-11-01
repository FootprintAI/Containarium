package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	corecontainer "github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A configured level is not enough: BUILD_TOOLS must have the managed mount.
// A missing host installation must not prevent NONE or FULL_SUDO runs.
func TestStartBoxRun_MissingManagedToolchain(t *testing.T) {
	for _, tc := range []struct {
		level, mount string
		refused      bool
	}{
		{"build_tools", "absent", true},
		{"build_tools", "nil", true},
		{"build_tools", "readonly", false},
		{"build_tools", "broken", true},
		{"none", "absent", false},
		{"full_sudo", "absent", false},
		{"none", "broken", false},
		{"full_sudo", "broken", false},
	} {
		t.Run(tc.level+"/"+tc.mount, func(t *testing.T) {
			spawned := false
			s := &ContainerServer{
				boxRunLogDir:     t.TempDir(),
				boxRunToolAccess: func(context.Context, string) (string, error) { return tc.level, nil },
				boxRunExec: func(_, script string) (string, error) {
					if strings.Contains(script, "useradd") {
						return "/home/ctn-run\n", nil
					}
					return "", nil
				},
				boxRunStartExec: func(_, _, script string) (string, error) {
					switch {
					case script == boxRunHomeAndConfigScript():
						return "/home/alice\n", nil
					case script == signInProbeScript(t):
						return "interactive\n", nil
					case strings.Contains(script, "setsid"):
						spawned = true
						return "4242 boot-1\n", nil
					}
					return "", nil
				},
			}
			if tc.mount != "nil" {
				s.boxRunEnsureToolchain = func(username string) error {
					if username != "alice" || spawned {
						t.Fatal("must attach this box before spawning")
					}
					if tc.mount == "absent" {
						return fmt.Errorf("%w: release absent", corecontainer.ErrManagedToolchainHostMissing)
					}
					if tc.mount == "broken" {
						return errors.New("mount is not read-only")
					}
					return nil
				}
			}
			_, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "build"})
			if tc.refused {
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "/opt/containarium/toolchains") {
					t.Fatalf("missing mount: got %v, want FailedPrecondition naming mount", err)
				}
				if spawned {
					t.Fatal("run spawned without the toolchain mount")
				}
				st, _ := status.FromError(err)
				wantTyped := tc.mount == "absent"
				gotTyped := false
				for _, d := range st.Details() {
					if pf, ok := d.(*errdetails.PreconditionFailure); ok {
						for _, v := range pf.GetViolations() {
							gotTyped = gotTyped || v.GetType() == BoxRunViolationHostManagedToolchainMissing
						}
					}
				}
				if gotTyped != wantTyped {
					t.Fatalf("typed missing-host reason = %v, want %v; details=%v", gotTyped, wantTyped, st.Details())
				}
			} else if err != nil || !spawned {
				t.Fatalf("%s/%s should run: spawned=%v err=%v", tc.level, tc.mount, spawned, err)
			}
		})
	}
}

func TestStartBoxRunCommand_MissingManagedToolchainHasTypedReason(t *testing.T) {
	spawned := false
	s := &ContainerServer{
		boxRunLogDir:     t.TempDir(),
		boxRunToolAccess: func(context.Context, string) (string, error) { return "build_tools", nil },
		boxRunEnsureToolchain: func(string) error {
			return fmt.Errorf("%w: release absent", corecontainer.ErrManagedToolchainHostMissing)
		},
		boxRunExec: func(_, script string) (string, error) {
			if strings.Contains(script, "useradd") {
				return "/home/ctn-run\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(_, _, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n", nil
			case strings.Contains(script, "setsid"):
				spawned = true
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	_, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Command: "make", TimeoutSeconds: 60})
	if status.Code(err) != codes.FailedPrecondition || spawned {
		t.Fatalf("spawned=%v err=%v", spawned, err)
	}
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				if v.GetType() == BoxRunViolationHostManagedToolchainMissing {
					return
				}
			}
		}
	}
	t.Fatalf("missing typed reason: %v", st.Details())
}

func TestBoxRunToolchainRefusalDoesNotTypeOtherEnsureFailures(t *testing.T) {
	err := boxRunToolchainRefusal(errors.New("attach failed"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v", status.Code(err))
	}
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok && len(pf.GetViolations()) > 0 && pf.GetViolations()[0].GetType() == BoxRunViolationHostManagedToolchainMissing {
			t.Fatalf("ordinary ensure failure got missing-host type: %v", d)
		}
	}
}
