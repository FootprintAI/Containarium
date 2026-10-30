package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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
			if tc.mount != "absent" {
				s.boxRunEnsureToolchain = func(username string) error {
					if username != "alice" || spawned {
						t.Fatal("must attach this box before spawning")
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
			} else if err != nil || !spawned {
				t.Fatalf("%s/%s should run: spawned=%v err=%v", tc.level, tc.mount, spawned, err)
			}
		})
	}
}
