package server

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func adminUpgradeCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "tester", auth.RoleAdmin)
}

// TriggerUpgrade and GetUpgradeStatus are admin-only (fleet-mutating /
// fleet-internal), matching the other System RPCs. #354.
func TestTriggerUpgrade_RequiresAdmin(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.TriggerUpgrade(context.Background(), &pb.TriggerUpgradeRequest{})
	if c := status.Code(err); c != codes.Unauthenticated && c != codes.PermissionDenied {
		t.Fatalf("want auth error, got %v", err)
	}
}

// A local upgrade with no auto-updater wired (no sentinel source) is Unavailable
// rather than a panic.
func TestTriggerUpgrade_LocalNoUpdater(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.TriggerUpgrade(adminUpgradeCtx(), &pb.TriggerUpgradeRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable (no auto-updater), got %v", err)
	}
	// cloud#1547: the message alone (no log access needed) must name the
	// missing flag, so a caller staring at a bare "no capacity in pool"
	// three hops away has something actionable to check.
	if !strings.Contains(err.Error(), "--sentinel-url") {
		t.Errorf("error = %q, want it to name the missing --sentinel-url flag", err.Error())
	}
}

// TestTriggerUpgrade_LocalNoUpdater_Logs is cloud#1547's root cause fix: this
// early return used to bail with NO log line at all, which is exactly what
// made a BYOC host's silently-missing --sentinel-url invisible — an operator
// SSHed into the target host during a failed upgrade saw nothing arrive,
// before or after, because the daemon never logged reaching this far. Now it
// does, before ever returning the error.
func TestTriggerUpgrade_LocalNoUpdater_Logs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	s := &ContainerServer{}
	_, err := s.TriggerUpgrade(adminUpgradeCtx(), &pb.TriggerUpgradeRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "upgrade") || !strings.Contains(out, "sentinel-url") {
		t.Errorf("log output = %q, want a line naming the upgrade attempt and the missing sentinel-url config", out)
	}
}

func TestGetUpgradeStatus_RequiresAdmin(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.GetUpgradeStatus(context.Background(), &pb.GetUpgradeStatusRequest{UpgradeId: "x"})
	if c := status.Code(err); c != codes.Unauthenticated && c != codes.PermissionDenied {
		t.Fatalf("want auth error, got %v", err)
	}
}

// An unrecognized id (or a job lost to a self-upgrade restart) reports "unknown"
// so callers fall back to comparing the version in ListBackends.
func TestGetUpgradeStatus_UnknownID(t *testing.T) {
	s := &ContainerServer{}
	resp, err := s.GetUpgradeStatus(adminUpgradeCtx(), &pb.GetUpgradeStatusRequest{UpgradeId: "nope"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "unknown" {
		t.Fatalf("want status %q, got %q", "unknown", resp.Status)
	}
}

func TestGetUpgradeStatus_EmptyID(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.GetUpgradeStatus(adminUpgradeCtx(), &pb.GetUpgradeStatusRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
