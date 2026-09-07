package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestGetConsoleLog_ReturnsLogForVMInstance(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetConsoleLogFunc = func(name string) (string, error) {
		if name != "alice-container" {
			t.Fatalf("unexpected container name: %s", name)
		}
		return "BIOS POST...\nboot hung here\n", nil
	}
	cs := &ContainerServer{manager: container.NewWithBackend(mock)}

	resp, err := cs.GetConsoleLog(testCtx(), &pb.GetConsoleLogRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Log != "BIOS POST...\nboot hung here\n" {
		t.Fatalf("unexpected log content: %q", resp.Log)
	}
}

func TestGetConsoleLog_LXCContainerReturnsEmptyNotError(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetConsoleLogFunc = func(name string) (string, error) {
		return "", errors.New("instance is not a VM")
	}
	cs := &ContainerServer{manager: container.NewWithBackend(mock)}

	resp, err := cs.GetConsoleLog(testCtx(), &pb.GetConsoleLogRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("expected no error for a container with no console device, got: %v", err)
	}
	if resp.Log != "" {
		t.Fatalf("expected empty log, got: %q", resp.Log)
	}
}

func TestGetConsoleLog_RequiresUsername(t *testing.T) {
	cs := &ContainerServer{manager: container.NewWithBackend(incustest.NewMockBackend())}

	if _, err := cs.GetConsoleLog(testCtx(), &pb.GetConsoleLogRequest{}); err == nil {
		t.Fatal("expected an error for an empty username")
	}
}

func TestGetConsoleLog_AuthGuard(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetConsoleLogFunc = func(name string) (string, error) { return "log", nil }
	cs := &ContainerServer{manager: container.NewWithBackend(mock)}

	t.Run("unauthenticated", func(t *testing.T) {
		if _, err := cs.GetConsoleLog(context.Background(), &pb.GetConsoleLogRequest{Username: "alice"}); err == nil {
			t.Fatal("returned console log to a caller with no authenticated subject")
		}
	})

	t.Run("wrong tenant", func(t *testing.T) {
		ctx := auth.ContextWithTestSubjectScopes(context.Background(), "mallory",
			[]string{"user"}, []string{auth.ScopeContainersRead})
		if _, err := cs.GetConsoleLog(ctx, &pb.GetConsoleLogRequest{Username: "alice"}); err == nil {
			t.Fatal("returned alice's console log to a caller authenticated as mallory")
		}
	})

	t.Run("own tenant", func(t *testing.T) {
		ctx := auth.ContextWithTestSubjectScopes(context.Background(), "alice",
			[]string{"user"}, []string{auth.ScopeContainersRead})
		if _, err := cs.GetConsoleLog(ctx, &pb.GetConsoleLogRequest{Username: "alice"}); err != nil {
			t.Fatalf("unexpected error for a caller reading their own console log: %v", err)
		}
	})
}
