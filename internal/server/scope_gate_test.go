package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.7b — daemon-side scope enforcement on the hot-path
// handlers. Pairs with the MCP-side filter landed in PR #250.
//
// Each test below confirms that:
//   1. A scoped JWT that DOESN'T grant the required scope is
//      rejected with PermissionDenied — even when the role
//      and tenant checks would otherwise pass.
//   2. A scoped JWT that DOES grant the required scope clears
//      the scope gate (downstream nil-dep panics are fine —
//      they confirm the gate is structural, not coincidental).
//
// As with the Phase 1.4 RBAC tests, servers are constructed
// with nil deps; a passing test means the scope gate fires
// BEFORE any nil-deref.

func tenantWithScopes(name string, scopes ...string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		name, []string{"user"}, scopes,
	)
}

// helper that wraps a call and asserts it does NOT return
// PermissionDenied. The handler may nil-deref after the gate
// passes; that's expected and proves the gate fired.
func mustPassScope(t *testing.T, label string, fn func() error) {
	t.Helper()
	defer func() {
		_ = recover()
	}()
	err := fn()
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("%s: scope gate must NOT reject this caller; got %v", label, err)
	}
}

// --- SecretsServer ---

func TestSecrets_RejectsMissingWriteScope(t *testing.T) {
	srv := &ContainerServer{}
	ctx := tenantWithScopes("alice", auth.ScopeSecretsRead) // read-only
	_, err := srv.SetSecret(ctx, &pb.SetSecretRequest{Username: "alice", Name: "X", Value: "y"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetSecret without secrets:write: got %v", err)
	}
	_, err = srv.DeleteSecret(ctx, &pb.DeleteSecretRequest{Username: "alice", Name: "X"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DeleteSecret without secrets:write: got %v", err)
	}
	_, err = srv.RefreshSecrets(ctx, &pb.RefreshSecretsRequest{Username: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RefreshSecrets without secrets:write: got %v", err)
	}
}

func TestSecrets_RejectsMissingReadScope(t *testing.T) {
	srv := &ContainerServer{}
	ctx := tenantWithScopes("alice", auth.ScopeSecretsWrite) // write-only
	_, err := srv.GetSecret(ctx, &pb.GetSecretRequest{Username: "alice", Name: "X"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetSecret without secrets:read: got %v", err)
	}
	_, err = srv.ListSecrets(ctx, &pb.ListSecretsRequest{Username: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListSecrets without secrets:read: got %v", err)
	}
}

func TestSecrets_PassesWithCorrectScope(t *testing.T) {
	srv := &ContainerServer{}
	ctxRW := tenantWithScopes("alice", auth.ScopeSecretsRead, auth.ScopeSecretsWrite)
	mustPassScope(t, "SetSecret", func() error {
		_, e := srv.SetSecret(ctxRW, &pb.SetSecretRequest{Username: "alice", Name: "X", Value: "y"})
		return e
	})
	mustPassScope(t, "GetSecret", func() error {
		_, e := srv.GetSecret(ctxRW, &pb.GetSecretRequest{Username: "alice", Name: "X"})
		return e
	})
}

// --- ContainerServer CRUD ---

func TestContainerWrite_RejectsMissingScope(t *testing.T) {
	srv := &ContainerServer{}
	ctx := tenantWithScopes("alice", auth.ScopeContainersRead) // read-only
	cases := map[string]func() error{
		"Create": func() error {
			_, e := srv.CreateContainer(ctx, &pb.CreateContainerRequest{Username: "alice"})
			return e
		},
		"Delete": func() error {
			_, e := srv.DeleteContainer(ctx, &pb.DeleteContainerRequest{Username: "alice"})
			return e
		},
		"Start": func() error {
			_, e := srv.StartContainer(ctx, &pb.StartContainerRequest{Username: "alice"})
			return e
		},
		"Stop": func() error {
			_, e := srv.StopContainer(ctx, &pb.StopContainerRequest{Username: "alice"})
			return e
		},
		"Resize": func() error {
			_, e := srv.ResizeContainer(ctx, &pb.ResizeContainerRequest{Username: "alice"})
			return e
		},
		"ToggleMonitoring": func() error {
			_, e := srv.ToggleMonitoring(ctx, &pb.ToggleMonitoringRequest{Username: "alice"})
			return e
		},
		"ToggleAutoSleep": func() error {
			_, e := srv.ToggleAutoSleep(ctx, &pb.ToggleAutoSleepRequest{Username: "alice"})
			return e
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if err := call(); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("%s without containers:write: got %v", name, err)
			}
		})
	}
}

func TestContainerRead_RejectsMissingScope(t *testing.T) {
	srv := &ContainerServer{}
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite) // write-only
	_, err := srv.GetContainer(ctx, &pb.GetContainerRequest{Username: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetContainer without containers:read: got %v", err)
	}
	_, err = srv.ListContainers(ctx, &pb.ListContainersRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListContainers without containers:read: got %v", err)
	}
}

// --- SSH key writes (ssh:write scope) ---

func TestSSHKey_RejectsMissingScope(t *testing.T) {
	srv := &ContainerServer{}
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	_, err := srv.AddSSHKey(ctx, &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: "ssh-ed25519 AAAA..."})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddSSHKey without ssh:write: got %v", err)
	}
	_, err = srv.RemoveSSHKey(ctx, &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: "ssh-ed25519 AAAA..."})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RemoveSSHKey without ssh:write: got %v", err)
	}
}

// --- NetworkServer routes ---

func TestRouteMutations_RejectMissingScope(t *testing.T) {
	srv := &NetworkServer{}
	ctx := tenantWithScopes("ops", auth.ScopeRoutesRead) // read-only
	_, err := srv.AddRoute(ctx, &pb.AddRouteRequest{Domain: "x", TargetIp: "1.2.3.4", TargetPort: 80})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddRoute without routes:write: got %v", err)
	}
	_, err = srv.UpdateRoute(ctx, &pb.UpdateRouteRequest{Domain: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("UpdateRoute without routes:write: got %v", err)
	}
	_, err = srv.DeleteRoute(ctx, &pb.DeleteRouteRequest{Domain: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DeleteRoute without routes:write: got %v", err)
	}
}

func TestRouteRead_RejectsMissingScope(t *testing.T) {
	srv := &NetworkServer{}
	ctx := tenantWithScopes("ops", auth.ScopeRoutesWrite) // write-only
	_, err := srv.GetRoutes(ctx, &pb.GetRoutesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetRoutes without routes:read: got %v", err)
	}
}

// --- Backwards compat: pre-1.7 tokens (no scopes claim) ---

func TestPre17Tokens_PassAllScopes(t *testing.T) {
	// A token with no scopes claim must continue to work.
	// auth.HasScope treats nil grants as unrestricted —
	// this asserts the wire-through behavior end-to-end.
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	mustPassScope(t, "GetContainer", func() error {
		_, e := srv.GetContainer(ctx, &pb.GetContainerRequest{Username: "alice"})
		return e
	})
	mustPassScope(t, "DeleteContainer", func() error {
		_, e := srv.DeleteContainer(ctx, &pb.DeleteContainerRequest{Username: "alice"})
		return e
	})
}
