package server

import (
	"context"
	"sort"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// backupRPCDecision is the recorded scope decision for one BackupService
// RPC (#2401). Every RPC the service exposes must have an entry; adding an
// RPC without deciding its scope and tenant behavior fails the test below.
type backupRPCDecision struct {
	// scope is the scope a token must hold to call the RPC.
	scope string
	// crossTenant attempts the RPC as tenant alice against tenant bob's
	// data. It must be refused with PermissionDenied.
	crossTenant func(context.Context, *BackupServer) error
}

const bobBackupID = "bob-app-20261003T010000Z"

var backupRPCDecisions = map[string]backupRPCDecision{
	"CreateBackup": {auth.ScopeBackupsWrite, func(ctx context.Context, s *BackupServer) error {
		_, err := s.CreateBackup(ctx, &pb.CreateBackupRequest{Username: "bob"})
		return err
	}},
	"CreateBackup/BOX": {auth.ScopeBackupsWrite, func(ctx context.Context, s *BackupServer) error {
		_, err := s.CreateBackup(ctx, &pb.CreateBackupRequest{
			Username: "bob", Scope: pb.BackupScope_BACKUP_SCOPE_BOX,
			KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED,
		})
		return err
	}},
	// ListBackups for another tenant is rewritten to the caller's own
	// tenant rather than denied (see TestBackupScopedToken_AllowsOwnBackupsOnly),
	// so it has no denial to assert here.
	"ListBackups": {auth.ScopeBackupsRead, nil},
	"GetBackup": {auth.ScopeBackupsRead, func(ctx context.Context, s *BackupServer) error {
		_, err := s.GetBackup(ctx, &pb.GetBackupRequest{Id: bobBackupID})
		return err
	}},
	"RestoreBackup": {auth.ScopeBackupsWrite, func(ctx context.Context, s *BackupServer) error {
		_, err := s.RestoreBackup(ctx, &pb.RestoreBackupRequest{Id: bobBackupID})
		return err
	}},
	"VerifyBackup": {auth.ScopeBackupsWrite, func(ctx context.Context, s *BackupServer) error {
		_, err := s.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: bobBackupID, TargetUsername: "alice"})
		return err
	}},
	"DeleteBackup": {auth.ScopeBackupsWrite, func(ctx context.Context, s *BackupServer) error {
		_, err := s.DeleteBackup(ctx, &pb.DeleteBackupRequest{Id: bobBackupID})
		return err
	}},
	"PruneBackups": {auth.ScopeBackupsWrite, func(ctx context.Context, s *BackupServer) error {
		_, err := s.PruneBackups(ctx, &pb.PruneBackupsRequest{Username: "bob", Keep: 1})
		return err
	}},
}

// callBackupRPC invokes the named RPC with minimal valid input for alice's
// own data, used only to prove the scope gate fires first.
func callBackupRPC(ctx context.Context, s *BackupServer, name string) error {
	var err error
	switch name {
	case "CreateBackup", "CreateBackup/BOX":
		_, err = s.CreateBackup(ctx, &pb.CreateBackupRequest{Username: "alice"})
	case "ListBackups":
		_, err = s.ListBackups(ctx, &pb.ListBackupsRequest{})
	case "GetBackup":
		_, err = s.GetBackup(ctx, &pb.GetBackupRequest{Id: "alice-app-20261003T010000Z"})
	case "RestoreBackup":
		_, err = s.RestoreBackup(ctx, &pb.RestoreBackupRequest{Id: "alice-app-20261003T010000Z"})
	case "VerifyBackup":
		_, err = s.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "alice"})
	case "DeleteBackup":
		_, err = s.DeleteBackup(ctx, &pb.DeleteBackupRequest{Id: "alice-app-20261003T010000Z"})
	case "PruneBackups":
		_, err = s.PruneBackups(ctx, &pb.PruneBackupsRequest{Username: "alice", Keep: 1})
	default:
		panic("no caller for " + name)
	}
	return err
}

// TestBackupRPCScopeDecisions_CoversEveryRPC fails when BackupService gains
// (or loses) an RPC without the decision table above being updated, so a new
// backup RPC cannot ship without a deliberate scope and tenant-binding choice.
func TestBackupRPCScopeDecisions_CoversEveryRPC(t *testing.T) {
	var served []string
	for _, m := range pb.BackupService_ServiceDesc.Methods {
		served = append(served, m.MethodName)
	}
	var decided []string
	for name := range backupRPCDecisions {
		if name == "CreateBackup/BOX" {
			continue // a scope variant of CreateBackup, not a separate RPC
		}
		decided = append(decided, name)
	}
	sort.Strings(served)
	sort.Strings(decided)
	if len(served) != len(decided) {
		t.Fatalf("BackupService RPCs %v != decided RPCs %v: record a scope decision for every RPC in backupRPCDecisions", served, decided)
	}
	for i := range served {
		if served[i] != decided[i] {
			t.Fatalf("BackupService RPCs %v != decided RPCs %v: record a scope decision for every RPC in backupRPCDecisions", served, decided)
		}
	}
}

// TestBackupRPCScopeDecisions_Enforced checks each recorded decision against
// the real handlers: the required scope is enforced, and a token bound to one
// tenant is refused another tenant's data.
func TestBackupRPCScopeDecisions_Enforced(t *testing.T) {
	_, bs := verifierServer(t)
	for name, d := range backupRPCDecisions {
		t.Run(name, func(t *testing.T) {
			// A token holding every other scope but the required one is denied.
			other := []string{auth.ScopeBackupsRead}
			if d.scope == auth.ScopeBackupsRead {
				other = []string{auth.ScopeBackupsWrite, "containers:read", "secrets:read"}
			}
			wrong := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, other)
			if c := status.Code(callBackupRPC(wrong, bs, name)); c != codes.PermissionDenied {
				t.Fatalf("without %s: code = %v, want PermissionDenied", d.scope, c)
			}
			if d.crossTenant == nil {
				return
			}
			// With the right scope, another tenant's data is still refused.
			if c := status.Code(d.crossTenant(verifierCtx("alice"), bs)); c != codes.PermissionDenied {
				t.Fatalf("cross-tenant: code = %v, want PermissionDenied", c)
			}
		})
	}
}
