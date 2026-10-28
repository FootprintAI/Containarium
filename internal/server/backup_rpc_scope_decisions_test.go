package server

import (
	"bytes"
	"context"
	"log"
	"sort"
	"strings"
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
	"VerifyBackup": {auth.ScopeBackupsVerify, func(ctx context.Context, s *BackupServer) error {
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
			other := []string{"containers:read", "secrets:read"}
			for _, scope := range []string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite, auth.ScopeBackupsVerify} {
				if scope != d.scope {
					other = append(other, scope)
				}
			}
			wrong := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, other)
			if c := status.Code(callBackupRPC(wrong, bs, name)); c != codes.PermissionDenied {
				t.Fatalf("without %s: code = %v, want PermissionDenied", d.scope, c)
			}
			if d.crossTenant == nil {
				return
			}
			// With the right scope, another tenant's data is still refused.
			right := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, []string{d.scope})
			if c := status.Code(d.crossTenant(right, bs)); c != codes.PermissionDenied {
				t.Fatalf("cross-tenant: code = %v, want PermissionDenied", c)
			}
		})
	}
}

// TestBackupRPCScopeDecisions_VerifyScopeRefusedOnWriteRPCs is the reason
// backups:verify exists: a token holding it (and backups:read) can verify its
// own tenant's backups but is refused every RPC that creates, restores,
// deletes or prunes. Granting it any of those RPCs makes this test fail.
func TestBackupRPCScopeDecisions_VerifyScopeRefusedOnWriteRPCs(t *testing.T) {
	_, bs := verifierServer(t)
	ctx := verifierCtx("alice")
	for _, name := range []string{"CreateBackup", "CreateBackup/BOX", "RestoreBackup", "DeleteBackup", "PruneBackups"} {
		t.Run(name+" refused", func(t *testing.T) {
			if c := status.Code(callBackupRPC(ctx, bs, name)); c != codes.PermissionDenied {
				t.Fatalf("verify-only token on %s: code = %v, want PermissionDenied", name, c)
			}
		})
	}
	for _, name := range []string{"ListBackups", "GetBackup", "VerifyBackup"} {
		t.Run(name+" allowed", func(t *testing.T) {
			if c := status.Code(callBackupRPC(ctx, bs, name)); c == codes.PermissionDenied || c == codes.Unauthenticated {
				t.Fatalf("verify-only token on %s: code = %v, want it to pass the scope gate", name, c)
			}
		})
	}
}

// The v0.120.1 deprecation window has ended (#3219). A write-only token is
// refused with re-mint instructions; the ordinary wildcard, unscoped-token
// and strict-mode rules are unchanged.
func TestBackupRPCScopeDecisions_VerifyRequiresVerifyScope(t *testing.T) {
	prevStrict := auth.StrictScopesEnabled()
	t.Cleanup(func() { auth.SetStrictScopes(prevStrict) })
	for _, tc := range []struct {
		name   string
		scopes []string // nil = a token with no scopes claim
		strict bool
		want   codes.Code
	}{
		{"legacy write only", []string{auth.ScopeBackupsWrite}, false, codes.PermissionDenied},
		{"legacy read and write", []string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite}, false, codes.PermissionDenied},
		{"read only", []string{auth.ScopeBackupsRead}, false, codes.PermissionDenied},
		{"empty scopes", []string{}, false, codes.PermissionDenied},
		{"verify only", []string{auth.ScopeBackupsVerify}, false, codes.OK},
		{"read and verify", []string{auth.ScopeBackupsRead, auth.ScopeBackupsVerify}, false, codes.OK},
		{"both scopes", []string{auth.ScopeBackupsWrite, auth.ScopeBackupsVerify}, false, codes.OK},
		{"wildcard", []string{auth.ScopeWildcard}, false, codes.OK},
		{"no scopes claim", nil, false, codes.OK},
		{"no scopes claim strict", nil, true, codes.PermissionDenied},
		{"verify strict", []string{auth.ScopeBackupsVerify}, true, codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth.SetStrictScopes(tc.strict)
			_, bs := verifierServer(t)
			ctx := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, tc.scopes)
			resp, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "alice"})
			if got := status.Code(err); got != tc.want {
				t.Fatalf("VerifyBackup code = %v (%v), want %v", got, err, tc.want)
			}
			if tc.want == codes.PermissionDenied {
				for _, want := range []string{auth.ScopeBackupsVerify, "containarium token generate", "--scopes backups:read,backups:verify"} {
					if !strings.Contains(status.Convert(err).Message(), want) {
						t.Errorf("denial %q must include %q", err, want)
					}
				}
			} else if resp.Verification.GetResult() != pb.VerificationResult_VERIFICATION_RESULT_PASSED {
				t.Fatalf("verification failed: %+v", resp.Verification)
			}
		})
	}
}

// Reject legacy tokens before input validation or backup lookup, without
// logging caller-controlled fields through the removed deprecation path.
func TestBackupRPCScopeDecisions_VerifyLegacyRefusedBeforeRequestProcessing(t *testing.T) {
	for _, id := range []string{"", "alice-app-20261003T010000Z", "x\n[backup] DEPRECATED: forged user=\"root\""} {
		t.Run(id, func(t *testing.T) {
			_, bs := verifierServer(t)
			var buf bytes.Buffer
			prevOut := log.Writer()
			log.SetOutput(&buf)
			t.Cleanup(func() { log.SetOutput(prevOut) })
			ctx := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"},
				[]string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite})
			_, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: id, TargetUsername: "alice"})
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Errorf("VerifyBackup code = %v (%v), want PermissionDenied before processing the id", got, err)
			}
			if strings.Contains(buf.String(), "DEPRECATED:") {
				t.Errorf("removed deprecation path logged caller input: %q", buf.String())
			}
		})
	}
}

func TestBackupRPCScopeDecisions_VerifyUnauthenticated(t *testing.T) {
	_, err := (&BackupServer{}).VerifyBackup(context.Background(), &pb.VerifyBackupRequest{})
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("VerifyBackup code = %v (%v), want Unauthenticated", got, err)
	}
}
