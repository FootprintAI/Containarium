package server

import (
	"bytes"
	"context"
	"log"
	"sort"
	"strconv"
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
			other := []string{auth.ScopeBackupsRead}
			if d.scope == auth.ScopeBackupsVerify {
				// VerifyBackup also accepts the broader write scope, so the
				// "wrong scope" token for it holds neither verify nor write.
				other = []string{auth.ScopeBackupsRead, "containers:write"}
			}
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
			if d.scope == auth.ScopeBackupsVerify {
				// The recorded scope is backups:verify, so the narrowed
				// token itself must also be refused another tenant's data.
				if c := status.Code(d.crossTenant(verifyOnlyCtx("alice"), bs)); c != codes.PermissionDenied {
					t.Fatalf("cross-tenant with %s token: code = %v, want PermissionDenied", d.scope, c)
				}
			}
		})
	}
}

// verifyOnlyCtx is the narrowed verifier token (#3186): one tenant, scopes
// exactly backups:read + backups:verify.
func verifyOnlyCtx(tenant string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), tenant, []string{"user"},
		[]string{auth.ScopeBackupsRead, auth.ScopeBackupsVerify})
}

// TestBackupRPCScopeDecisions_VerifyScopeRefusedOnWriteRPCs is the reason
// backups:verify exists: a token holding it (and backups:read) can verify its
// own tenant's backups but is refused every RPC that creates, restores,
// deletes or prunes. Granting it any of those RPCs makes this test fail.
func TestBackupRPCScopeDecisions_VerifyScopeRefusedOnWriteRPCs(t *testing.T) {
	_, bs := verifierServer(t)
	ctx := verifyOnlyCtx("alice")
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

// TestBackupRPCScopeDecisions_VerifyAcceptsLegacyWriteScope pins the
// one-release deprecation window (#3186, Q8 on #3196): tokens minted before
// backups:verify existed carry backups:write and keep verifying for this
// release. The next release drops backups:write from VerifyBackup; this test
// changes then.
func TestBackupRPCScopeDecisions_VerifyAcceptsLegacyWriteScope(t *testing.T) {
	_, bs := verifierServer(t)
	_, err := bs.VerifyBackup(verifierCtx("alice"), &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "alice"})
	if err != nil {
		t.Fatalf("legacy backups:write verifier token refused: %v", err)
	}
}

// verifyDeprecationMarker is the stable prefix of the deprecation line the
// daemon logs when VerifyBackup is authorized only by the legacy
// backups:write scope. The operator docs tell operators to grep for it.
const verifyDeprecationMarker = "[backup] DEPRECATED: VerifyBackup authorized by legacy scope backups:write"

// TestBackupRPCScopeDecisions_VerifyLegacyScopeLogsDeprecation pins the Q8
// decision on #3196: a VerifyBackup call let through only by backups:write
// logs a deprecation line naming the user, and a call admitted by
// backups:verify (or a wildcard / unscoped token) does not.
func TestBackupRPCScopeDecisions_VerifyLegacyScopeLogsDeprecation(t *testing.T) {
	prevStrict := auth.StrictScopesEnabled()
	auth.SetStrictScopes(false) // the no-scopes-claim row needs permissive mode
	t.Cleanup(func() { auth.SetStrictScopes(prevStrict) })
	for _, tc := range []struct {
		name    string
		scopes  []string // nil = a token with no scopes claim
		wantLog bool
	}{
		{"legacy backups:write", []string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite}, true},
		{"backups:verify", []string{auth.ScopeBackupsRead, auth.ScopeBackupsVerify}, false},
		{"both scopes", []string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite, auth.ScopeBackupsVerify}, false},
		{"wildcard", []string{auth.ScopeWildcard}, false},
		{"no scopes claim", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, bs := verifierServer(t)
			var buf bytes.Buffer
			prevOut, prevFlags := log.Writer(), log.Flags()
			log.SetOutput(&buf)
			log.SetFlags(0)
			t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

			ctx := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, tc.scopes)
			if _, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "alice"}); err != nil {
				t.Fatalf("VerifyBackup: %v", err)
			}
			out := buf.String()
			var line string
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, verifyDeprecationMarker) {
					line = l
				}
			}
			if !tc.wantLog {
				if line != "" {
					t.Fatalf("unexpected deprecation line: %q", line)
				}
				return
			}
			if line == "" {
				t.Fatalf("no deprecation line containing %q in log:\n%s", verifyDeprecationMarker, out)
			}
			for _, want := range []string{`user="alice"`, auth.ScopeBackupsVerify} {
				if !strings.Contains(line, want) {
					t.Errorf("deprecation line %q does not name %q", line, want)
				}
			}
		})
	}
}

// TestBackupRPCScopeDecisions_VerifyLegacyScopeDeprecationQuotesCallerInput
// pins that the caller-controlled id is %q-quoted in the deprecation line, so
// a newline in it cannot forge a second log line (#3186 follow-up).
func TestBackupRPCScopeDecisions_VerifyLegacyScopeDeprecationQuotesCallerInput(t *testing.T) {
	_, bs := verifierServer(t)
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	const evilID = "x\n[backup] DEPRECATED: forged user=\"root\""
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"},
		[]string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite})
	// The request is rejected downstream; only the log line matters here.
	_, _ = bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: evilID, TargetUsername: "alice"})

	out := strings.TrimSuffix(buf.String(), "\n")
	if n := len(strings.Split(out, "\n")); n != 1 {
		t.Fatalf("log has %d lines, want exactly 1 (forged line injected):\n%s", n, out)
	}
	if want := "id=" + strconv.Quote(evilID); !strings.Contains(out, want) {
		t.Errorf("log line %q does not contain quoted id %s", out, want)
	}
	if !strings.Contains(out, `user="alice"`) {
		t.Errorf("log line %q does not contain quoted user", out)
	}
}
