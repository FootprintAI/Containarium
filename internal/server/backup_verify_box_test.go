package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #2802: VerifyBackup of a whole-box backup at the server boundary ---

// The tenant's own verifier token (verifierCtx, #2401) restores the box backup into a scratch
// box through the container manager and the Incus mock, passes, and leaves
// no instance behind; the source box is untouched.
func TestVerifyBackup_BoxPassesWithTenantBoundToken(t *testing.T) {
	f := newBoxRestoreFixture(t)
	source := string(f.backend.Archives["alice-container"])
	resp, err := f.s.VerifyBackup(verifierCtx("alice"), &pb.VerifyBackupRequest{Id: f.id, TargetUsername: "alice", AgeIdentity: f.identity})
	if err != nil {
		t.Fatalf("VerifyBackup: %v", err)
	}
	v := resp.Verification
	if v.Result != pb.VerificationResult_VERIFICATION_RESULT_PASSED || !strings.HasPrefix(v.TargetContainer, "containarium-verify-") {
		t.Fatalf("verification = %+v, want PASSED in a scratch box", v)
	}
	if resp.Record.LastVerification.GetResult() != pb.VerificationResult_VERIFICATION_RESULT_PASSED {
		t.Errorf("record not stamped: %+v", resp.Record.LastVerification)
	}
	if n := f.newBoxes(); len(n) != 0 {
		t.Errorf("instances left after verify: %v", n)
	}
	if string(f.backend.Archives["alice-container"]) != source || f.backend.Containers["alice-container"] == nil {
		t.Error("the source box was touched")
	}
}

// A flipped byte in the stored backup is a FAILED verification that names
// the failure, with no instance left behind.
func TestVerifyBackup_BoxTamperedFails(t *testing.T) {
	f := newBoxRestoreFixture(t)
	rec, err := f.s.mgr.Get(f.id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(rec.Location)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(rec.Location, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := f.s.VerifyBackup(verifierCtx("alice"), &pb.VerifyBackupRequest{Id: f.id, TargetUsername: "alice", AgeIdentity: f.identity})
	if err != nil {
		t.Fatalf("VerifyBackup: %v", err)
	}
	if resp.Verification.Result != pb.VerificationResult_VERIFICATION_RESULT_FAILED || !strings.Contains(resp.Message, "checksum") {
		t.Errorf("response = %q %v, want FAILED naming the checksum", resp.Message, resp.Verification.Result)
	}
	if n := f.newBoxes(); len(n) != 0 {
		t.Errorf("instances left after a failed verify: %v", n)
	}
}

// #2401: the verifier token stays tenant-bound. Another tenant's token is
// refused before anything runs, and a box backup cannot be pointed at
// another tenant as the target, even by an admin.
func TestVerifyBackup_BoxStaysTenantBound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		target string
		want   codes.Code
	}{
		{"another tenant's verifier token", verifierCtx("bob"), "bob", codes.PermissionDenied},
		{"own token, another tenant as target", verifierCtx("alice"), "bob", codes.PermissionDenied},
		{"admin, another tenant as target", auth.ContextWithTestSubjectScopes(context.Background(), "ops", []string{auth.RoleAdmin}, []string{auth.ScopeBackupsVerify}), "bob", codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoxRestoreFixture(t)
			_, err := f.s.VerifyBackup(tc.ctx, &pb.VerifyBackupRequest{Id: f.id, TargetUsername: tc.target, AgeIdentity: f.identity})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
			if n := f.newBoxes(); len(n) != 0 {
				t.Errorf("a refused verify created instances: %v", n)
			}
		})
	}
}
