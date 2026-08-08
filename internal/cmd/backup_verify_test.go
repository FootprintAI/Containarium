package cmd

import (
	"errors"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBackupAPI is a backupAPI that returns a canned verification result.
// Only VerifyBackup is exercised; the rest satisfy the interface.
type fakeBackupAPI struct {
	resp    *pb.VerifyBackupResponse
	err     error
	gotReq  *pb.VerifyBackupRequest
	closed  bool
	callCnt int
}

func (f *fakeBackupAPI) VerifyBackup(req *pb.VerifyBackupRequest) (*pb.VerifyBackupResponse, error) {
	f.gotReq = req
	f.callCnt++
	return f.resp, f.err
}

func (f *fakeBackupAPI) CreateBackup(*pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	return nil, errors.New("not used")
}
func (f *fakeBackupAPI) ListBackups(string) ([]*pb.BackupRecord, error) {
	return nil, errors.New("not used")
}
func (f *fakeBackupAPI) GetBackup(string) (*pb.BackupRecord, error) {
	return nil, errors.New("not used")
}
func (f *fakeBackupAPI) RestoreBackup(*pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	return nil, errors.New("not used")
}
func (f *fakeBackupAPI) DeleteBackup(string) (*pb.DeleteBackupResponse, error) {
	return nil, errors.New("not used")
}
func (f *fakeBackupAPI) Close() error { f.closed = true; return nil }

func withFakeBackupClient(t *testing.T, f *fakeBackupAPI) {
	t.Helper()
	orig := newBackupClientFn
	newBackupClientFn = func() (backupAPI, error) { return f, nil }
	t.Cleanup(func() { newBackupClientFn = orig })
}

// A failed restore test must exit non-zero. A scheduled verification that
// exits 0 on a dump that cannot be restored is worse than no verification
// at all — it reports success for the exact case it exists to catch.
func TestBackupVerifyExitCodeReflectsResult(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  pb.VerificationResult
		wantErr bool
	}{
		{"passed exits zero", pb.VerificationResult_VERIFICATION_RESULT_PASSED, false},
		{"failed exits non-zero", pb.VerificationResult_VERIFICATION_RESULT_FAILED, true},
		{"unspecified exits non-zero", pb.VerificationResult_VERIFICATION_RESULT_UNSPECIFIED, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBackupAPI{resp: &pb.VerifyBackupResponse{
				Message: "result: " + tc.result.String(),
				Verification: &pb.BackupVerification{
					Result:          tc.result,
					TargetContainer: "scratch-container",
					ScratchDatabase: "containarium_verify_x",
					VerifiedAt:      "2026-08-08T05:12:44Z",
					Checks: []*pb.VerificationCheck{
						{Name: "restore", Passed: tc.result == pb.VerificationResult_VERIFICATION_RESULT_PASSED, Detail: "d"},
					},
				},
			}}
			withFakeBackupClient(t, f)
			backupVerifyTarget = "scratch"

			err := runBackupVerify(backupVerifyCmd, []string{"alice-app-20260605T130405Z"})
			if tc.wantErr && err == nil {
				t.Error("want a non-nil error so the command exits non-zero")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want success, got %v", err)
			}
			if !f.closed {
				t.Error("client was not closed")
			}
		})
	}
}

// The CLI must pass the target through; a verify that silently defaulted
// the target could restore somewhere the operator did not intend.
func TestBackupVerifySendsTarget(t *testing.T) {
	f := &fakeBackupAPI{resp: &pb.VerifyBackupResponse{
		Message:      "ok",
		Verification: &pb.BackupVerification{Result: pb.VerificationResult_VERIFICATION_RESULT_PASSED},
	}}
	withFakeBackupClient(t, f)
	backupVerifyTarget = "scratch-tenant"

	if err := runBackupVerify(backupVerifyCmd, []string{"alice-app-20260605T130405Z"}); err != nil {
		t.Fatalf("runBackupVerify: %v", err)
	}
	if f.gotReq.TargetUsername != "scratch-tenant" {
		t.Errorf("TargetUsername = %q, want scratch-tenant", f.gotReq.TargetUsername)
	}
	if f.gotReq.Id != "alice-app-20260605T130405Z" {
		t.Errorf("Id = %q", f.gotReq.Id)
	}
}

// A daemon response with no verification payload is a protocol error, not
// a silent pass.
func TestBackupVerifyRejectsEmptyResult(t *testing.T) {
	f := &fakeBackupAPI{resp: &pb.VerifyBackupResponse{Message: "ok"}}
	withFakeBackupClient(t, f)
	backupVerifyTarget = "scratch"

	if err := runBackupVerify(backupVerifyCmd, []string{"alice-app-20260605T130405Z"}); err == nil {
		t.Error("a response with no verification must be an error")
	}
}
