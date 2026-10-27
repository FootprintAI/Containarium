package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// An age identity is a private key. It must never cross a cleartext
// transport to a non-loopback host (review feedback on #2302, CWE-319).
func TestRequireSecureTransportForIdentity(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		httpMode bool
		insecure bool
		wantErr  bool
	}{
		{name: "no server configured is left to the client", server: ""},
		{name: "gRPC with mTLS", server: "host.example.com:50051"},
		{name: "gRPC --insecure to a remote host", server: "host.example.com:50051", insecure: true, wantErr: true},
		{name: "gRPC --insecure to loopback", server: "127.0.0.1:50051", insecure: true},
		{name: "http mode, https URL", server: "https://host.example.com", httpMode: true},
		{name: "http mode, explicit http URL", server: "http://host.example.com", httpMode: true, wantErr: true},
		{name: "http mode, scheme-less (client prepends http://)", server: "host.example.com:8080", httpMode: true, wantErr: true},
		{name: "http mode, http to localhost", server: "http://localhost:8080", httpMode: true},
		{name: "http mode, scheme-less loopback", server: "127.0.0.1:8080", httpMode: true},
		{name: "http mode, http to IPv6 loopback", server: "http://[::1]:8080", httpMode: true},
		{name: "http mode, http to a private LAN IP is still cleartext", server: "http://10.0.0.5:8080", httpMode: true, wantErr: true},
		{name: "http mode, lookalike host is not loopback", server: "http://localhost.evil.example:8080", httpMode: true, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := requireSecureTransportForIdentity(tc.server, tc.httpMode, tc.insecure)
			if (err != nil) != tc.wantErr {
				t.Fatalf("requireSecureTransportForIdentity(%q, http=%t, insecure=%t) error = %v, wantErr %t",
					tc.server, tc.httpMode, tc.insecure, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "age identity") {
				t.Errorf("error should name the age identity so the operator knows why: %v", err)
			}
		})
	}
}

func setTransportGlobals(t *testing.T, server string, http, insec bool) {
	t.Helper()
	oa, oh, oi := serverAddr, httpMode, insecure
	serverAddr, httpMode, insecure = server, http, insec
	t.Cleanup(func() { serverAddr, httpMode, insecure = oa, oh, oi })
}

func writeIdentityFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "backup.key")
	const secret = "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
	if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBackupVerify_RefusesIdentityOverCleartext(t *testing.T) {
	f := &fakeBackupAPI{}
	withFakeBackupClient(t, f)
	setTransportGlobals(t, "http://host.example.com", true, false)
	backupVerifyTarget = "scratch-tenant"
	backupVerifyAgeIdentityFile = writeIdentityFile(t)
	t.Cleanup(func() { backupVerifyAgeIdentityFile = "" })

	err := runBackupVerify(backupVerifyCmd, []string{"alice-app-x"})
	if err == nil || !strings.Contains(err.Error(), "age identity") {
		t.Fatalf("expected a refusal naming the age identity, got %v", err)
	}
	if f.callCnt != 0 {
		t.Error("the key must not be sent: no verify call may be made")
	}
}

func TestBackupRestore_RefusesIdentityOverCleartext(t *testing.T) {
	f := withRecordingBackupClient(t)
	setTransportGlobals(t, "host.example.com:8080", true, false)
	backupRestoreAgeIdentityFile = writeIdentityFile(t)
	t.Cleanup(func() { backupRestoreAgeIdentityFile = "" })

	err := runBackupRestore(backupRestoreCmd, []string{"alice-app-x"})
	if err == nil || !strings.Contains(err.Error(), "age identity") {
		t.Fatalf("expected a refusal naming the age identity, got %v", err)
	}
	if f.gotRestore != nil {
		t.Error("the key must not be sent: no restore call may be made")
	}
}

// Without an identity nothing secret is in the request, so cleartext
// behaves exactly as before.
func TestBackupVerify_NoIdentity_CleartextUnchanged(t *testing.T) {
	f := &fakeBackupAPI{resp: &pb.VerifyBackupResponse{
		Message:      "ok",
		Verification: &pb.BackupVerification{Result: pb.VerificationResult_VERIFICATION_RESULT_PASSED},
	}}
	withFakeBackupClient(t, f)
	setTransportGlobals(t, "http://host.example.com", true, false)
	backupVerifyTarget = "scratch-tenant"
	backupVerifyAgeIdentityFile = ""

	if err := runBackupVerify(backupVerifyCmd, []string{"alice-app-x"}); err != nil {
		t.Fatalf("verify without an identity must not be affected by the guard: %v", err)
	}
}
