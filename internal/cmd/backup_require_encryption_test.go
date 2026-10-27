package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3169: --require-encryption reaches the wire request; without it the
// request is unchanged (false), so the daemon keeps today's behaviour.
func TestBackupCreate_RequireEncryptionFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  bool
	}{
		{"flag set", true},
		{"default", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := withRecordingBackupClient(t)
			resetBackupCreateFlags(t)
			backupCreateRequireEncryption = tc.set
			if err := runBackupCreate(backupCreateCmd, []string{"alice"}); err != nil {
				t.Fatalf("runBackupCreate: %v", err)
			}
			if f.gotCreate.RequireEncryption != tc.set {
				t.Errorf("RequireEncryption = %v, want %v", f.gotCreate.RequireEncryption, tc.set)
			}
		})
	}
}

// #3169: `backup list` names plaintext records instead of leaving the object
// suffix to be noticed.
func TestPrintBackupList_EncryptedColumn(t *testing.T) {
	var buf bytes.Buffer
	if err := printBackupList(&buf, []*pb.BackupRecord{
		{Id: "acme-app-1", Username: "acme", Database: "app", Encrypted: true, AgeRecipient: "age1x"},
		{Id: "beta-app-1", Username: "beta", Database: "app"},
	}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got:\n%s", buf.String())
	}
	if !strings.Contains(lines[0], "ENCRYPTED") {
		t.Errorf("header has no ENCRYPTED column: %q", lines[0])
	}
	if f := strings.Fields(lines[1]); f[0] != "acme-app-1" || !containsField(f, "yes") {
		t.Errorf("encrypted row = %q, want id first and 'yes'", lines[1])
	}
	if f := strings.Fields(lines[2]); f[0] != "beta-app-1" || !containsField(f, "NO") {
		t.Errorf("plaintext row = %q, want id first and 'NO'", lines[2])
	}
}

type getBackupAPI struct {
	fakeBackupAPI
	rec *pb.BackupRecord
}

func (f *getBackupAPI) GetBackup(string) (*pb.BackupRecord, error) { return f.rec, nil }

// #3169: `backup get` says "no" for a plaintext record instead of printing
// nothing, and is unchanged for an encrypted one.
func TestBackupGet_EncryptedLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  *pb.BackupRecord
		want string
	}{
		{"plaintext", &pb.BackupRecord{Id: "beta-app-1"}, "Encrypted:   NO (stored in plaintext)"},
		{"encrypted", &pb.BackupRecord{Id: "acme-app-1", Encrypted: true, AgeRecipient: "age1x"}, "Encrypted:   yes (age recipient age1x; restore needs --age-identity-file)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &getBackupAPI{rec: tc.rec}
			orig := newBackupClientFn
			newBackupClientFn = func() (backupAPI, error) { return f, nil }
			t.Cleanup(func() { newBackupClientFn = orig })
			out := captureStdout(t, func() {
				if err := runBackupGet(backupGetCmd, []string{tc.rec.Id}); err != nil {
					t.Errorf("runBackupGet: %v", err)
				}
			})
			if !strings.Contains(out, tc.want) {
				t.Errorf("output missing %q:\n%s", tc.want, out)
			}
		})
	}
}

func containsField(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

// fakeSecretsLister returns the secret names registered per tenant.
type fakeSecretsLister struct {
	names map[string][]string
	errs  map[string]error
}

func (f *fakeSecretsLister) ListSecrets(username string) ([]*pb.SecretMetadata, error) {
	if err := f.errs[username]; err != nil {
		return nil, err
	}
	var out []*pb.SecretMetadata
	for _, n := range f.names[username] {
		out = append(out, &pb.SecretMetadata{Username: username, Name: n})
	}
	return out, nil
}

func TestReadBackupConfTenants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup-tenants.conf")
	conf := "# comment\n\nacme appdb\nbeta --hook /opt/dump.sh --label x\n  acme otherdb PW_ENV\n#gamma appdb\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readBackupConfTenants(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "acme,beta" {
		t.Errorf("tenants = %v, want [acme beta] (deduplicated, comments skipped)", got)
	}
}

// #3169: the preflight names every configured tenant with no registered
// recipient, and fails so it can gate a deploy or a host move.
func TestCheckBackupRecipients(t *testing.T) {
	lister := &fakeSecretsLister{
		names: map[string][]string{
			"acme": {"CONTAINARIUM_BACKUP_AGE_RECIPIENT", "OTHER"},
			"beta": {"OTHER"},
		},
		errs: map[string]error{"gamma": errors.New("permission denied")},
	}
	var buf bytes.Buffer
	missing := checkBackupRecipients(&buf, lister, []string{"acme", "beta", "gamma"})
	out := buf.String()
	if missing != 2 {
		t.Errorf("missing = %d, want 2 (beta has none, gamma could not be checked)\n%s", missing, out)
	}
	for _, want := range []string{"✓ acme", "✗ beta", "no CONTAINARIUM_BACKUP_AGE_RECIPIENT registered", "? gamma", "permission denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestCheckBackupRecipients_AllRegistered(t *testing.T) {
	lister := &fakeSecretsLister{names: map[string][]string{"acme": {"CONTAINARIUM_BACKUP_AGE_RECIPIENT"}}}
	var buf bytes.Buffer
	if missing := checkBackupRecipients(&buf, lister, []string{"acme"}); missing != 0 {
		t.Errorf("missing = %d, want 0:\n%s", missing, buf.String())
	}
}
