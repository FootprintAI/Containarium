package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const backupAllTenantsScript = "../../scripts/backup-all-tenants.sh"

// runBackupAllTenants runs scripts/backup-all-tenants.sh hermetically
// against conf, with a stand-in containarium binary that records each
// invocation's argv, and returns the recorded `backup create` lines.
func runBackupAllTenants(t *testing.T, conf string) []string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "backup-tenants.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls.log")
	fakeBin := filepath.Join(dir, "containarium")
	fake := "#!/usr/bin/env bash\necho \"$*\" >> " + logPath + "\n"
	if err := os.WriteFile(fakeBin, []byte(fake), 0o700); err != nil { //nolint:gosec // test-only executable stand-in
		t.Fatal(err)
	}

	cmd := exec.Command("bash", backupAllTenantsScript) //nolint:gosec // test-only, fixed path
	cmd.Env = append(os.Environ(),
		"CONTAINARIUM_BACKUP_CONF="+confPath,
		"CONTAINARIUM_SERVER=localhost:0",
		"CONTAINARIUM_BACKUP_BUCKET=gs://example-bucket/pg",
		"CONTAINARIUM_BIN="+fakeBin,
		"CONTAINARIUM_AUTH_TOKEN=",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(logPath) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var creates []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(l, "backup create ") {
			creates = append(creates, l)
		}
	}
	return creates
}

// #2405: a hook tenant's conf line may declare the hook's output format;
// the script passes it as --hook-format. Lines without it keep working
// exactly as before.
func TestBackupAllTenantsScript_HookFormatColumn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		line     string
		wantArgs []string
		denyArgs []string
	}{
		{
			name:     "hook with format",
			line:     "tenant-a  --hook /opt/backup/dump.sh  --hook-format pg_custom",
			wantArgs: []string{"--hook /opt/backup/dump.sh", "--hook-format pg_custom"},
		},
		{
			name:     "hook with label then format",
			line:     "tenant-a  --hook /opt/backup/dump.sh  --label app  --hook-format pg_custom",
			wantArgs: []string{"--hook /opt/backup/dump.sh", "--label app", "--hook-format pg_custom"},
		},
		{
			name:     "hook with format then label",
			line:     "tenant-a  --hook /opt/backup/dump.sh  --hook-format pg_custom  --label app",
			wantArgs: []string{"--hook /opt/backup/dump.sh", "--label app", "--hook-format pg_custom"},
		},
		{
			name:     "legacy hook line with label",
			line:     "tenant-a  --hook /opt/backup/dump.sh  --label app",
			wantArgs: []string{"--hook /opt/backup/dump.sh", "--label app"},
			denyArgs: []string{"--hook-format"},
		},
		{
			name:     "legacy hook line, path only",
			line:     "tenant-a  --hook /opt/backup/dump.sh",
			wantArgs: []string{"--hook /opt/backup/dump.sh"},
			denyArgs: []string{"--hook-format", "--label"},
		},
		{
			name:     "plain pg_dump line",
			line:     "tenant-a  app",
			wantArgs: []string{"--database app"},
			denyArgs: []string{"--hook"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creates := runBackupAllTenants(t, "# comment\n"+tc.line+"\n")
			if len(creates) != 1 {
				t.Fatalf("backup create calls = %v, want exactly one", creates)
			}
			got := creates[0]
			for _, w := range tc.wantArgs {
				if !strings.Contains(got, w) {
					t.Errorf("create %q missing %q", got, w)
				}
			}
			for _, d := range tc.denyArgs {
				if strings.Contains(got, d) {
					t.Errorf("create %q must not contain %q", got, d)
				}
			}
		})
	}
}
