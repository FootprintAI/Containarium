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

// runBackupAllTenantsMint runs the script with extra env and a stand-in
// binary whose `token generate` prints a fixed token (or fails when
// mintFails). It returns the combined output, every recorded invocation, and
// the script's exit error.
func runBackupAllTenantsMint(t *testing.T, extraEnv []string, mintFails bool) (string, []string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "backup-tenants.conf")
	if err := os.WriteFile(confPath, []byte("acme appdb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls.log")
	fakeBin := filepath.Join(dir, "containarium")
	fail := "0"
	if mintFails {
		fail = "1"
	}
	fake := "#!/usr/bin/env bash\necho \"$*\" >> " + logPath + "\n" +
		"if [[ \"$1 $2\" == \"token generate\" ]]; then\n" +
		"  if [[ " + fail + " == 1 ]]; then echo 'cannot read secret' >&2; exit 1; fi\n" +
		"  printf 'minted-token'\n" +
		"fi\n"
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
		"CONTAINARIUM_JWT_SECRET_FILE=",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, runErr := cmd.CombinedOutput()
	var calls []string
	if raw, err := os.ReadFile(logPath); err == nil { // #nosec G304 -- test temp dir
		calls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	return string(out), calls, runErr
}

// #2592: with CONTAINARIUM_JWT_SECRET_FILE set the script mints a short-lived
// token per run and ignores any static CONTAINARIUM_AUTH_TOKEN.
func TestBackupAllTenantsScript_MintsPerRunToken(t *testing.T) {
	out, calls, runErr := runBackupAllTenantsMint(t, []string{
		"CONTAINARIUM_JWT_SECRET_FILE=/etc/containarium/jwt.secret",
		"CONTAINARIUM_AUTH_TOKEN=stale-static-token",
	}, false)
	if runErr != nil {
		t.Fatalf("script failed: %v\n%s", runErr, out)
	}
	if len(calls) < 2 || !strings.HasPrefix(calls[0], "token generate ") {
		t.Fatalf("first call should be the mint, got %q", calls)
	}
	for _, want := range []string{"--expiry 2h", "--secret-file /etc/containarium/jwt.secret", "--raw", "--scopes backups:write,backups:read", "--username backup-scheduler"} {
		if !strings.Contains(calls[0], want) {
			t.Errorf("mint call %q missing %q", calls[0], want)
		}
	}
	create := calls[1]
	if !strings.Contains(create, "--token minted-token") {
		t.Errorf("backup create should use the minted token: %q", create)
	}
	if strings.Contains(strings.Join(calls, "\n"), "stale-static-token") {
		t.Errorf("static token must be ignored when the secret file is set: %q", calls)
	}
}

// #2592: a failed mint is a hard exit — never a fallback to the static token.
func TestBackupAllTenantsScript_MintFailureIsFatal(t *testing.T) {
	out, calls, runErr := runBackupAllTenantsMint(t, []string{
		"CONTAINARIUM_JWT_SECRET_FILE=/nonexistent/jwt.secret",
		"CONTAINARIUM_AUTH_TOKEN=stale-static-token",
	}, true)
	if runErr == nil {
		t.Fatalf("script should exit non-zero when the mint fails\n%s", out)
	}
	if !strings.Contains(out, "mint") {
		t.Errorf("output should report the mint failure: %s", out)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "backup create ") {
			t.Errorf("no backup may run after a failed mint: %q", c)
		}
	}
}

// runBackupAllTenantsPlaintext runs the script with a stand-in binary whose
// `backup create` prints the Encrypted line chosen per tenant: tenants listed
// in plaintext print "Encrypted: no", the rest "Encrypted: yes". Returns
// combined output and the exit code.
func runBackupAllTenantsPlaintext(t *testing.T, conf string, plaintext []string, extraEnv ...string) (string, int) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "backup-tenants.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(dir, "containarium")
	fake := "#!/usr/bin/env bash\n" +
		"if [[ \"$1 $2\" == \"backup create\" ]]; then\n" +
		"  case \" " + strings.Join(plaintext, " ") + " \" in *\" $3 \"*) echo '      Encrypted: no';; *) echo '      Encrypted: yes (to age1x)';; esac\n" +
		"fi\n"
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
		"CONTAINARIUM_JWT_SECRET_FILE=",
		"CONTAINARIUM_BACKUP_FAIL_ON_UNENCRYPTED=",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

// #3169: a plaintext tenant is named in a greppable per-tenant line and in a
// summary count; the default exit status is unchanged.
func TestBackupAllTenantsScript_PlaintextTenantWarned(t *testing.T) {
	out, code := runBackupAllTenantsPlaintext(t, "acme appdb\nbeta appdb\n", []string{"beta"})
	if code != 0 {
		t.Fatalf("default exit must stay 0, got %d\n%s", code, out)
	}
	for _, want := range []string{
		"[backup] WARNING UNENCRYPTED tenant=beta",
		"[backup] 1/2 tenant(s) stored UNENCRYPTED: beta",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "UNENCRYPTED tenant=acme") {
		t.Errorf("encrypted tenant must not be flagged:\n%s", out)
	}
	if !strings.Contains(out, "all 2 tenant(s) done") {
		t.Errorf("success line must remain:\n%s", out)
	}
}

func TestBackupAllTenantsScript_AllEncryptedNoWarning(t *testing.T) {
	out, code := runBackupAllTenantsPlaintext(t, "acme appdb\n", nil, "CONTAINARIUM_BACKUP_FAIL_ON_UNENCRYPTED=1")
	if code != 0 || strings.Contains(out, "UNENCRYPTED") {
		t.Fatalf("code=%d, want 0 and no warning:\n%s", code, out)
	}
}

// #3169: opt-in distinct exit status so the timer-health metric can go red.
func TestBackupAllTenantsScript_FailOnUnencryptedExit(t *testing.T) {
	out, code := runBackupAllTenantsPlaintext(t, "acme appdb\nbeta appdb\n", []string{"beta"}, "CONTAINARIUM_BACKUP_FAIL_ON_UNENCRYPTED=1")
	if code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", code, out)
	}
}
