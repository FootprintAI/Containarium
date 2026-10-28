package sentinel

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The live harness controls a VM. Exercise its success and failure paths
// against synthetic command-line services before giving it real credentials.
func TestSentinelOutageHarness(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"recover", "PASS"},
		{"restart", "sentinel restarted"},
		{"restart-count", "sentinel restarted"},
		{"changed-ip", "backend IP changed"},
		{"ssh-stuck", "forwarding did not recover"},
		{"https-stuck", "forwarding did not recover"},
		{"short-outage", "outage must exceed"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "state")
			require.NoError(t, os.WriteFile(state, []byte("initial"), 0600))
			for _, name := range []string{"gcloud", "ssh", "curl"} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(outageCommandFixture), 0700))
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			for k, v := range map[string]string{
				"FIXTURE_STATE": state, "FIXTURE_MODE": tc.mode,
				"GCP_PROJECT": "fixture", "GCP_ZONE": "fixture", "BACKEND_VM": "fixture",
				"SENTINEL_SSH_TARGET": "sentinel", "APP_SSH_TARGET": "app",
				"SENTINEL_HTTPS_IP": "192.0.2.1", "APP_URL": "https://app.example/",
				"EXPECTED_HTTPS_BODY": "fixture-ok", "KEYSYNC_INTERVAL_SECONDS": "1",
				"OUTAGE_SECONDS": "2", "RECOVERY_SECONDS": "1",
			} {
				t.Setenv(k, v)
			}
			if tc.mode == "short-outage" {
				t.Setenv("OUTAGE_SECONDS", "1")
			}
			cmd := exec.Command("bash", "../../scripts/ci/sentinel-outage-smoke.sh")
			out, err := cmd.CombinedOutput()
			if tc.mode == "recover" {
				require.NoError(t, err, "%s", out)
			} else {
				require.Error(t, err, "%s", out)
			}
			require.Contains(t, string(out), tc.want)
			final, err := os.ReadFile(state)
			require.NoError(t, err)
			wantState := "recovered"
			if tc.mode == "short-outage" {
				wantState = "initial"
			}
			require.Equal(t, wantState, strings.TrimSpace(string(final)), "the VM must be restored after an assertion failure; invalid input must not stop it")
		})
	}
}

const outageCommandFixture = `#!/usr/bin/env bash
set -euo pipefail
state="$(cat "$FIXTURE_STATE")"
case "${0##*/}" in
  gcloud)
    case "$*" in
      *"instances stop"*) echo down > "$FIXTURE_STATE" ;;
      *"instances start"*) echo recovered > "$FIXTURE_STATE" ;;
      *"instances describe"*)
        if [[ "$FIXTURE_MODE" == changed-ip && "$state" == recovered ]]; then echo 192.0.2.3; else echo 192.0.2.2; fi ;;
      *) exit 2 ;;
    esac ;;
  ssh)
    if [[ "$*" == *"systemctl show"* ]]; then
      if [[ "$FIXTURE_MODE" == restart && "$state" != initial ]]; then echo MainPID=2; else echo MainPID=1; fi
      if [[ "$FIXTURE_MODE" == restart-count && "$state" != initial ]]; then echo NRestarts=1; else echo NRestarts=0; fi
    else
      [[ "$state" != down && !( "$state" == recovered && "$FIXTURE_MODE" == ssh-stuck ) ]] || exit 1
      echo sentinel-outage-ssh-ok
    fi ;;
  curl)
    [[ "$state" != down ]] || exit 1
    if [[ "$FIXTURE_MODE" == https-stuck && "$state" == recovered ]]; then echo wrong-backend; else echo fixture-ok; fi ;;
esac
`
