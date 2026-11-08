package server

import (
	"strings"
	"testing"
)

// A run with a token gets its own 0600 file, the environment variable that
// points the engine and helper at it, and removal on exit. Nothing else.
func TestBoxRunSpawn_RunTokenFileLifecycle(t *testing.T) {
	script := boxRunSpawnScript(boxRunSpawn{
		dir: "/var/run/box", name: "r1", command: "echo hi", home: "/home/ctn-run",
		runToken: "eyJhbGciOi.x.y",
	})
	// The write runs in the spawning shell under umask 077, so the file is
	// never readable by anyone else.
	if !strings.Contains(script, "(umask 077; printf '%s' 'eyJhbGciOi.x.y' > '/var/run/box/r1.token')") {
		t.Errorf("spawn script does not write the token under umask 077\n%s", script)
	}
	// The run's shell is started through sh -c, so the path appears quoted
	// inside it: the export points the engine and helper at the file.
	if !strings.Contains(script, "export CONTAINARIUM_JWT_TOKEN_FILE=") || !strings.Contains(script, "r1.token") {
		t.Errorf("run does not get CONTAINARIUM_JWT_TOKEN_FILE pointing at its token file")
	}
	// Removed on exit, from inside the run's own shell (quoted, as above).
	if !strings.Contains(script, `rm -f '\''/var/run/box/r1.token'\''`) {
		t.Errorf("the token file is not removed in the run's exit path")
	}
}

// A run without a token writes no token file and exports nothing.
func TestBoxRunSpawn_NoTokenNoFile(t *testing.T) {
	script := boxRunSpawnScript(boxRunSpawn{dir: "/var/run/box", name: "r2", command: "echo hi", home: "/home/ctn-run"})
	// The script still removes a stale <name>.token at start, so a leftover
	// file from an earlier run never survives into this one; it writes and
	// exports nothing.
	for _, banned := range []string{"CONTAINARIUM_JWT_TOKEN_FILE", "umask 077; printf"} {
		if strings.Contains(script, banned) {
			t.Errorf("a run with no token must not contain %q", banned)
		}
	}
}

// The run user's home no longer receives the box principal, and an earlier
// daemon's copy is removed.
func TestBoxRunStage_NoPrincipalCopyAndStaleRemoved(t *testing.T) {
	if len(boxRunStagedPlatformCredentials) != 0 {
		t.Fatalf("the box principal is still staged: %v", boxRunStagedPlatformCredentials)
	}
	stage, err := boxRunStageScript("/home/owner", "/home/ctn-run")
	if err != nil {
		t.Fatalf("boxRunStageScript: %v", err)
	}
	if !strings.Contains(stage, `rm -f "$r/.config/containarium/box-token"`) {
		t.Errorf("stage script does not remove a stale principal copy:\n%s", stage)
	}
	if strings.Contains(stage, `cat "$o/.config/containarium/box-token"`) {
		t.Error("stage script still copies the box principal")
	}
}

// The capability is advertised so the cloud sends run tokens only to a daemon
// that honours them.
func TestBoxRunToken_CapabilityAdvertised(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxRunToken {
			return
		}
	}
	t.Errorf("capabilities %v missing %q", daemonCapabilities(), DaemonCapBoxRunToken)
}
