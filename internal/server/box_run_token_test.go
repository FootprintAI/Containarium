package server

import (
	"strings"
	"testing"
)

// The token never appears in any script the daemon runs: it travels only as
// file content (boxRunTokenInstallFn), never in a command line.
func TestBoxRunToken_NeverInAnyScript(t *testing.T) {
	const token = "eyJhbGciOi.secret.payload"
	scripts := map[string]string{
		"spawn": boxRunSpawnScript(boxRunSpawn{dir: "/var/run/box", name: "r1", command: "echo hi", home: "/home/ctn-run", runToken: token}),
		"prep":  boxRunTokenPrepScript(),
		"move":  boxRunTokenMoveScript(boxRunTokenStaging+"/r1.x", "ctn-run", "r1"),
		"stop":  boxRunStopScript("/var/run/box", "r1", "ctn-run", 1234, false),
	}
	for name, script := range scripts {
		if strings.Contains(script, token) {
			t.Errorf("the %s script contains the token", name)
		}
	}
}

// A run with a token reads it from the run-token path, and its exit path
// removes it. The daemon writes nothing else.
func TestBoxRunSpawn_RunTokenPathAndExitRemoval(t *testing.T) {
	script := boxRunSpawnScript(boxRunSpawn{
		dir: "/var/run/box", name: "r1", command: "echo hi", home: "/home/ctn-run",
		runToken: "eyJhbGciOi.x.y",
	})
	if !strings.Contains(script, "export CONTAINARIUM_JWT_TOKEN_FILE=") || !strings.Contains(script, "r1.token") {
		t.Errorf("run does not get CONTAINARIUM_JWT_TOKEN_FILE pointing at its token")
	}
	if !strings.Contains(script, `rm -f '\''`+boxRunTokenPath("r1")+`'\''`) {
		t.Errorf("the token is not removed in the run's exit path")
	}
	if strings.Contains(script, "umask 077; printf") {
		t.Error("the spawn script still writes the token itself")
	}
}

// A run without a token writes no token file and exports nothing.
func TestBoxRunSpawn_NoTokenNoFile(t *testing.T) {
	script := boxRunSpawnScript(boxRunSpawn{dir: "/var/run/box", name: "r2", command: "echo hi", home: "/home/ctn-run"})
	for _, banned := range []string{"CONTAINARIUM_JWT_TOKEN_FILE", "umask 077; printf"} {
		if strings.Contains(script, banned) {
			t.Errorf("a run with no token must not contain %q", banned)
		}
	}
}

// The token is placed as root, owned by the run user, and renamed into place,
// so a symlink planted at the destination is replaced, not followed.
func TestBoxRunToken_MoveIsOwnedAndAtomic(t *testing.T) {
	move := boxRunTokenMoveScript(boxRunTokenStaging+"/r1.x", "ctn-run", "r1")
	for _, want := range []string{"chown 'ctn-run':'ctn-run'", "chmod 0600", "mv -f"} {
		if !strings.Contains(move, want) {
			t.Errorf("move script missing %q\n%s", want, move)
		}
	}
	if !strings.Contains(move, "'"+boxRunTokenPath("r1")+"'") {
		t.Error("move script does not rename into the run's token path")
	}
}

// Stopping a run removes its token, since a killed run never reaches its exit path.
func TestBoxRunStop_RemovesTheToken(t *testing.T) {
	stop := boxRunStopScript("/var/run/box", "r1", "ctn-run", 1234, false)
	if !strings.Contains(stop, "rm -f '"+boxRunTokenPath("r1")+"'") {
		t.Errorf("stop script does not remove the run's token:\n%s", stop)
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

// The install hook is called with the token only when the run has one.
func TestInstallRunToken_CalledOnlyWithAToken(t *testing.T) {
	var calls []string
	s := &ContainerServer{boxRunTokenInstall: func(box, runAs, name, token string) error {
		calls = append(calls, box+"/"+runAs+"/"+name+"/"+token)
		return nil
	}}
	if err := s.installRunToken("box1", "ctn-run", "r1", ""); err != nil || len(calls) != 0 {
		t.Fatalf("a run with no token installed something: calls=%v err=%v", calls, err)
	}
	if err := s.installRunToken("box1", "ctn-run", "r1", "tok"); err != nil {
		t.Fatalf("installRunToken: %v", err)
	}
	if len(calls) != 1 || calls[0] != "box1/ctn-run/r1/tok" {
		t.Fatalf("install calls = %v, want one call with the run's token", calls)
	}
}
