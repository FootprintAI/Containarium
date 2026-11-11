package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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

// stopScriptOutcome runs the stop script with ps, id, kill, sleep and rm
// replaced by shell functions, and returns what it printed. The group has one
// member, owned by the box user, for as long as the matching flag says so:
// aliveBeforeSignal until the script signals it, aliveAfterSignal from then
// on. rm prints its arguments instead of removing anything, so the output
// shows which branch removed what, in order.
func stopScriptOutcome(t *testing.T, aliveBeforeSignal, aliveAfterSignal bool, script string) string {
	t.Helper()
	signalled := shellSingleQuote(t.TempDir() + "/signalled")
	member := func(alive bool) string {
		if alive {
			return "echo '1234 1000'"
		}
		return ":"
	}
	fakes := "id() { echo 1000; }\n" +
		"kill() { : > " + signalled + "; }\n" +
		"sleep() { :; }\n" +
		"rm() { echo \"rm $*\"; }\n" +
		"ps() { if [ -e " + signalled + " ]; then " + member(aliveAfterSignal) + "; else " + member(aliveBeforeSignal) + "; fi; }\n"
	return runSh(t, fakes+script)
}

// Stopping a run removes its token, since a killed run never reaches its exit
// path. Each branch that ends with the run gone removes it itself: the one
// that finds the group already gone, and the one that signals it and sees it
// die. A run that survives the signal keeps its token.
func TestBoxRunStop_RemovesTheToken(t *testing.T) {
	removal := "rm -f " + boxRunTokenPath("r1") + "\n"
	for _, tc := range []struct {
		name                    string
		aliveBefore, aliveAfter bool
		want                    string
	}{
		{name: "dead: the signal ends the group", aliveBefore: true, aliveAfter: false, want: removal + "dead\n"},
		{name: "gone: no such group", aliveBefore: false, aliveAfter: false, want: removal + "gone\n"},
		{name: "alive: the group survives the signal", aliveBefore: true, aliveAfter: true, want: "alive\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := boxRunStopScript(t.TempDir(), "r1", "ctn-run", 1234, false)
			if got := stopScriptOutcome(t, tc.aliveBefore, tc.aliveAfter, stop); got != tc.want {
				t.Errorf("stop script printed %q, want %q", got, tc.want)
			}
		})
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
	if err := s.installRunToken(context.Background(), "box1", "ctn-run", "r1", ""); err != nil || len(calls) != 0 {
		t.Fatalf("a run with no token installed something: calls=%v err=%v", calls, err)
	}
	if err := s.installRunToken(context.Background(), "box1", "ctn-run", "r1", "tok"); err != nil {
		t.Fatalf("installRunToken: %v", err)
	}
	if len(calls) != 1 || calls[0] != "box1/ctn-run/r1/tok" {
		t.Fatalf("install calls = %v, want one call with the run's token", calls)
	}
}

// Oversized or control-character tokens are refused before anything is written.
func TestValidateRunToken(t *testing.T) {
	if err := validateRunToken(""); err != nil {
		t.Fatalf("no token must be valid: %v", err)
	}
	if err := validateRunToken(strings.Repeat("a", runTokenMaxBytes+1)); err == nil {
		t.Error("an oversized token was accepted")
	}
	for _, bad := range []string{"tok\nen", "tok\rx", "to\x00k"} {
		if err := validateRunToken(bad); err == nil {
			t.Errorf("token %q with a control byte was accepted", bad)
		}
	}
	if err := validateRunToken("eyJhbGciOi.payload.sig"); err != nil {
		t.Errorf("a normal token was refused: %v", err)
	}
}

// The install is bounded: a hung install stops StartBoxRun waiting, so the run's
// lock is released.
func TestInstallRunToken_TimesOut(t *testing.T) {
	old := runTokenInstallTimeout
	runTokenInstallTimeout = 20 * time.Millisecond
	defer func() { runTokenInstallTimeout = old }()
	block := make(chan struct{})
	defer close(block)
	s := &ContainerServer{boxRunTokenInstall: func(string, string, string, string) error {
		<-block
		return nil
	}}
	err := s.installRunToken(context.Background(), "box1", "ctn-run", "r1", "tok")
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("a hung install returned %v; want a timeout", err)
	}
}

// A cancelled request stops the wait at once.
func TestInstallRunToken_CancelledRequestStopsWaiting(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	s := &ContainerServer{boxRunTokenInstall: func(string, string, string, string) error {
		<-block
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.installRunToken(ctx, "box1", "ctn-run", "r1", "tok")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled install returned %v, want context.Canceled", err)
	}
}
