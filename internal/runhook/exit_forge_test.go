//go:build !windows

package runhook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The run user owns the run directory, so it can write <name>.exit there. A
// command in the run that writes "0" into it after the engine was killed must
// not turn the sink's close from INTERRUPTED into ENGINE_REFUSED.
func TestRunEnded_RunUserForgedExitStatusIsNotTrusted(t *testing.T) {
	since := time.Now().Add(-time.Minute)
	dir := t.TempDir() // the run directory: writable by the run user
	b, _ := json.Marshal(map[string]any{"pid": 42, "started_at": time.Now()})
	if err := os.WriteFile(filepath.Join(dir, "r1.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	forged := "0 " + strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.WriteFile(filepath.Join(dir, "r1.exit"), []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	gone := func(int) bool { return false }

	// No root-owned status (the supervisor never wrote one, or none is
	// configured): the forged file is ignored.
	for _, exitPath := range []string{"", filepath.Join(t.TempDir(), "r1.exit")} {
		ended, how := runEnded(exitPath, dir, "r1", since, time.Now(), gone)
		if !ended || how != RunExitInterrupted {
			t.Errorf("exit path %q, run user wrote %q to the run directory: runEnded = %v, %v; want ended, interrupted", exitPath, forged, ended, how)
		}
	}
	// The root-owned status says killed: that wins over the forged file.
	root := filepath.Join(t.TempDir(), "r1.exit")
	if err := os.WriteFile(root, []byte("137 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ended, how := runEnded(root, dir, "r1", since, time.Now(), gone); !ended || how != RunExitInterrupted {
		t.Errorf("root status 137, forged run-directory 0: runEnded = %v, %v; want ended, interrupted", ended, how)
	}
}

// The supervisor is the run's parent: the status it records is the run's real
// one, whatever the run writes to the run directory, and the run is its own
// session (its process group is the run user's alone, for StopBoxRun).
func TestSupervise_RecordsTheRunsRealExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		status       string
		want         RunExit
	}{
		{"clean exit", "exit 0", "0", RunExitClean},
		{"failure", "exit 3", "3", RunExitInterrupted},
		{"killed after forging the run directory's exit file", `printf '0 1' > "$RUNDIR/r1.exit"; kill -9 $$`, "137", RunExitInterrupted},
		{"forged clean exit file, then non-zero", `printf '0 1' > "$RUNDIR/r1.exit"; exit 2`, "2", RunExitInterrupted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runDir := t.TempDir()
			exitPath := filepath.Join(t.TempDir(), "r1.exit")
			since := time.Now().Add(-time.Second)
			var launch bytes.Buffer
			err := supervise(superviseSpec{
				Shell: "/bin/sh", Command: tc.script, Dir: runDir,
				Env:      []string{"RUNDIR=" + runDir, "PATH=" + supervisePath},
				ExitPath: exitPath,
			}, &launch)
			if err != nil {
				t.Fatal(err)
			}
			f := strings.Fields(launch.String())
			if len(f) < 1 {
				t.Fatalf("launch line = %q, want \"<pid> <boot_id>\"", launch.String())
			}
			if _, err := strconv.Atoi(f[0]); err != nil {
				t.Errorf("launch pid = %q", f[0])
			}
			b, err := os.ReadFile(exitPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Fields(string(b)); len(got) != 2 || got[0] != tc.status {
				t.Errorf("exit status file = %q, want status %s", b, tc.status)
			}
			if fi, _ := os.Stat(exitPath); fi.Mode().Perm() != 0o600 {
				t.Errorf("exit status mode = %v, want 0600", fi.Mode().Perm())
			}
			b2, _ := json.Marshal(map[string]any{"pid": 42, "started_at": time.Now()})
			_ = os.WriteFile(filepath.Join(runDir, "r1.json"), b2, 0o600)
			if ended, how := runEnded(exitPath, runDir, "r1", since, time.Now(), func(int) bool { return true }); !ended || how != tc.want {
				t.Errorf("runEnded = %v, %v; want ended, %v", ended, how, tc.want)
			}
		})
	}
}

func TestSupervise_RunIsItsOwnSession(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ids")
	var launch bytes.Buffer
	err := supervise(superviseSpec{
		Shell: "/bin/sh", Command: `ps -o pid=,pgid=,sid= -p $$ > "$OUT"`, Dir: t.TempDir(),
		Env: []string{"OUT=" + out, "PATH=" + supervisePath}, ExitPath: filepath.Join(t.TempDir(), "x.exit"),
	}, &launch)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Skipf("no ps on this machine: %v", err)
	}
	f := strings.Fields(string(b))
	if len(f) != 3 || f[0] != f[1] || f[0] != f[2] || f[0] != strings.Fields(launch.String())[0] {
		t.Errorf("pid/pgid/sid = %q, launch = %q: the run must lead its own session and group", f, launch.String())
	}
	if f[1] == strconv.Itoa(syscall.Getpgrp()) {
		t.Error("the run shares the supervisor's process group")
	}
}

func TestLookupPasswd(t *testing.T) {
	p := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(p, []byte("root:x:0:0:root:/root:/bin/bash\nrunner:x:1500:1501::/home/runner:/bin/sh\nbad:x:z:1::/:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := lookupPasswd(p, "runner")
	if err != nil || e.uid != 1500 || e.gid != 1501 || e.home != "/home/runner" || e.shell != "/bin/sh" {
		t.Errorf("runner = %+v, %v", e, err)
	}
	if _, err := lookupPasswd(p, "nobody-here"); err == nil {
		t.Error("missing user must be an error")
	}
	if _, err := lookupPasswd(p, "bad"); err == nil {
		t.Error("malformed uid must be an error")
	}
}

func TestRunSuperviseCLI_RefusesWithoutAnExitPath(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "c.json")
	b, _ := json.Marshal(testConfig())
	if err := os.WriteFile(conf, b, 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := RunSuperviseCLI([]string{"--config", conf, "--user", "x", "--dir", "/", "--command", "true"}, &bytes.Buffer{}, &stderr); code == 0 {
		t.Errorf("no exit_path: exit %d, want refusal (%s)", code, stderr.String())
	}
	if code := RunSuperviseCLI(nil, &bytes.Buffer{}, &stderr); code != 2 || !strings.Contains(stderr.String(), SuperviseUsage) {
		t.Errorf("no args: exit %d, stderr %q", code, stderr.String())
	}
}

// End to end, without the daemon: the supervisor runs the run and records its
// status, the sink reads it through runEnded, and closes the open START. A
// clean run closes an engine-refused command as NOT_RUN / ENGINE_REFUSED; a
// run that is killed or fails closes it as UNKNOWN / INTERRUPTED, also when the
// run forged a clean exit file in its own directory; a command whose post hook
// fired keeps its RAN END and gets no second one.
func TestSupervisedRun_SinkClosesOpenStartsFromTheRootStatus(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		outcome      pb.AgentCommandOutcome
		reason       pb.AgentCommandCloseReason
	}{
		{"exits normally", "exit 0", pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_NOT_RUN, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_ENGINE_REFUSED},
		{"interrupted", "kill -9 $$", pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_UNKNOWN, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_INTERRUPTED},
		{"interrupted after forging a clean exit", `printf '0 1' > "$RUNDIR/r1.exit"; kill -9 $$`, pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_UNKNOWN, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_INTERRUPTED},
		{"fails", "exit 1", pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_UNKNOWN, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_INTERRUPTED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runDir := t.TempDir()
			exitPath := filepath.Join(t.TempDir(), "r1.exit")
			since := time.Now().Add(-time.Second)
			var how RunExit = -1
			cfg, send, stop := startSink(t, func() RunExit { return how })
			var out strings.Builder
			if err := RunPre(cfg, strings.NewReader(toolInput("PreToolUse", "toolu_ran", "git status", "")), &out, send); err != nil {
				t.Fatal(err)
			}
			if err := RunPost(cfg, strings.NewReader(toolInput("PostToolUse", "toolu_ran", "git status", `,"tool_response":{"stdout":""}`)), send); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err := RunPre(cfg, strings.NewReader(toolInput("PreToolUse", "toolu_open", "ls /outside", "")), &out, send); err != nil {
				t.Fatal(err)
			}
			if err := supervise(superviseSpec{Shell: "/bin/sh", Command: tc.script, Dir: runDir,
				Env: []string{"RUNDIR=" + runDir, "PATH=" + supervisePath}, ExitPath: exitPath}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			ended, h := runEnded(exitPath, runDir, "r1", since, time.Now(), func(int) bool { return true })
			if !ended {
				t.Fatal("the supervisor's status must end the sink's run")
			}
			how = h
			evs := stop()
			if ends := endsFor(evs, "toolu_ran"); len(ends) != 1 || ends[0].GetOutcome() != pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_RAN {
				t.Errorf("toolu_ran ENDs = %v, want exactly its RAN END", ends)
			}
			ends := endsFor(evs, "toolu_open")
			if len(ends) != 1 || ends[0].GetOutcome() != tc.outcome || ends[0].GetCloseReason() != tc.reason || ends[0].ExitCode != nil {
				t.Errorf("toolu_open ENDs = %v, want one %v / %v without an exit code", ends, tc.outcome, tc.reason)
			}
		})
	}
}
