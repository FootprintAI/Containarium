package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/spf13/cobra"
)

// --- `containarium code bootstrap <box>` (#3512) ---------------------------

// bootstrapRun is what one runCodeBootstrapWith call observed.
type bootstrapRun struct {
	runs        []installRun
	urlCmdCalls []string // the --url-cmd command each call received
	stdout      string
	stderr      string
	resolved    bool
}

// runCodeBootstrapWith drives runCodeBootstrap against fakes. urlCmdOut and
// urlCmdErr are what the fake --url-cmd hook returns.
func runCodeBootstrapWith(t *testing.T, box, url, urlCmd string, f installFakes, urlCmdOut string, urlCmdErr error) (bootstrapRun, error) {
	t.Helper()
	origSSH, origResolve, origURLCmd := sshExec, resolveCodeTargetFn, runURLCmdFn
	origURL, origCmd := codeBootstrapFlagURL, codeBootstrapFlagURLCmd
	t.Cleanup(func() {
		sshExec, resolveCodeTargetFn, runURLCmdFn = origSSH, origResolve, origURLCmd
		codeBootstrapFlagURL, codeBootstrapFlagURLCmd = origURL, origCmd
	})
	codeBootstrapFlagURL, codeBootstrapFlagURLCmd = url, urlCmd

	var r bootstrapRun
	resolveCodeTargetFn = func(context.Context, string, io.Writer) (connectcore.Target, string, error) {
		r.resolved = true
		return connectcore.Target{User: "alice", Host: "box.example.test", Port: 22}, "/dev/null", nil
	}
	sshExec = func(_ io.Writer, args []string) (string, error) {
		script := args[len(args)-1]
		r.runs = append(r.runs, installRun{script: script})
		if f.events != nil {
			*f.events = append(*f.events, "exec")
		}
		if f.exec != nil {
			return f.exec(script)
		}
		return "", nil
	}
	withProbe(t, func(_ context.Context, args []string) error {
		if f.events != nil {
			*f.events = append(*f.events, "probe")
		}
		if f.probe != nil {
			return f.probe(args)
		}
		return nil
	})
	runURLCmdFn = func(_ context.Context, command, gotBox string, _ io.Writer) (string, error) {
		r.urlCmdCalls = append(r.urlCmdCalls, command)
		if f.events != nil {
			*f.events = append(*f.events, "url-cmd")
		}
		if gotBox != box {
			t.Errorf("--url-cmd ran for box %q, want %q", gotBox, box)
		}
		return urlCmdOut, urlCmdErr
	}

	cmd := &cobra.Command{}
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetContext(context.Background())
	err := runCodeBootstrap(cmd, []string{box})
	r.stdout, r.stderr = out.String(), errBuf.String()
	return r, err
}

func TestCodeBootstrap_AppliesOnlyTheBundle(t *testing.T) {
	r, err := runCodeBootstrapWith(t, "alice", testBundleURL, "", installFakes{}, "", nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if len(r.runs) != 1 {
		t.Fatalf("ran %d scripts, want exactly the bundle step:\n%s", len(r.runs), allScripts(r.runs))
	}
	scripts := allScripts(r.runs)
	if !strings.Contains(r.runs[0].script, "apply.sh") || !strings.Contains(scripts, coderun.ShellQuoteSingle(testBundleURL)) {
		t.Errorf("the one script is not the bundle step with the quoted URL:\n%s", scripts)
	}
	for _, banned := range []string{claudeInstallScript, "agent-box-" + agentBoxAssetArch, "install-sdlc-skills", engine.CodeConfigPath, "sudo"} {
		if strings.Contains(scripts, banned) {
			t.Errorf("code bootstrap ran a script containing %q:\n%s", banned, scripts)
		}
	}
	if !strings.Contains(r.stdout, "bootstrap bundle applied on alice") {
		t.Errorf("stdout = %q", r.stdout)
	}
	if strings.Contains(r.stdout+r.stderr, testBundleURL) {
		t.Error("the URL was printed")
	}
}

func TestCodeBootstrap_URLCmdRunsOnceAfterThePreflight(t *testing.T) {
	var events []string
	const hook = `my-control-plane bootstrap-url "$CONTAINARIUM_BOX"`
	r, err := runCodeBootstrapWith(t, "alice", "", hook, installFakes{events: &events}, testBundleURL, nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if len(r.urlCmdCalls) != 1 || r.urlCmdCalls[0] != hook {
		t.Fatalf("--url-cmd calls = %q, want exactly one with the flag's command", r.urlCmdCalls)
	}
	if strings.Join(events, ",") != "probe,url-cmd,exec" {
		t.Errorf("call order = %v, want the preflight probe, then --url-cmd, then the bundle step", events)
	}
	if len(r.runs) != 1 || !strings.Contains(r.runs[0].script, coderun.ShellQuoteSingle(testBundleURL)) {
		t.Errorf("the hook's URL did not reach the bundle step, shell-quoted:\n%s", allScripts(r.runs))
	}
	if strings.Contains(r.stdout+r.stderr, testBundleURL) {
		t.Error("the URL was printed")
	}
}

func TestCodeBootstrap_PreflightFailureNeverRunsTheURLCmd(t *testing.T) {
	for name, perr := range map[string]error{
		"host unreachable":  &connectcore.SSHError{ExitCode: 255, Stderr: "ssh: connect to host box.example.test port 22: No route to host", Err: errors.New("exit status 255")},
		"home not writable": &remoteExitError{code: preflightExitHome},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := runCodeBootstrapWith(t, "alice", "", "printf x", installFakes{
				probe: func([]string) error { return perr },
			}, testBundleURL, nil)
			if err == nil {
				t.Fatal("bootstrap succeeded although the preflight failed")
			}
			if len(r.urlCmdCalls) != 0 {
				t.Errorf("--url-cmd ran %d times after a failed preflight", len(r.urlCmdCalls))
			}
			if len(r.runs) != 0 {
				t.Errorf("%d scripts ran after a failed preflight", len(r.runs))
			}
			if !strings.Contains(err.Error(), "nothing was requested or applied") {
				t.Errorf("error %q does not say nothing was requested", err)
			}
		})
	}
}

func TestCodeBootstrap_FetchAndApplyFailuresDiffer(t *testing.T) {
	for code, want := range map[int]string{
		bootstrapExitFetch:        "not consumed, retry is safe",
		bootstrapExitFetchReached: "may already be consumed",
		bootstrapExitApply:        "one-shot URL is spent",
	} {
		r, err := runCodeBootstrapWith(t, "alice", "", "printf x", installFakes{
			exec: func(string) (string, error) { return "", &remoteExitError{code: code} },
		}, testBundleURL, nil)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), `"alice"`) {
			t.Errorf("exit %d: error = %v, want it to say %q and name the box", code, err, want)
			continue
		}
		if strings.Contains(err.Error()+r.stdout+r.stderr, testBundleURL) {
			t.Errorf("exit %d: the URL was printed", code)
		}
	}
}

func TestCodeBootstrap_URLCmdFailureAppliesNothing(t *testing.T) {
	r, err := runCodeBootstrapWith(t, "alice", "", "false", installFakes{}, "", errors.New("exit status 1"))
	if err == nil {
		t.Fatal("bootstrap succeeded although --url-cmd failed")
	}
	if len(r.runs) != 0 {
		t.Errorf("%d scripts ran after --url-cmd failed", len(r.runs))
	}
	if !strings.Contains(err.Error(), "nothing was applied") {
		t.Errorf("error %q does not say nothing was applied", err)
	}
}

func TestCodeBootstrap_URLSourceFlags(t *testing.T) {
	tests := []struct {
		name, url, cmd, want string
	}{
		{name: "both", url: testBundleURL, cmd: "printf x", want: "mutually exclusive"},
		{name: "neither", want: "--url or --url-cmd"},
		{name: "blank", url: "  ", cmd: " ", want: "--url or --url-cmd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := runCodeBootstrapWith(t, "alice", tc.url, tc.cmd, installFakes{}, testBundleURL, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if r.resolved || len(r.urlCmdCalls) != 0 || len(r.runs) != 0 {
				t.Errorf("a flag error must stop before any lookup, hook or script (resolved=%v hook=%d scripts=%d)",
					r.resolved, len(r.urlCmdCalls), len(r.runs))
			}
		})
	}
}

// TestRunURLCmd runs the real hook through /bin/sh: it sees CONTAINARIUM_BOX,
// only its first stdout line is the URL, its stderr reaches the user, and a
// failing or silent hook is an error.
func TestRunURLCmd(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	var stderr bytes.Buffer
	got, err := runURLCmd(context.Background(), `printf 'https://b.example.test/%s\nsecond line\n' "$CONTAINARIUM_BOX"; echo diag >&2`, "alice", &stderr)
	if err != nil {
		t.Fatalf("runURLCmd: %v", err)
	}
	if got != "https://b.example.test/alice" {
		t.Errorf("url = %q, want the first stdout line with the box substituted", got)
	}
	if !strings.Contains(stderr.String(), "diag") {
		t.Errorf("the hook's stderr should reach the user, got %q", stderr.String())
	}
	if _, err := runURLCmd(context.Background(), "exit 3", "alice", &stderr); err == nil {
		t.Error("a failing hook must error")
	}
	if _, err := runURLCmd(context.Background(), `printf '\n'`, "alice", &stderr); err == nil {
		t.Error("a hook that prints no URL must error")
	}
}
