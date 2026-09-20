package submit

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// recordedCall is one gitRunFunc invocation captured by a fake runner.
type recordedCall struct {
	env  []string
	args []string
}

// fakeRunner returns a gitRunFunc that records every call and returns
// canned (stdout, stderr, err) tuples in order; calls beyond len(results)
// return a zero-value success.
func fakeRunner(calls *[]recordedCall, results ...error) gitRunFunc {
	i := 0
	return func(_ context.Context, env []string, args []string) (string, string, error) {
		*calls = append(*calls, recordedCall{env: append([]string(nil), env...), args: append([]string(nil), args...)})
		var err error
		if i < len(results) {
			err = results[i]
		}
		i++
		return "", "", err
	}
}

func validSpec() PushSpec {
	return PushSpec{
		BundlePath:  "/tmp/does-not-matter.bundle",
		BaseSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		HeadSHA:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RemoteURL:   "https://tracker.example/acme/widgets.git",
		Credential:  "s3cr3t-token-value",
		RunID:       "run-abc123def456ghi789",
		IssueNumber: 42,
		Title:       "Fix the thing",
	}
}

func TestGitPusher_EnvAndArgv(t *testing.T) {
	var calls []recordedCall
	pusher := &ExecGitPusher{run: fakeRunner(&calls)}

	spec := validSpec()
	result, err := pusher.PushBundle(context.Background(), spec)
	if err != nil {
		t.Fatalf("PushBundle: %v", err)
	}

	if len(calls) != 5 {
		t.Fatalf("got %d git invocations, want 5 (init, fetch base, verify, fetch bundle, push); calls=%+v", len(calls), calls)
	}

	for i, c := range calls {
		argv := strings.Join(c.args, " ")
		if strings.Contains(argv, spec.Credential) {
			t.Errorf("call %d: credential %q found in argv %q — must be env-only", i, spec.Credential, argv)
		}
		if strings.Contains(argv, "-c ") || contains(c.args, "-c") {
			t.Errorf("call %d: argv %q contains a -c flag; hardening must go through GIT_CONFIG_* env vars, not argv", i, argv)
		}

		wantEnvContains := []string{
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
		}
		for _, want := range wantEnvContains {
			if !contains(c.env, want) {
				t.Errorf("call %d: env missing %q; env=%v", i, want, c.env)
			}
		}
		if !anyHasPrefix(c.env, "HOME=") {
			t.Errorf("call %d: env missing HOME override; env=%v", i, c.env)
		}

		// The credential must appear SOMEWHERE in env (as the
		// http.extraHeader GIT_CONFIG_VALUE), and never anywhere else.
		foundInEnv := false
		for _, e := range c.env {
			if strings.Contains(e, spec.Credential) {
				foundInEnv = true
				if !strings.Contains(e, "GIT_CONFIG_VALUE_") {
					t.Errorf("call %d: credential found in unexpected env var %q", i, e)
				}
			}
		}
		if !foundInEnv {
			t.Errorf("call %d: credential not present in env at all — PushBundle must supply it via GIT_CONFIG_VALUE_N", i)
		}
	}

	// First call is `init --bare` and must name the temp dir directly
	// (no -C yet, since the repo doesn't exist until this runs).
	if calls[0].args[0] != "init" {
		t.Errorf("first call = %v, want init --bare ...", calls[0].args)
	}

	// The final call must be the push, with no --force anywhere in argv.
	last := calls[len(calls)-1]
	if !contains(last.args, "push") {
		t.Errorf("last call = %v, want a push", last.args)
	}
	if contains(last.args, "--force") || contains(last.args, "-f") {
		t.Errorf("last call = %v, must never force-push", last.args)
	}
	if !contains(last.args, spec.RemoteURL) {
		t.Errorf("push call = %v, want remote URL %q", last.args, spec.RemoteURL)
	}
	wantRefspec := spec.HeadSHA + ":refs/heads/" + result.Branch
	if !contains(last.args, wantRefspec) {
		t.Errorf("push call = %v, want refspec %q", last.args, wantRefspec)
	}

	if result.SHA != spec.HeadSHA {
		t.Errorf("result.SHA = %q, want %q", result.SHA, spec.HeadSHA)
	}
	wantBranch := BranchName(spec.RunID, spec.IssueNumber, spec.Title)
	if result.Branch != wantBranch {
		t.Errorf("result.Branch = %q, want %q", result.Branch, wantBranch)
	}
}

func TestGitPusher_EachStepFailureAbortsAndWrapsError(t *testing.T) {
	stepErr := errors.New("boom")
	for i := 0; i < 5; i++ {
		results := make([]error, 5)
		results[i] = stepErr
		var calls []recordedCall
		pusher := &ExecGitPusher{run: fakeRunner(&calls, results...)}

		_, err := pusher.PushBundle(context.Background(), validSpec())
		if err == nil {
			t.Fatalf("step %d: PushBundle succeeded, want error", i)
		}
		if !errors.Is(err, stepErr) {
			t.Errorf("step %d: err = %v, want wrapping %v", i, err, stepErr)
		}
		if len(calls) != i+1 {
			t.Errorf("step %d: got %d calls, want exactly %d (abort after the failing step)", i, len(calls), i+1)
		}
	}
}

func TestGitPusher_ErrorNeverEchoesCredential(t *testing.T) {
	spec := validSpec()
	stepErr := errors.New("boom")
	// A fake runner whose "stderr" (returned as the second string, here
	// folded into the error by wrapGitErr in production — this test
	// exercises wrapGitErr directly since gitRunFunc's signature returns
	// stdout/stderr separately from err) — see wrapGitErr test below for
	// the direct check; this test additionally confirms PushBundle's
	// returned error text never contains the raw credential even when
	// the underlying error message happens to.
	leaky := func(_ context.Context, _ []string, _ []string) (string, string, error) {
		return "", "leaked header value: " + spec.Credential, stepErr
	}
	pusher := &ExecGitPusher{run: leaky}
	_, err := pusher.PushBundle(context.Background(), spec)
	if err == nil {
		t.Fatal("PushBundle succeeded, want error")
	}
	if strings.Contains(err.Error(), spec.Credential) {
		t.Errorf("error %q contains the raw credential", err.Error())
	}
}

func TestGitPusher_EmptyShaRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec PushSpec
	}{
		{"empty base", func() PushSpec { s := validSpec(); s.BaseSHA = ""; return s }()},
		{"empty head", func() PushSpec { s := validSpec(); s.HeadSHA = ""; return s }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []recordedCall
			pusher := &ExecGitPusher{run: fakeRunner(&calls)}
			_, err := pusher.PushBundle(context.Background(), tc.spec)
			if !errors.Is(err, ErrEmptyBundle) {
				t.Errorf("err = %v, want ErrEmptyBundle", err)
			}
			if len(calls) != 0 {
				t.Errorf("got %d git invocations, want 0 — must reject before running anything", len(calls))
			}
		})
	}
}

func TestTmpdir_RemovedOnEveryPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []error
	}{
		{"success", nil},
		{"fails on the third step", []error{nil, nil, errors.New("boom")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []recordedCall
			var capturedDir string
			run := func(ctx context.Context, env []string, args []string) (string, string, error) {
				calls = append(calls, recordedCall{env: env, args: args})
				if capturedDir == "" {
					for _, e := range env {
						if strings.HasPrefix(e, "HOME=") {
							capturedDir = strings.TrimPrefix(e, "HOME=")
						}
					}
				}
				idx := len(calls) - 1
				if idx < len(tc.results) {
					return "", "", tc.results[idx]
				}
				return "", "", nil
			}
			pusher := &ExecGitPusher{run: run}
			_, _ = pusher.PushBundle(context.Background(), validSpec())

			if capturedDir == "" {
				t.Fatal("never captured a HOME dir from any call")
			}
			if _, err := os.Stat(capturedDir); !os.IsNotExist(err) {
				t.Errorf("temp dir %q still exists after PushBundle returned (stat err = %v)", capturedDir, err)
			}
		})
	}
}

func TestGitVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		out          string
		major, minor int
		want         bool
	}{
		{"git version 2.43.0", 2, 31, true},
		{"git version 2.31.0", 2, 31, true},
		{"git version 2.30.9", 2, 31, false},
		{"git version 1.9.5", 2, 31, false},
		{"git version 3.0.0", 2, 31, true},
		{"garbage output", 2, 31, false},
		{"", 2, 31, false},
	} {
		if got := GitVersionAtLeast(tc.out, tc.major, tc.minor); got != tc.want {
			t.Errorf("GitVersionAtLeast(%q, %d, %d) = %v, want %v", tc.out, tc.major, tc.minor, got, tc.want)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func anyHasPrefix(ss []string, prefix string) bool {
	for _, s := range ss {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
