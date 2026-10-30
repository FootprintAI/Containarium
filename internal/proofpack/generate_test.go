package proofpack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBox answers Generate's execs from canned values, so the tests
// control exactly what "the box" returns.
type fakeBox struct {
	declaration *string // nil = no .github/containarium.yml
	makefile    bool
	noTimeout   bool // the box has no coreutils `timeout`
	missingDir  bool
	commit      string
	// steps maps a command line to its result.
	steps map[string]fakeResult
	// ran records the command lines executed, in order.
	ran []string
	// argv records every exec, to show nothing but the wrapper and its
	// positional args reaches the box.
	argv [][]string
}

type fakeResult struct {
	log  string
	exit int
	size int64 // 0 = len(log)
}

func strp(s string) *string { return &s }

func (f *fakeBox) ExecWithExitCode(_ string, argv []string) (string, string, int, error) {
	f.argv = append(f.argv, argv)
	switch {
	case len(argv) > 3 && argv[3] == "proofpack-probe":
		if f.missingDir {
			return "", "sh: cd: can't cd to " + argv[4], 97, nil
		}
		rc := 10
		out := ""
		if f.declaration != nil {
			rc++
			out = *f.declaration
		}
		if f.makefile {
			rc += 2
		}
		if f.noTimeout {
			rc += 4
		}
		return out, "", rc, nil
	case len(argv) > 0 && argv[0] == "git":
		if f.commit == "" {
			return "", "fatal: not a git repository", 128, nil
		}
		return f.commit + "\n", "", 0, nil
	case len(argv) > 6 && argv[3] == "proofpack-step":
		run := argv[6]
		f.ran = append(f.ran, run)
		r, ok := f.steps[run]
		if !ok {
			return "", "", 0, fmt.Errorf("unexpected command %q", run)
		}
		size := r.size
		if size == 0 {
			size = int64(len(r.log))
		}
		return r.log, fmt.Sprintf("%d\n", size), r.exit, nil
	}
	return "", "", 0, fmt.Errorf("unexpected exec %q", argv)
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

// The issue's acceptance case: the coding agent claims tests_run: true, the
// tests actually fail, and the pack shows the failure. Generate has no
// parameter for the agent's claim; the pack is built from what ran.
func TestGenerate_FailingTestsShowFailure(t *testing.T) {
	failLog := "--- FAIL: TestWidget (0.00s)\n    widget_test.go:12: got 1, want 2\nFAIL\n"
	box := &fakeBox{
		declaration: strp("test:\n  - name: unit\n    kind: unit\n    run: go test ./...\n  - name: vet\n    kind: static_analysis\n    run: go vet ./...\n"),
		commit:      "0123456789abcdef0123456789abcdef01234567",
		steps: map[string]fakeResult{
			"go test ./...": {log: failLog, exit: 1},
			"go vet ./...":  {log: "", exit: 0},
		},
	}
	pack, err := Generate(context.Background(), box, "tenant-box", Options{Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED {
		t.Fatalf("status = %v, want FAILED", pack.GetStatus())
	}
	if pack.GetCommandSource() != pb.ProofCommandSource_PROOF_COMMAND_SOURCE_DECLARED {
		t.Errorf("command_source = %v, want DECLARED", pack.GetCommandSource())
	}
	if pack.GetDeclarationSha256() != LogDigest([]byte(*box.declaration)) {
		t.Errorf("declaration_sha256 does not match the declaration read")
	}
	if pack.GetProducer() != "tenant-box" || pack.GetRepoDir() != DefaultRepoDir || pack.GetGitCommit() != box.commit {
		t.Errorf("producer/repo_dir/git_commit = %q/%q/%q", pack.GetProducer(), pack.GetRepoDir(), pack.GetGitCommit())
	}
	if len(pack.GetSteps()) != 2 {
		t.Fatalf("steps = %d, want 2", len(pack.GetSteps()))
	}
	unit := pack.GetSteps()[0]
	if unit.GetName() != "unit" || unit.GetKind() != pb.ProofPartKind_PROOF_PART_KIND_UNIT {
		t.Errorf("step 0 = %q/%v", unit.GetName(), unit.GetKind())
	}
	if unit.GetExitCode() != 1 || unit.GetTimedOut() {
		t.Errorf("unit exit=%d timed_out=%v, want 1/false", unit.GetExitCode(), unit.GetTimedOut())
	}
	if string(unit.GetLog()) != failLog {
		t.Errorf("unit log = %q", unit.GetLog())
	}
	if unit.GetLogSha256() != LogDigest([]byte(failLog)) {
		t.Errorf("unit log digest mismatch")
	}
	if unit.GetLogTruncated() || unit.GetLogOriginalBytes() != int64(len(failLog)) {
		t.Errorf("unit truncated=%v original=%d", unit.GetLogTruncated(), unit.GetLogOriginalBytes())
	}
	if unit.GetDurationMs() != 1000 {
		t.Errorf("unit duration_ms = %d, want 1000 from the fixed clock", unit.GetDurationMs())
	}
	wantCounts := []*pb.ProofKindCount{
		{Kind: pb.ProofPartKind_PROOF_PART_KIND_UNIT, Passed: 0, Failed: 1},
		{Kind: pb.ProofPartKind_PROOF_PART_KIND_STATIC_ANALYSIS, Passed: 1, Failed: 0},
	}
	if len(pack.GetCounts()) != len(wantCounts) {
		t.Fatalf("counts = %v", pack.GetCounts())
	}
	for i, w := range wantCounts {
		if !proto.Equal(pack.GetCounts()[i], w) {
			t.Errorf("counts[%d] = %v, want %v", i, pack.GetCounts()[i], w)
		}
	}
	if err := CheckPartDigests(pack); err != nil {
		t.Errorf("CheckPartDigests on a fresh pack: %v", err)
	}
	if got := strings.Join(box.ran, "|"); got != "go test ./...|go vet ./..." {
		t.Errorf("ran %q, want declaration order", got)
	}
}

// Argv and environment never reach the pack: only the declared name and
// kind identify a step.
func TestGenerate_NoArgvOrEnvRecorded(t *testing.T) {
	const run = "SECRET_TOKEN=hunter2-env-value go test -run TestOnlyThis ./pkg/..."
	box := &fakeBox{
		declaration: strp("test:\n  - name: unit\n    run: \"" + run + "\"\n"),
		steps:       map[string]fakeResult{run: {log: "ok\n", exit: 0}},
	}
	t.Setenv("PROOFPACK_TEST_ENV_MARKER", "env-marker-value-7f3a")
	pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	js, err := protojson.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{run, "hunter2-env-value", "TestOnlyThis", "env-marker-value-7f3a"} {
		if bytes.Contains(wire, []byte(needle)) || bytes.Contains(js, []byte(needle)) {
			t.Errorf("pack contains %q", needle)
		}
	}
	// The environment is not forwarded to the box either: every exec is the
	// fixed wrapper plus positional args.
	for _, argv := range box.argv {
		if strings.Contains(strings.Join(argv, " "), "env-marker-value-7f3a") {
			t.Errorf("exec argv carries the daemon's environment: %q", argv)
		}
	}
}

func TestGenerate_TruncatedLogKeepsTail(t *testing.T) {
	tail := strings.Repeat("x", LogLimitBytes-4) + "FAIL"
	box := &fakeBox{
		declaration: strp("test: make check\n"),
		steps:       map[string]fakeResult{"make check": {log: tail, exit: 2, size: 5 * LogLimitBytes}},
	}
	pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	s := pack.GetSteps()[0]
	if s.GetName() != "test" || s.GetKind() != pb.ProofPartKind_PROOF_PART_KIND_TEST {
		t.Errorf("string-form step = %q/%v, want test/TEST", s.GetName(), s.GetKind())
	}
	if !s.GetLogTruncated() || s.GetLogOriginalBytes() != 5*LogLimitBytes {
		t.Errorf("truncated=%v original=%d", s.GetLogTruncated(), s.GetLogOriginalBytes())
	}
	if len(s.GetLog()) != LogLimitBytes || !bytes.HasSuffix(s.GetLog(), []byte("FAIL")) {
		t.Errorf("log len=%d, want the last %d bytes", len(s.GetLog()), LogLimitBytes)
	}
	if s.GetLogSha256() != LogDigest(s.GetLog()) {
		t.Errorf("digest is not over the stored (truncated) bytes")
	}
	if pack.GetLogLimitBytes() != LogLimitBytes {
		t.Errorf("log_limit_bytes = %d", pack.GetLogLimitBytes())
	}
}

func TestGenerate_FallbackAndNone(t *testing.T) {
	t.Run("no declaration, Makefile -> make test", func(t *testing.T) {
		box := &fakeBox{makefile: true, steps: map[string]fakeResult{"make test": {log: "PASS\n"}}}
		pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
		if err != nil {
			t.Fatal(err)
		}
		if pack.GetCommandSource() != pb.ProofCommandSource_PROOF_COMMAND_SOURCE_FALLBACK_MAKE_TEST {
			t.Errorf("source = %v", pack.GetCommandSource())
		}
		if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED || pack.GetSteps()[0].GetName() != "make-test" {
			t.Errorf("status=%v step=%q", pack.GetStatus(), pack.GetSteps()[0].GetName())
		}
		if pack.GetDeclarationSha256() != "" {
			t.Errorf("declaration_sha256 set without a declaration")
		}
	})
	t.Run("declaration without test key, Makefile -> make test", func(t *testing.T) {
		box := &fakeBox{declaration: strp("other_feature: true\n"), makefile: true,
			steps: map[string]fakeResult{"make test": {log: "PASS\n"}}}
		pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
		if err != nil {
			t.Fatal(err)
		}
		if pack.GetCommandSource() != pb.ProofCommandSource_PROOF_COMMAND_SOURCE_FALLBACK_MAKE_TEST {
			t.Errorf("source = %v", pack.GetCommandSource())
		}
	})
	t.Run("nothing to run -> NO_COMMANDS", func(t *testing.T) {
		box := &fakeBox{}
		pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
		if err != nil {
			t.Fatal(err)
		}
		if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_NO_COMMANDS ||
			pack.GetCommandSource() != pb.ProofCommandSource_PROOF_COMMAND_SOURCE_NONE ||
			len(pack.GetSteps()) != 0 || len(box.ran) != 0 {
			t.Errorf("status=%v source=%v steps=%d ran=%v", pack.GetStatus(), pack.GetCommandSource(), len(pack.GetSteps()), box.ran)
		}
	})
}

func TestGenerate_Refusals(t *testing.T) {
	if _, err := Generate(context.Background(), &fakeBox{missingDir: true}, "b", Options{}); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing repo dir: err = %v", err)
	}
	bad := &fakeBox{declaration: strp("test:\n  - name: unit\n    kind: fuzz\n    run: x\n")}
	if _, err := Generate(context.Background(), bad, "b", Options{}); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("bad declaration: err = %v", err)
	}
	null := &fakeBox{declaration: strp("test:\n"), makefile: true, steps: map[string]fakeResult{"make test": {}}}
	if _, err := Generate(context.Background(), null, "b", Options{}); err == nil || len(null.ran) != 0 {
		t.Errorf("null test: key: err=%v ran=%v, want an error and no fallback", err, null.ran)
	}
	big := &fakeBox{declaration: strp(strings.Repeat("#", MaxDeclarationBytes+1))}
	if _, err := Generate(context.Background(), big, "b", Options{}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized declaration: err = %v", err)
	}
	if _, err := Generate(context.Background(), &fakeBox{}, "", Options{}); err == nil {
		t.Errorf("empty box name accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	box := &fakeBox{makefile: true, steps: map[string]fakeResult{"make test": {}}}
	if _, err := Generate(ctx, box, "b", Options{}); !errors.Is(err, context.Canceled) || len(box.ran) != 0 {
		t.Errorf("cancelled ctx: err=%v ran=%v", err, box.ran)
	}
}

// A wrapper failure (stderr is not the size line) is an error, not a step
// outcome: the pack must not record "exit 97" as if the tests had run.
func TestGenerate_WrapperFailureIsError(t *testing.T) {
	box := &wrapperFailBox{}
	if _, err := Generate(context.Background(), box, "b", Options{}); err == nil || !strings.Contains(err.Error(), "could not run") {
		t.Errorf("err = %v", err)
	}
}

type wrapperFailBox struct{}

func (wrapperFailBox) ExecWithExitCode(_ string, argv []string) (string, string, int, error) {
	if argv[3] == "proofpack-probe" {
		return "", "", 12, nil
	}
	if argv[0] == "git" {
		return "", "", 128, nil
	}
	return "", "mktemp: failed to create file\n", 98, nil
}

func TestPartDigests(t *testing.T) {
	box := &fakeBox{makefile: true, steps: map[string]fakeResult{"make test": {log: "PASS\n"}}}
	pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	d1, err := PackDigest(pack)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through the wire format: the digest is a function of the
	// content, not of the in-memory value.
	wire, err := proto.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	var back pb.ProofPack
	if err := proto.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if d2, _ := PackDigest(&back); d2 != d1 {
		t.Errorf("PackDigest not stable across a round trip: %s vs %s", d1, d2)
	}

	back.Steps[0].Log[0] ^= 1
	err = CheckPartDigests(&back)
	if err == nil || !strings.Contains(err.Error(), `"make-test"`) {
		t.Errorf("tampered log: err = %v, want it to name the step", err)
	}
	if d3, _ := PackDigest(&back); d3 == d1 {
		t.Errorf("PackDigest did not change after a log byte changed")
	}
}

// A box without `timeout` can still report that there is nothing to run;
// it is an error only when a step would have to be bounded.
func TestGenerate_MissingTimeoutOnlyMattersWhenAStepRuns(t *testing.T) {
	box := &fakeBox{noTimeout: true}
	pack, err := Generate(context.Background(), box, "b", Options{Now: fixedClock()})
	if err != nil {
		t.Fatalf("no commands and no timeout: %v", err)
	}
	if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_NO_COMMANDS {
		t.Errorf("status = %v", pack.GetStatus())
	}
	for name, b := range map[string]*fakeBox{
		"fallback": {noTimeout: true, makefile: true, steps: map[string]fakeResult{"make test": {}}},
		"declared": {noTimeout: true, declaration: strp("test: x\n"), steps: map[string]fakeResult{"x": {}}},
	} {
		if _, err := Generate(context.Background(), b, "b", Options{}); err == nil || !strings.Contains(err.Error(), "timeout") || len(b.ran) != 0 {
			t.Errorf("%s: err=%v ran=%v, want a timeout error and nothing run", name, err, b.ran)
		}
	}
}
