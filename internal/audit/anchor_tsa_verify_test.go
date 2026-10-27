package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #2728: `audit verify-anchor` against the TSA tokens. Tokens come from
// fakeTSA (anchor_tsa_test.go); no real TSA is contacted.

type tsaVerifyFixture struct {
	t     *testing.T
	tsa   *testTSA
	file  *FileSink
	sink  *TSAAnchorSink
	fake  *fakeTSA
	chain *fakeChainStore
}

func newTSAVerifyFixture(t *testing.T, maxID int64) *tsaVerifyFixture {
	t.Helper()
	a := newValidTestTSA(t, "a")
	file, sink, fake := newTSAFixture(t, a, a)
	chain := &fakeChainStore{maxID: maxID, hashes: map[int64]string{}}
	for id := int64(1); id <= maxID; id++ {
		chain.hashes[id] = fmt.Sprintf("root-%d", id)
	}
	return &tsaVerifyFixture{t: t, tsa: a, file: file, sink: sink, fake: fake, chain: chain}
}

// anchor publishes through the tee, file first, as the daemon's tick does.
func (f *tsaVerifyFixture) anchor(checkpoints ...int64) {
	f.t.Helper()
	tee := NewTeeSink(f.file, f.sink)
	for _, cp := range checkpoints {
		if err := tee.PublishRoot(context.Background(), cp, fmt.Sprintf("root-%d", cp)); err != nil {
			f.t.Fatalf("PublishRoot(%d): %v", cp, err)
		}
	}
}

func (f *tsaVerifyFixture) verify(chain ChainStore) TSAAnchorReport {
	f.t.Helper()
	r, err := VerifyAnchorsAgainstTSA(context.Background(), chain, f.file, f.tsa.pool())
	if err != nil {
		f.t.Fatalf("VerifyAnchorsAgainstTSA: %v", err)
	}
	return r
}

// rewriteLocalLine replaces the root recorded for checkpoint in the local
// anchor file, as a host-root attacker would.
func (f *tsaVerifyFixture) rewriteLocalLine(checkpoint int64, newRoot string) {
	f.t.Helper()
	data := readFile(f.t, f.file.path)
	old := fmt.Sprintf(`"checkpoint":%d,"root":"root-%d"`, checkpoint, checkpoint)
	if !strings.Contains(data, old) {
		f.t.Fatalf("local file has no line for checkpoint %d", checkpoint)
	}
	data = strings.Replace(data, old, fmt.Sprintf(`"checkpoint":%d,"root":%q`, checkpoint, newRoot), 1)
	if err := os.WriteFile(f.file.path, []byte(data), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func tsaKinds(fs []TSAAnchorFinding) []TSAFindingKind {
	var out []TSAFindingKind
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}

func hasTSAFinding(fs []TSAAnchorFinding, kind TSAFindingKind, checkpoint int64) bool {
	for _, f := range fs {
		if f.Kind == kind && f.Checkpoint == checkpoint {
			return true
		}
	}
	return false
}

func TestVerifyAnchorsAgainstTSA_CleanIsOK(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10, 20)
	r := f.verify(f.chain)
	if !r.OK() || len(r.Warnings) != 0 {
		t.Fatalf("failures %v warnings %v, want none", tsaKinds(r.Failures), tsaKinds(r.Warnings))
	}
	if r.StampedCheckpoints != 2 || r.LatestStamped != 20 || r.TailCheckpoint != 20 || r.TailRoot != "root-20" {
		t.Fatalf("report = %+v", r)
	}
}

// Acceptance: tampering with the local anchor file after anchoring is
// detected against the TSA token. The attacker rewrites a row and the local
// line to match each other, which the local-file check alone cannot see.
func TestVerifyAnchorsAgainstTSA_DetectsTamperedLocalFile(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10, 20)
	f.chain.hashes[10] = "rewritten"
	f.rewriteLocalLine(10, "rewritten")

	r := f.verify(f.chain)
	if r.OK() {
		t.Fatal("tampered local file passed")
	}
	if !hasTSAFinding(r.Failures, TSAFindingImprintMismatch, 10) {
		t.Fatalf("failures = %v, want imprint-mismatch at 10", tsaKinds(r.Failures))
	}
	if hasTSAFinding(r.Failures, TSAFindingImprintMismatch, 20) {
		t.Fatal("untouched checkpoint 20 reported")
	}
}

// Acceptance: a token signed by a TSA outside the trust bundle is rejected.
func TestVerifyAnchorsAgainstTSA_UntrustedSignerFails(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10)
	other := newValidTestTSA(t, "other")
	planted := other.token(t, AnchorRecordDigest(10, "root-10"), time.Now())
	if err := os.WriteFile(filepath.Join(f.sink.TokenDir(), tsaTokenName(10)), planted, 0o600); err != nil {
		t.Fatal(err)
	}
	r := f.verify(f.chain)
	if !hasTSAFinding(r.Failures, TSAFindingUntrustedSigner, 10) {
		t.Fatalf("failures = %v, want untrusted-signer at 10", tsaKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstTSA_CorruptTokenFails(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10)
	if err := os.WriteFile(filepath.Join(f.sink.TokenDir(), tsaTokenName(10)), []byte{0x30, 0x02, 0x04, 0x01, 0x41}, 0o600); err != nil {
		t.Fatal(err)
	}
	r := f.verify(f.chain)
	if !hasTSAFinding(r.Failures, TSAFindingTokenInvalid, 10) {
		t.Fatalf("failures = %v, want token-invalid at 10", tsaKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstTSA_TokenWithoutLocalRecordFails(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10, 20)
	data := readFile(t, f.file.path)
	lines := splitNonEmptyLines(data)
	if err := os.WriteFile(f.file.path, []byte(lines[0]+"\n"), 0o600); err != nil { // drop checkpoint 20
		t.Fatal(err)
	}
	r := f.verify(f.chain)
	if !hasTSAFinding(r.Failures, TSAFindingMissingLocally, 20) {
		t.Fatalf("failures = %v, want missing-locally at 20", tsaKinds(r.Failures))
	}
}

// Q6: a checkpoint with no token (anchored before the TSA was configured, or
// a failed stamp) is a warning, exit zero; it is still checked against the
// database.
func TestVerifyAnchorsAgainstTSA_CheckpointWithoutTokenWarns(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	if err := f.file.PublishRoot(context.Background(), 5, "root-5"); err != nil { // before the TSA was configured
		t.Fatal(err)
	}
	f.anchor(10)
	f.fake.down = true
	if err := NewTeeSink(f.file, f.sink).PublishRoot(context.Background(), 20, "root-20"); err == nil {
		t.Fatal("publish with the TSA down succeeded")
	}

	r := f.verify(f.chain)
	if !r.OK() {
		t.Fatalf("failures = %v, want none", tsaKinds(r.Failures))
	}
	if !hasTSAFinding(r.Warnings, TSAFindingNoToken, 20) {
		t.Fatalf("warnings = %v, want no-token (latest unstamped 20)", tsaKinds(r.Warnings))
	}
	if r.TailCheckpoint != 20 {
		t.Fatalf("tail = %d, want 20 (the local-only checkpoint still bounds the tail check)", r.TailCheckpoint)
	}

	f.chain.hashes[5] = "rewritten"
	if r := f.verify(f.chain); !hasTSAFinding(r.Failures, TSAFindingDatabaseRootDiffers, 5) {
		t.Fatalf("failures = %v, want database-root-differs at the unstamped checkpoint 5", tsaKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstTSA_DatabaseRootMismatchFails(t *testing.T) {
	for name, mutate := range map[string]func(*fakeChainStore){
		"row rewritten": func(c *fakeChainStore) { c.hashes[10] = "rewritten" },
		"row deleted":   func(c *fakeChainStore) { delete(c.hashes, 10) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newTSAVerifyFixture(t, 30)
			f.anchor(10)
			mutate(f.chain)
			if r := f.verify(f.chain); !hasTSAFinding(r.Failures, TSAFindingDatabaseRootDiffers, 10) {
				t.Fatalf("failures = %v, want database-root-differs at 10", tsaKinds(r.Failures))
			}
		})
	}
}

func TestVerifyAnchorsAgainstTSA_UnrecognisedFileWarns(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10)
	for _, name := range []string{"notes.txt", "10.tsr", "-0000000000000000010.tsr"} {
		if err := os.WriteFile(filepath.Join(f.sink.TokenDir(), name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := f.verify(f.chain)
	if !r.OK() {
		t.Fatalf("failures = %v", tsaKinds(r.Failures))
	}
	n := 0
	for _, w := range r.Warnings {
		if w.Kind == TSAFindingUnrecognisedFile {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("unrecognised warnings = %d, want 3: %v", n, r.Warnings)
	}
}

func TestVerifyAnchorsAgainstTSA_NothingAnchored(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	if _, err := VerifyAnchorsAgainstTSA(context.Background(), f.chain, f.file, f.tsa.pool()); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("err = %v, want ErrNoAnchor", err)
	}
}

func TestVerifyAnchorsAgainstTSA_BelowChainBaseComparesTokenNotDatabase(t *testing.T) {
	f := newTSAVerifyFixture(t, 40)
	f.anchor(5, 20)
	for id := range f.chain.hashes {
		if id < 15 {
			delete(f.chain.hashes, id)
		}
	}
	chain := &purgedChain{fakeChainStore: f.chain, base: ChainBase{ID: 15, Hash: "root-15", RowsPurged: 15}}
	r := f.verify(chain)
	if !r.OK() || r.BelowChainBase != 1 || !hasTSAFinding(r.Warnings, TSAFindingBelowChainBase, 0) {
		t.Fatalf("report = %+v", r)
	}
	// The token still protects the purged checkpoint's local record.
	f.rewriteLocalLine(5, "rewritten")
	if r := f.verify(chain); !hasTSAFinding(r.Failures, TSAFindingImprintMismatch, 5) {
		t.Fatalf("failures = %v, want imprint-mismatch at 5", tsaKinds(r.Failures))
	}
}

// The tee's external sinks are independent: the bucket failing does not stop
// the TSA stamp, and the next tick retries only what is missing.
func TestTeeSink_ExternalSinksAreIndependent(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	var order []string
	bucket := &recordingSink{name: "bucket", order: &order, fail: errors.New("bucket unreachable"), inner: newTestGCSSink(t, newFakeGcloud())}
	tee := NewTeeSink(f.file, bucket, f.sink)
	err := tee.PublishRoot(context.Background(), 10, "root-10")
	if err == nil || !strings.Contains(err.Error(), "bucket unreachable") {
		t.Fatalf("err = %v, want the bucket failure", err)
	}
	if _, err := os.Stat(filepath.Join(f.sink.TokenDir(), tsaTokenName(10))); err != nil {
		t.Fatalf("TSA token not stored while the bucket failed: %v", err)
	}
	bucket.fail = nil
	if err := tee.PublishRoot(context.Background(), 10, "root-10"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if f.fake.calls != 1 {
		t.Fatalf("TSA calls = %d, want 1 (the retry must not re-stamp)", f.fake.calls)
	}
}
