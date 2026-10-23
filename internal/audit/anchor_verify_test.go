package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2560 slice B (#2881): `audit verify-anchor` against the bucket. Every
// test runs against fakeGcloud (an in-memory bucket) and fakeChainStore; no
// real bucket is touched (decision Q18.5 on #2727).

const lockedRetentionJSON = `{"retention_policy": {"isLocked": true, "retentionPeriod": "31536000"}}`

// anchorFixture is a local file sink and a bucket sink wired together the
// way the daemon does it (file first, then bucket), plus a chain whose
// rows hash to "root-<id>".
type anchorFixture struct {
	t        *testing.T
	gcloud   *fakeGcloud
	bucket   *GCSAnchorSink
	file     *FileSink
	filePath string
	tee      *TeeSink
	chain    *fakeChainStore
}

func newAnchorFixture(t *testing.T, maxID int64) *anchorFixture {
	t.Helper()
	g := newFakeGcloud()
	g.retentionJSON = lockedRetentionJSON
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	file, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	b := newTestGCSSink(t, g)
	chain := &fakeChainStore{maxID: maxID, hashes: map[int64]string{}}
	for id := int64(1); id <= maxID; id++ {
		chain.hashes[id] = fmt.Sprintf("root-%d", id)
	}
	return &anchorFixture{t: t, gcloud: g, bucket: b, file: file, filePath: path, tee: NewTeeSink(file, b), chain: chain}
}

// anchor publishes checkpoints through the tee, as the daemon's tick does.
func (f *anchorFixture) anchor(checkpoints ...int64) {
	f.t.Helper()
	for _, cp := range checkpoints {
		if err := f.tee.PublishRoot(context.Background(), cp, fmt.Sprintf("root-%d", cp)); err != nil {
			f.t.Fatalf("PublishRoot(%d): %v", cp, err)
		}
	}
}

func (f *anchorFixture) verify() (BucketAnchorReport, error) {
	f.t.Helper()
	return VerifyAnchorsAgainstBucket(context.Background(), f.chain, f.file, f.bucket)
}

func findingKinds(fs []BucketAnchorFinding) []BucketFindingKind {
	var out []BucketFindingKind
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}

func hasFinding(fs []BucketAnchorFinding, kind BucketFindingKind, checkpoint int64) bool {
	for _, f := range fs {
		if f.Kind == kind && f.Checkpoint == checkpoint {
			return true
		}
	}
	return false
}

func TestVerifyAnchorsAgainstBucket_CleanIsOK(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10, 20, 30)

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.OK() || len(r.Warnings) != 0 {
		t.Fatalf("want clean report, got failures=%v warnings=%v", r.Failures, r.Warnings)
	}
	if r.LatestCheckpoint != 30 || r.CheckedCheckpoints != 3 {
		t.Fatalf("LatestCheckpoint/CheckedCheckpoints = %d/%d, want 30/3", r.LatestCheckpoint, r.CheckedCheckpoints)
	}
}

func TestVerifyAnchorsAgainstBucket_DetectsTamperedLocalFile(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10, 20, 30)

	// A host-root attacker rewrites the local file's root for checkpoint 20.
	data, err := os.ReadFile(f.filePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"root":"root-20"`, `"root":"forged"`, 1)
	if tampered == string(data) {
		t.Fatal("test setup: did not find the line to tamper with")
	}
	if err := os.WriteFile(f.filePath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK() || !hasFinding(r.Failures, FindingLocalRootDiffers, 20) {
		t.Fatalf("want FindingLocalRootDiffers at 20, got failures=%v", findingKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstBucket_BucketCheckpointMissingLocallyFails(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10, 30)
	// Checkpoint 20 exists in the bucket only (the local line was removed).
	if err := f.bucket.PublishRoot(context.Background(), 20, "root-20"); err != nil {
		t.Fatal(err)
	}

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK() || !hasFinding(r.Failures, FindingMissingLocally, 20) {
		t.Fatalf("want FindingMissingLocally at 20, got failures=%v", findingKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstBucket_LocalNewerThanBucketWarnsAndPasses(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10)
	// 20 reached the local file but its bucket upload failed (TeeSink retries
	// next tick); the bucket holds a subset of the file's checkpoints.
	if err := f.file.PublishRoot(context.Background(), 20, "root-20"); err != nil {
		t.Fatal(err)
	}

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.OK() {
		t.Fatalf("local-newer-than-bucket must not fail, got %v", findingKinds(r.Failures))
	}
	if !hasFinding(r.Warnings, FindingLocalNewerThanBucket, 20) {
		t.Fatalf("want FindingLocalNewerThanBucket warning at 20, got %v", findingKinds(r.Warnings))
	}
}

// The post-merge review of #2882: a host-root attacker can create (not
// delete) bucket objects, so a name like 09223372036854775807.json must not
// be trusted as "the latest anchor".
func TestVerifyAnchorsAgainstBucket_PlantedFarFutureCheckpointFails(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10, 20, 30)
	planted := f.bucket.objectURI(9223372036854775807)
	f.gcloud.objects[planted] = []byte(`{"checkpoint":9223372036854775807,"root":"planted","anchored_at":"2026-01-01T00:00:00Z"}` + "\n")

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK() || !hasFinding(r.Failures, FindingAboveChainTip, 9223372036854775807) {
		t.Fatalf("want FindingAboveChainTip at the planted checkpoint, got failures=%v", findingKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstBucket_PlantedCheckpointDoesNotHideRealTampering(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10, 20, 30)
	f.gcloud.objects[f.bucket.objectURI(9223372036854775807)] = []byte(`{"checkpoint":9223372036854775807,"root":"planted","anchored_at":"x"}` + "\n")
	// The database row at an anchored checkpoint was rewritten.
	f.chain.hashes[20] = "rewritten"

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasFinding(r.Failures, FindingDatabaseRootDiffers, 20) {
		t.Fatalf("the planted object hid the rewrite at 20: failures=%v", findingKinds(r.Failures))
	}
}

func TestVerifyAnchorsAgainstBucket_ContentNotMatchingNameFails(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"checkpoint in body differs from name", `{"checkpoint":5,"root":"root-5","anchored_at":"x"}` + "\n"},
		{"body is not a record", "not json\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnchorFixture(t, 30)
			f.anchor(10, 30)
			f.gcloud.objects[f.bucket.objectURI(20)] = []byte(tc.body)

			r, err := f.verify()
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if r.OK() || !hasFinding(r.Failures, FindingContentMismatch, 20) {
				t.Fatalf("want FindingContentMismatch at 20, got failures=%v", findingKinds(r.Failures))
			}
		})
	}
}

func TestVerifyAnchorsAgainstBucket_DatabaseRootMismatchFails(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeChainStore)
	}{
		{"row rewritten", func(c *fakeChainStore) { c.hashes[30] = "rewritten" }},
		{"row deleted", func(c *fakeChainStore) { delete(c.hashes, 30) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnchorFixture(t, 30)
			f.anchor(10, 20, 30)
			tc.setup(f.chain)

			r, err := f.verify()
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if r.OK() || !hasFinding(r.Failures, FindingDatabaseRootDiffers, 30) {
				t.Fatalf("want FindingDatabaseRootDiffers at 30, got failures=%v", findingKinds(r.Failures))
			}
		})
	}
}

func TestVerifyAnchorsAgainstBucket_RetentionLockWarnings(t *testing.T) {
	tests := []struct {
		name     string
		describe string
		wantWarn bool
	}{
		{"locked policy", lockedRetentionJSON, false},
		{"no policy", `{}`, true},
		{"policy not locked", `{"retention_policy": {"isLocked": false, "retentionPeriod": "60"}}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnchorFixture(t, 10)
			f.gcloud.retentionJSON = tc.describe
			f.anchor(10)

			r, err := f.verify()
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !r.OK() {
				t.Fatalf("an unlocked bucket is a warning, not a failure: %v", findingKinds(r.Failures))
			}
			if got := hasFinding(r.Warnings, FindingNoLockedRetention, 0); got != tc.wantWarn {
				t.Fatalf("retention warning = %v, want %v (warnings=%v)", got, tc.wantWarn, findingKinds(r.Warnings))
			}
		})
	}
}

func TestVerifyAnchorsAgainstBucket_UnrecognisedObjectWarns(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10)
	f.gcloud.objects[f.bucket.prefix+"notes.json"] = []byte("{}")

	r, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.OK() || !hasFinding(r.Warnings, FindingUnrecognisedObject, 0) {
		t.Fatalf("want OK with an unrecognised-object warning, got failures=%v warnings=%v", findingKinds(r.Failures), findingKinds(r.Warnings))
	}
}

func TestVerifyAnchorsAgainstBucket_NothingAnchoredAnywhere(t *testing.T) {
	f := newAnchorFixture(t, 0)

	_, err := f.verify()
	if !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("err = %v, want ErrNoAnchor", err)
	}
}

func TestVerifyAnchorsAgainstBucket_UnreachableBucketIsAnError(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10)
	f.gcloud.down = true

	if _, err := f.verify(); err == nil {
		t.Fatal("an unreachable bucket must be an error, never a clean pass")
	}
}

func TestVerifyAnchorsAgainstBucket_BucketLevelListErrorIsNotNeverAnchored(t *testing.T) {
	f := newAnchorFixture(t, 30)
	f.anchor(10)
	f.gcloud.lsErr = errors.New("exit status 1: ERROR: HTTPError 403: caller does not have storage.objects.list access")

	if _, err := f.verify(); err == nil || errors.Is(err, ErrNoAnchor) {
		t.Fatalf("a 403 on ls must be an error, got %v", err)
	}
}

func TestFileSinkCheckpoints_ReadsEveryValidLineAndSkipsDamagedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	body := `{"checkpoint":1,"root":"a","anchored_at":"x"}` + "\n" +
		`{"checkpoint":2,"root":"b","anchored_at":"x"}` + "\n" +
		`{"checkpoint":3,"ro`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Checkpoints()
	if err != nil {
		t.Fatalf("Checkpoints: %v", err)
	}
	if len(got) != 2 || got[0] != (AnchorCheckpoint{1, "a"}) || got[1] != (AnchorCheckpoint{2, "b"}) {
		t.Fatalf("Checkpoints = %+v", got)
	}
}
