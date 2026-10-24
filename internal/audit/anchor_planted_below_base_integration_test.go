//go:build integration

// Real-Postgres coverage for #2980: after a retention purge (#2878) the bucket
// comparison no longer checks the database for checkpoints below the chain
// base, so the only thing standing between a planted bucket object and a clean
// verify-anchor is the comparison with the local anchor file. These tests plant
// forged objects below the base, as an attacker holding the host's gcloud
// credentials could (the retention lock blocks overwrites and deletes, not new
// objects), and require verify-anchor to fail.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/audit/
package audit

import (
	"context"
	"testing"
)

// plantedFixture is a 40-row chain with real anchors at 5, 10, 20, 30 and 40 in
// both copies, purged up to a base of 15. Checkpoints 5 and 10 lose their rows.
func plantedFixture(t *testing.T) (*Store, *anchorFixture) {
	t.Helper()
	s := auditTestStore(t)
	logN(t, s, 40)
	f := newAnchorFixture(t, 0)
	publishReal(t, s, f, 5, 10, 20, 30, 40)
	simulatePurge(t, s, 15)
	return s, f
}

func TestPlantedBucketCheckpointBelowTheChainBase_NotInTheLocalFileFails(t *testing.T) {
	ctx := context.Background()
	s, f := plantedFixture(t)

	// Control: the legitimately purged chain passes, so the failure below is
	// caused by the planted object and by nothing else.
	r, err := VerifyAnchorsAgainstBucket(ctx, s, f.file, f.bucket)
	if err != nil || !r.OK() {
		t.Fatalf("a legitimately purged chain must pass before anything is planted: err=%v failures=%v", err, r.Failures)
	}

	// The attacker adds a well-formed object whose name matches its content, at
	// a checkpoint below the base that the daemon never anchored. The database
	// cannot contradict it (those rows are gone), so only the local file can.
	if err := f.bucket.PublishRoot(ctx, 3, "forged-root"); err != nil {
		t.Fatalf("plant: %v", err)
	}

	r, err = VerifyAnchorsAgainstBucket(ctx, s, f.file, f.bucket)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK() {
		t.Fatalf("a checkpoint planted below the chain base passed verify-anchor silently; warnings=%v", findingKinds(r.Warnings))
	}
	if !hasFinding(r.Failures, FindingMissingLocally, 3) {
		t.Fatalf("want a missing-locally failure at the planted checkpoint 3, got %v", findingKinds(r.Failures))
	}
}

func TestPlantedBucketCheckpointBelowTheChainBase_ForgedRootAtAnAnchoredCheckpointFails(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 40)
	f := newAnchorFixture(t, 0)

	// The attacker wins the race for checkpoint 5: the forged object is in the
	// bucket first, so the daemon's own create-only upload would get a 412 and
	// the bucket never holds the real root. The local file still gets it.
	if err := f.bucket.PublishRoot(ctx, 5, "forged-root"); err != nil {
		t.Fatalf("plant: %v", err)
	}
	h, found, err := s.RowHashAt(ctx, 5)
	if err != nil || !found {
		t.Fatalf("no row 5: found=%v err=%v", found, err)
	}
	if err := f.file.PublishRoot(ctx, 5, h); err != nil {
		t.Fatal(err)
	}
	publishReal(t, s, f, 10, 20, 30, 40)
	simulatePurge(t, s, 15) // checkpoint 5 is now below the base

	r, err := VerifyAnchorsAgainstBucket(ctx, s, f.file, f.bucket)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK() {
		t.Fatalf("a forged bucket root below the chain base passed verify-anchor silently; warnings=%v", findingKinds(r.Warnings))
	}
	if !hasFinding(r.Failures, FindingLocalRootDiffers, 5) {
		t.Fatalf("want a local-root-differs failure at checkpoint 5, got %v", findingKinds(r.Failures))
	}
}
