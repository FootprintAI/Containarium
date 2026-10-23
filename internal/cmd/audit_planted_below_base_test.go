//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
)

// #2980: after a retention purge (#2878) the database cannot contradict a
// bucket checkpoint below the chain base, so the command must still turn a
// planted one into a failure and a non-zero exit, not a quiet warning.

// purgedAnchorChain is a chain whose rows below the base are gone; the base
// row itself is served from the base, as audit.Store.RowHashAt does.
type purgedAnchorChain struct {
	*fakeAnchorChain
	base audit.ChainBase
}

func (p *purgedAnchorChain) ChainBase(context.Context) (audit.ChainBase, bool, error) {
	return p.base, true, nil
}

func newPurgedAnchorChain(maxID, baseID int64) *purgedAnchorChain {
	c := newAnchorTestChain(maxID)
	for id := range c.hashes {
		if id < baseID {
			delete(c.hashes, id)
		}
	}
	return &purgedAnchorChain{fakeAnchorChain: c, base: audit.ChainBase{ID: baseID, Hash: "root-15", RowsPurged: baseID}}
}

func TestVerifyAnchorBucket_PlantedCheckpointBelowTheChainBaseExitsNonZero(t *testing.T) {
	run := func(bucket *fakeAnchorBucket) (error, string, string) {
		var out, errOut bytes.Buffer
		err := verifyAnchorBucket(context.Background(), newPurgedAnchorChain(40, 15), newAnchorTestFile(t, 20, 30), "anchors.jsonl", bucket, &out, &errOut)
		return err, out.String(), errOut.String()
	}

	// Control: the same purged chain with an honest bucket exits zero, so the
	// failure below is caused by the planted checkpoint and nothing else.
	if err, _, stderr := run(bucketAt(20, 30)); err != nil {
		t.Fatalf("an honest bucket over a purged chain must exit zero: %v\n%s", err, stderr)
	}

	planted := bucketAt(20, 30)
	planted.cps = append(planted.cps, audit.BucketCheckpoint{Checkpoint: 3, Root: "forged-root"})
	err, stdout, stderr := run(planted)
	if err == nil {
		t.Fatalf("a checkpoint planted below the chain base exited zero:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("error = %v, want an anchor-check failure", err)
	}
	if !strings.Contains(stderr, "checkpoint id=3") {
		t.Errorf("stderr must name the planted checkpoint:\n%s", stderr)
	}
}
