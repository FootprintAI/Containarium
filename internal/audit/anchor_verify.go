package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// #2560 slice B (#2881): check the database and the local anchor file against
// the bucket's copy of the anchors.
//
// Slice A's bucket is write-once, not write-only: the retention lock stops a
// delete or an overwrite, but anyone holding the host's gcloud credentials can
// still ADD objects. So "the bucket's latest anchor = the highest object name"
// is attacker-steerable (a planted 09223372036854775807.json hides the real
// tip). VerifyAnchorsAgainstBucket therefore never trusts a name: it examines
// every bucket checkpoint, and one above the database's highest row id, or
// whose content does not match its name, is a failure.

// AnchorCheckpoint is one (checkpoint, root) pair read from the local anchor
// file.
type AnchorCheckpoint struct {
	Checkpoint int64
	Root       string
}

// Checkpoints returns every record in the anchor file that parses, in file
// order. Like lastPublishedLocked, it skips a line that does not parse (the
// damaged tail an O_APPEND writer can leave after a crash). An absent file is
// no checkpoints, not an error.
func (f *FileSink) Checkpoints() ([]AnchorCheckpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: read anchor file: %w", err)
	}
	var out []AnchorCheckpoint
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec anchorRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, AnchorCheckpoint{Checkpoint: rec.Checkpoint, Root: rec.Root})
	}
	return out, nil
}

// BucketCheckpoint is one anchor object in the bucket. Checkpoint comes from
// the object's NAME; Root from its content. A non-empty Problem means the
// content does not agree with the name (not JSON, or it records another
// checkpoint) and Root must not be used.
type BucketCheckpoint struct {
	Checkpoint int64
	Root       string
	Problem    string
}

// ListCheckpoints reads every anchor object under the sink's prefix. Objects
// whose name is not a zero-padded checkpoint are returned by URI in
// unrecognised. Any gcloud failure, a 403 on the listing included, is an
// error: only gcloud's "matched no objects" means an empty bucket.
func (g *GCSAnchorSink) ListCheckpoints(ctx context.Context) (cps []BucketCheckpoint, unrecognised []string, err error) {
	out, err := g.run(ctx, nil, "storage", "ls", g.prefix)
	if err != nil {
		if isGcloudNoMatch(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("audit: list anchors under %s: %w", g.prefix, err)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, g.prefix) {
			continue
		}
		name, ok := strings.CutSuffix(path.Base(line), ".json")
		if !ok || len(name) != 20 {
			unrecognised = append(unrecognised, line)
			continue
		}
		cp, perr := strconv.ParseInt(name, 10, 64)
		if perr != nil || cp < 0 {
			unrecognised = append(unrecognised, line)
			continue
		}
		rec, problem, err := g.fetchRecord(ctx, g.objectURI(cp))
		if err != nil {
			return nil, nil, err
		}
		if problem != "" {
			cps = append(cps, BucketCheckpoint{Checkpoint: cp, Problem: problem})
			continue
		}
		cps = append(cps, BucketCheckpoint{Checkpoint: cp, Root: rec.Root})
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].Checkpoint < cps[j].Checkpoint })
	return cps, unrecognised, nil
}

// BucketFindingKind classifies one result of VerifyAnchorsAgainstBucket.
type BucketFindingKind int

const (
	FindingUnspecified BucketFindingKind = iota

	// Failures.

	// FindingLocalRootDiffers: a checkpoint is in both the bucket and the
	// local file with different roots.
	FindingLocalRootDiffers
	// FindingMissingLocally: the bucket has a checkpoint the local file lacks.
	// The daemon writes the file first, so this means a line was removed or
	// the object was planted.
	FindingMissingLocally
	// FindingAboveChainTip: a bucket checkpoint is above the database's
	// highest row id, which the daemon can never have anchored.
	FindingAboveChainTip
	// FindingContentMismatch: a bucket object's content is not a record for
	// its own name.
	FindingContentMismatch
	// FindingDatabaseRootDiffers: the database row at an anchored checkpoint
	// no longer hashes to the anchored root, or no longer exists.
	FindingDatabaseRootDiffers

	// Warnings.

	// FindingLocalNewerThanBucket: the local file has checkpoints past the
	// bucket's latest (an upload that has not succeeded yet).
	FindingLocalNewerThanBucket
	// FindingNoLockedRetention: the bucket's retention policy is missing,
	// unlocked, or could not be read, so the bucket copy is not immutable.
	FindingNoLockedRetention
	// FindingUnrecognisedObject: an object under the prefix is not named like
	// an anchor. Never counted as an anchor.
	FindingUnrecognisedObject
)

func (k BucketFindingKind) String() string {
	switch k {
	case FindingLocalRootDiffers:
		return "local-root-differs"
	case FindingMissingLocally:
		return "missing-locally"
	case FindingAboveChainTip:
		return "above-chain-tip"
	case FindingContentMismatch:
		return "content-mismatch"
	case FindingDatabaseRootDiffers:
		return "database-root-differs"
	case FindingLocalNewerThanBucket:
		return "local-newer-than-bucket"
	case FindingNoLockedRetention:
		return "no-locked-retention"
	case FindingUnrecognisedObject:
		return "unrecognised-object"
	}
	return "unspecified"
}

// BucketAnchorFinding is one failure or warning. Checkpoint is 0 when the
// finding is not about one checkpoint.
type BucketAnchorFinding struct {
	Kind       BucketFindingKind
	Checkpoint int64
	Detail     string
}

// BucketAnchorReport is the result of VerifyAnchorsAgainstBucket. Failures
// make verify-anchor exit non-zero; Warnings do not.
type BucketAnchorReport struct {
	Failures []BucketAnchorFinding
	Warnings []BucketAnchorFinding
	// CheckedCheckpoints counts the bucket checkpoints compared with the
	// database: well-formed ones at or below the database's highest row id.
	CheckedCheckpoints int
	// LatestCheckpoint and LatestRoot are the highest such checkpoint; 0 and
	// "" when there is none.
	LatestCheckpoint int64
	LatestRoot       string
}

// OK reports whether there are no failures.
func (r BucketAnchorReport) OK() bool { return len(r.Failures) == 0 }

// VerifyAnchorsAgainstBucket compares the bucket's anchors with the database
// and with the local anchor file:
//
//   - every well-formed bucket checkpoint at or below the database's highest
//     row id must match the database row hash and the local file's record;
//   - a bucket checkpoint above that row id, or whose content does not match
//     its name, is a failure, as is one missing from the local file;
//   - local checkpoints newer than the bucket's latest are a warning;
//   - a bucket without a locked retention policy is a warning.
//
// ErrNoAnchor means nothing is anchored locally or in the bucket. A gcloud
// failure is an error, never a clean result.
func VerifyAnchorsAgainstBucket(ctx context.Context, chain ChainStore, local *FileSink, bucket *GCSAnchorSink) (BucketAnchorReport, error) {
	var r BucketAnchorReport

	bucketCPs, unrecognised, err := bucket.ListCheckpoints(ctx)
	if err != nil {
		return r, err
	}
	localCPs, err := local.Checkpoints()
	if err != nil {
		return r, err
	}
	if len(bucketCPs) == 0 && len(localCPs) == 0 {
		return r, ErrNoAnchor
	}
	maxID, err := chain.MaxRowID(ctx)
	if err != nil {
		return r, fmt.Errorf("audit: max row id: %w", err)
	}

	localRoots := make(map[int64][]string, len(localCPs))
	var maxLocal int64
	for _, c := range localCPs {
		localRoots[c.Checkpoint] = append(localRoots[c.Checkpoint], c.Root)
		if c.Checkpoint > maxLocal {
			maxLocal = c.Checkpoint
		}
	}

	for _, uri := range unrecognised {
		r.Warnings = append(r.Warnings, BucketAnchorFinding{Kind: FindingUnrecognisedObject,
			Detail: fmt.Sprintf("%s is not named like an anchor and is ignored", uri)})
	}

	for _, b := range bucketCPs {
		switch {
		case b.Problem != "":
			r.Failures = append(r.Failures, BucketAnchorFinding{Kind: FindingContentMismatch, Checkpoint: b.Checkpoint, Detail: b.Problem})
			continue
		case b.Checkpoint > maxID:
			r.Failures = append(r.Failures, BucketAnchorFinding{Kind: FindingAboveChainTip, Checkpoint: b.Checkpoint,
				Detail: fmt.Sprintf("the bucket holds a checkpoint above the database's highest row id %d; the daemon cannot have anchored it", maxID)})
			continue
		}
		r.CheckedCheckpoints++
		if b.Checkpoint > r.LatestCheckpoint {
			r.LatestCheckpoint, r.LatestRoot = b.Checkpoint, b.Root
		}

		dbRoot, found, err := chain.RowHashAt(ctx, b.Checkpoint)
		if err != nil {
			return r, fmt.Errorf("audit: row hash at anchored checkpoint %d: %w", b.Checkpoint, err)
		}
		switch {
		case !found:
			r.Failures = append(r.Failures, BucketAnchorFinding{Kind: FindingDatabaseRootDiffers, Checkpoint: b.Checkpoint,
				Detail: "the anchored row no longer exists in the database"})
		case dbRoot != b.Root:
			r.Failures = append(r.Failures, BucketAnchorFinding{Kind: FindingDatabaseRootDiffers, Checkpoint: b.Checkpoint,
				Detail: "the database row's hash differs from the anchored root"})
		}

		roots := localRoots[b.Checkpoint]
		if len(roots) == 0 {
			r.Failures = append(r.Failures, BucketAnchorFinding{Kind: FindingMissingLocally, Checkpoint: b.Checkpoint,
				Detail: "the bucket holds this checkpoint but the local anchor file does not"})
			continue
		}
		for _, root := range roots {
			if root != b.Root {
				r.Failures = append(r.Failures, BucketAnchorFinding{Kind: FindingLocalRootDiffers, Checkpoint: b.Checkpoint,
					Detail: "the local anchor file records a different root than the bucket"})
				break
			}
		}
	}

	if maxLocal > r.LatestCheckpoint && !hasBucketCheckpointAtOrAbove(bucketCPs, maxLocal) {
		r.Warnings = append(r.Warnings, BucketAnchorFinding{Kind: FindingLocalNewerThanBucket, Checkpoint: maxLocal,
			Detail: fmt.Sprintf("the local file is ahead of the bucket (latest bucket checkpoint %d); the upload is retried on the next anchoring tick", r.LatestCheckpoint)})
	}

	st, lockErr := bucket.CheckRetentionLock(ctx)
	if msg := RetentionLockWarning(bucket.URI(), st, lockErr); msg != "" {
		r.Warnings = append(r.Warnings, BucketAnchorFinding{Kind: FindingNoLockedRetention, Detail: msg})
	}
	return r, nil
}

// hasBucketCheckpointAtOrAbove reports whether any bucket object, however
// malformed, is named at or above cp, so a planted object never turns
// "local is ahead" into a warning that hides its own failure.
func hasBucketCheckpointAtOrAbove(cps []BucketCheckpoint, cp int64) bool {
	for _, b := range cps {
		if b.Checkpoint >= cp {
			return true
		}
	}
	return false
}
