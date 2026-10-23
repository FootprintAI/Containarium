package audit

import (
	"context"
	"fmt"
)

// PurgeAnchor is the newest anchor a retention purge may stay below (#2878):
// the purge removes rows strictly under Checkpoint and keeps the anchored row,
// so verify-anchor can still compare it with the database afterwards.
type PurgeAnchor struct {
	Checkpoint int64
	Root       string
}

// SafeAnchor picks the anchor that bounds a purge. With only a local file it is
// the file's latest record. With an external sink as well it is the LOWER of the
// two latest checkpoints, so neither copy can be the one that lets rows go: an
// object planted above the real tip in a bucket raises only the bucket's
// "latest", and the file still holds the bound down; a bucket that is behind
// the file (an upload that has not succeeded yet) holds it down the same way.
//
// ok is false when nothing is anchored yet, or the external sink has nothing:
// without an anchor a purge could destroy the evidence a later rewrite would be
// caught by, so the caller must delete nothing. A sink failure is an error for
// the same reason, never "no anchor".
func SafeAnchor(ctx context.Context, file, external RootSink) (a PurgeAnchor, ok bool, err error) {
	cpF, rootF, okF, err := file.LastPublished(ctx)
	if err != nil {
		return PurgeAnchor{}, false, fmt.Errorf("audit: read the local anchor: %w", err)
	}
	if !okF {
		return PurgeAnchor{}, false, nil
	}
	if external == nil {
		return PurgeAnchor{Checkpoint: cpF, Root: rootF}, true, nil
	}
	cpE, rootE, okE, err := external.LastPublished(ctx)
	if err != nil {
		return PurgeAnchor{}, false, fmt.Errorf("audit: read the external anchor: %w", err)
	}
	if !okE {
		return PurgeAnchor{}, false, nil
	}
	switch {
	case cpE == cpF && rootE != rootF:
		return PurgeAnchor{}, false, fmt.Errorf("audit: the local file and the external anchor disagree at checkpoint %d", cpF)
	case cpE < cpF:
		return PurgeAnchor{Checkpoint: cpE, Root: rootE}, true, nil
	}
	return PurgeAnchor{Checkpoint: cpF, Root: rootF}, true, nil
}
