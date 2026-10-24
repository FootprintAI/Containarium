//go:build integration

// #2980: the purge bound is the LOWER of the local anchor file's and the
// external bucket's latest checkpoint (audit.SafeAnchor). The unit test
// TestSafeAnchor covers the function; these tests run a real purge through the
// sweeper with the anchor wired the way the daemon wires it, so choosing the
// higher of the two would delete rows an unvouched-for anchor says are safe.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/retention/pgstore/
package pgstore_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/retention/pgstore"
)

// anchorFromBothCopies wires the purge anchor like the daemon: SafeAnchor over
// a real local anchor file holding a real row hash at fileCP, and an external
// sink whose latest checkpoint is bucketCP with its real row hash.
func (e *chainEnv) anchorFromBothCopies(t *testing.T, fileCP, bucketCP int64) {
	t.Helper()
	file, err := audit.NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.PublishRoot(e.ctx, fileCP, mustHash(t, e, fileCP)); err != nil {
		t.Fatal(err)
	}
	external := fixed{bucketCP, mustHash(t, e, bucketCP)}
	e.source.SetAnchor(func(ctx context.Context) (pgstore.Anchor, bool, error) {
		a, ok, err := audit.SafeAnchor(ctx, file, external)
		return pgstore.Anchor{Checkpoint: a.Checkpoint, Root: a.Root}, ok, err
	})
}

func TestChain_ThePurgeStopsAtTheLowerOfTheFileAndBucketAnchors(t *testing.T) {
	// Every row is far past its window, so only the anchors stop the purge.
	var rows []chainRow
	for i := 0; i < 30; i++ {
		rows = append(rows, chainRow{"api_access", 400, ""})
	}
	tests := []struct {
		name             string
		fileCP, bucketCP int64
		wantMin          int64
	}{
		{"bucket behind the file (an upload not done yet)", 25, 12, 12},
		{"file behind the bucket (a planted object raised the bucket's latest)", 12, 25, 12},
		{"both copies at the same checkpoint", 20, 20, 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newChainEnv(t, rows)
			e.anchorFromBothCopies(t, tc.fileCP, tc.bucketCP)

			e.enforce(t)

			min, max, n := e.ids(t)
			if min != tc.wantMin || max != 30 || n != 30-tc.wantMin+1 {
				t.Fatalf("ids %d..%d (%d rows), want %d..30: the purge must stop below the LOWER anchor (file %d, bucket %d)",
					min, max, n, tc.wantMin, tc.fileCP, tc.bucketCP)
			}
			e.verify(t)
			base, ok, err := e.audit.ChainBase(e.ctx)
			if err != nil || !ok || base.ID != tc.wantMin-1 {
				t.Fatalf("chain base = %+v ok=%v err=%v, want id %d", base, ok, err, tc.wantMin-1)
			}
		})
	}
}
