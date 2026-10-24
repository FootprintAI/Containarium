package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
)

func TestRetentionAnchorFunc_FileOnlyUsesTheFilesLatestAnchor(t *testing.T) {
	file, err := audit.NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := retentionAnchorFunc(file, nil, "")
	if !ok {
		t.Fatal("no bucket configured must still give an anchor function")
	}
	if _, found, err := fn(context.Background()); err != nil || found {
		t.Fatalf("nothing anchored: found=%v err=%v, want not found", found, err)
	}
	if err := file.PublishRoot(context.Background(), 42, "r42"); err != nil {
		t.Fatal(err)
	}
	a, found, err := fn(context.Background())
	if err != nil || !found || a.Checkpoint != 42 || a.Root != "r42" {
		t.Fatalf("anchor = %+v found=%v err=%v, want 42/r42", a, found, err)
	}
}

// A configured bucket that could not be built must not silently downgrade the
// purge to the local file alone.
func TestRetentionAnchorFunc_AConfiguredButUnavailableBucketFailsClosed(t *testing.T) {
	file, err := audit.NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if fn, ok := retentionAnchorFunc(file, nil, "gs://example-bucket/anchors"); ok || fn != nil {
		t.Fatal("a configured bucket with no sink must give no anchor function")
	}
	if _, ok := retentionAnchorFunc(file, nil, "   "); !ok {
		t.Fatal("a blank bucket setting is no bucket")
	}
}
