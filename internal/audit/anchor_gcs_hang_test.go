package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #2912: the real gcloud runner must return within a bounded time of its
// deadline even when gcloud leaves a child holding the stdout/stderr pipes.

// hangingGcloud writes a stub `gcloud` that starts a background sleep (which
// inherits the pipes) and then waits on it, like a hung network helper.
func hangingGcloud(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gcloud")
	script := "#!/bin/sh\nsleep 20 &\nwait\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatalf("write stub gcloud: %v", err)
	}
	return bin
}

func TestRunGcloud_HungChildIsBoundedByDeadline(t *testing.T) {
	bin := hangingGcloud(t)
	start := time.Now()
	_, err := runGcloud(context.Background(), bin, 300*time.Millisecond, nil, "storage", "ls", "gs://example-bucket/")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("hung gcloud returned nil error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("runGcloud returned after %s, want within a bounded time of the 300ms deadline", elapsed)
	}
}

func TestRunGcloud_Success(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gcloud")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ncat\n"), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatal(err)
	}
	out, err := runGcloud(context.Background(), bin, 5*time.Second, []byte("hello"), "storage", "cat", "x")
	if err != nil || out != "hello" {
		t.Fatalf("got (%q, %v), want (hello, nil)", out, err)
	}
}

func TestRunGcloud_FailureCarriesStderr(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gcloud")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho boom >&2\nexit 3\n"), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatal(err)
	}
	_, err := runGcloud(context.Background(), bin, 5*time.Second, nil, "storage", "ls", "x")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want it to carry stderr text", err)
	}
}

// A hung bucket call must not stop the file sink from anchoring, and must not
// make AnchorManager.Stop block.
func TestAnchorManager_HungBucketDoesNotStallFileAnchoringOrStop(t *testing.T) {
	bin := hangingGcloud(t)
	bucket, err := newGCSAnchorSink("gs://example-bucket/audit-anchors", func(ctx context.Context, stdin []byte, args ...string) (string, error) {
		return runGcloud(ctx, bin, 300*time.Millisecond, stdin, args...)
	})
	if err != nil {
		t.Fatal(err)
	}
	fileSink := tempSink(t)
	store := &fakeChainStore{hashes: map[int64]string{10: "hash-at-10"}, maxID: 10}
	m := NewAnchorManager(store, NewTeeSink(fileSink, bucket), AnchorOptions{Interval: 20 * time.Millisecond})
	m.Start(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	for {
		if cp, _, ok, _ := fileSink.LastPublished(context.Background()); ok && cp == 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("file sink never anchored checkpoint 10 while the bucket call hung")
		}
		time.Sleep(10 * time.Millisecond)
	}

	stopped := make(chan struct{})
	go func() { m.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(8 * time.Second):
		t.Fatal("AnchorManager.Stop blocked on a hung bucket call")
	}
}
