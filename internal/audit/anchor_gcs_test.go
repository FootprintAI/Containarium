package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// #2560 slice A (#2880): an anchor sink outside the host — a GCS bucket
// with a locked retention policy — driven through the host's `gcloud`.
// Every test here runs against fakeGcloud, an in-memory bucket that
// understands exactly the gcloud invocations the sink makes. No real
// bucket is touched (decision Q18.5 on #2727).

// fakeGcloud is an in-memory stand-in for `gcloud storage`. objects maps a
// full gs:// object URI to its content. retentionJSON is what
// `buckets describe --format=json` prints. down makes every call fail the
// way an unreachable endpoint does.
type fakeGcloud struct {
	mu            sync.Mutex
	objects       map[string][]byte
	retentionJSON string
	down          bool
	calls         [][]string
}

func newFakeGcloud() *fakeGcloud {
	return &fakeGcloud{objects: map[string][]byte{}}
}

func (f *fakeGcloud) run(_ context.Context, stdin []byte, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	if f.down {
		return "", errors.New("exit status 1: ERROR: Could not connect to storage.googleapis.com")
	}
	if len(args) < 2 || args[0] != "storage" {
		return "", fmt.Errorf("fakeGcloud: unexpected args %v", args)
	}
	switch args[1] {
	case "cp":
		// storage cp --if-generation-match=0 - gs://...
		if len(args) != 5 || args[2] != "--if-generation-match=0" || args[3] != "-" {
			return "", fmt.Errorf("fakeGcloud: cp must be create-only from stdin, got %v", args)
		}
		uri := args[4]
		if _, exists := f.objects[uri]; exists {
			return "", errors.New("exit status 1: ERROR: HTTPError 412: At least one of the pre-conditions you specified did not hold.")
		}
		f.objects[uri] = append([]byte(nil), stdin...)
		return "", nil
	case "cat":
		body, ok := f.objects[args[2]]
		if !ok {
			return "", errors.New("exit status 1: ERROR: The following URLs matched no objects or files: " + args[2])
		}
		return string(body), nil
	case "ls":
		prefix := args[2]
		var out []string
		for uri := range f.objects {
			if strings.HasPrefix(uri, prefix) {
				out = append(out, uri)
			}
		}
		if len(out) == 0 {
			return "", errors.New("exit status 1: ERROR: One or more URLs matched no objects.")
		}
		sort.Strings(out)
		return strings.Join(out, "\n") + "\n", nil
	case "buckets":
		if len(args) >= 3 && args[2] == "describe" {
			return f.retentionJSON, nil
		}
	}
	return "", fmt.Errorf("fakeGcloud: unexpected args %v", args)
}

func (f *fakeGcloud) objectURIs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for uri := range f.objects {
		out = append(out, uri)
	}
	sort.Strings(out)
	return out
}

func newTestGCSSink(t *testing.T, g *fakeGcloud) *GCSAnchorSink {
	t.Helper()
	s, err := newGCSAnchorSink("gs://example-bucket/audit-anchors", g.run)
	if err != nil {
		t.Fatalf("newGCSAnchorSink: %v", err)
	}
	return s
}

func TestNewGCSAnchorSink_ValidatesURI(t *testing.T) {
	g := newFakeGcloud()
	tests := []struct {
		uri        string
		wantErr    bool
		wantBucket string
		wantPrefix string
	}{
		{uri: "gs://example-bucket", wantBucket: "example-bucket", wantPrefix: "gs://example-bucket/"},
		{uri: "gs://example-bucket/", wantBucket: "example-bucket", wantPrefix: "gs://example-bucket/"},
		{uri: "gs://example-bucket/a/b/", wantBucket: "example-bucket", wantPrefix: "gs://example-bucket/a/b/"},
		{uri: "", wantErr: true},
		{uri: "s3://example-bucket", wantErr: true},
		{uri: "gs://", wantErr: true},
		{uri: "gs:///prefix", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			s, err := newGCSAnchorSink(tc.uri, g.run)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("newGCSAnchorSink(%q) = nil error, want error", tc.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("newGCSAnchorSink(%q): %v", tc.uri, err)
			}
			if s.bucket != tc.wantBucket || s.prefix != tc.wantPrefix {
				t.Fatalf("bucket/prefix = %q/%q, want %q/%q", s.bucket, s.prefix, tc.wantBucket, tc.wantPrefix)
			}
		})
	}
}

func TestGCSAnchorSink_EmptyBucketNotPublished(t *testing.T) {
	s := newTestGCSSink(t, newFakeGcloud())
	_, _, ok, err := s.LastPublished(context.Background())
	if err != nil {
		t.Fatalf("LastPublished: %v", err)
	}
	if ok {
		t.Fatal("ok = true for a bucket that was never published to")
	}
}

func TestGCSAnchorSink_OneCreateOnlyObjectPerCheckpoint(t *testing.T) {
	g := newFakeGcloud()
	s := newTestGCSSink(t, g)
	ctx := context.Background()

	for _, cp := range []int64{9, 10, 125} {
		if err := s.PublishRoot(ctx, cp, fmt.Sprintf("hash-at-%d", cp)); err != nil {
			t.Fatalf("PublishRoot(%d): %v", cp, err)
		}
	}
	// An unrelated object under the prefix is ignored, not misparsed.
	g.objects["gs://example-bucket/audit-anchors/README.txt"] = []byte("hello")

	want := []string{
		"gs://example-bucket/audit-anchors/00000000000000000009.json",
		"gs://example-bucket/audit-anchors/00000000000000000010.json",
		"gs://example-bucket/audit-anchors/00000000000000000125.json",
		"gs://example-bucket/audit-anchors/README.txt",
	}
	if got := g.objectURIs(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("objects = %v, want %v", got, want)
	}

	var rec anchorRecord
	if err := json.Unmarshal(g.objects[want[1]], &rec); err != nil {
		t.Fatalf("object body is not an anchor record: %v", err)
	}
	if rec.Checkpoint != 10 || rec.Root != "hash-at-10" || rec.AnchoredAt == "" {
		t.Fatalf("object body = %+v, want checkpoint 10, root hash-at-10, anchored_at set", rec)
	}

	cp, root, ok, err := s.LastPublished(ctx)
	if err != nil {
		t.Fatalf("LastPublished: %v", err)
	}
	if !ok || cp != 125 || root != "hash-at-125" {
		t.Fatalf("LastPublished = (%d, %q, %v), want (125, hash-at-125, true)", cp, root, ok)
	}
}

func TestGCSAnchorSink_IdempotentRepublishAndConflict(t *testing.T) {
	g := newFakeGcloud()
	s := newTestGCSSink(t, g)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("republishing the same root must be a no-op, got %v", err)
	}
	err := s.PublishRoot(ctx, 10, "a-different-hash")
	if !errors.Is(err, ErrAnchorConflict) {
		t.Fatalf("conflicting root: err = %v, want ErrAnchorConflict", err)
	}
	// The original object was not replaced.
	_, root, _, _ := s.LastPublished(ctx)
	if root != "hash-at-10" {
		t.Fatalf("root after conflict = %q, want hash-at-10", root)
	}
}

func TestGCSAnchorSink_UnreachableIsAnError(t *testing.T) {
	g := newFakeGcloud()
	g.down = true
	s := newTestGCSSink(t, g)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err == nil {
		t.Fatal("PublishRoot against an unreachable bucket returned nil")
	}
	if _, _, _, err := s.LastPublished(ctx); err == nil {
		t.Fatal("LastPublished against an unreachable bucket returned nil — must not read as 'never anchored'")
	}
}

func TestGCSAnchorSink_CheckRetentionLock(t *testing.T) {
	tests := []struct {
		name       string
		describe   string
		down       bool
		wantErr    bool
		wantPolicy bool
		wantLocked bool
		wantPeriod string
		wantWarn   bool
	}{
		{
			name:       "locked",
			describe:   `{"name":"example-bucket","retention_policy":{"effectiveTime":"2026-01-01T00:00:00Z","isLocked":true,"retentionPeriod":"31536000"}}`,
			wantPolicy: true, wantLocked: true, wantPeriod: "31536000",
		},
		{
			name:       "policy set but not locked",
			describe:   `{"name":"example-bucket","retention_policy":{"retentionPeriod":"86400"}}`,
			wantPolicy: true, wantPeriod: "86400", wantWarn: true,
		},
		{
			name:     "no retention policy",
			describe: `{"name":"example-bucket"}`,
			wantWarn: true,
		},
		{
			name:       "camelCase top-level key",
			describe:   `{"retentionPolicy":{"isLocked":true,"retentionPeriod":"60"}}`,
			wantPolicy: true, wantLocked: true, wantPeriod: "60",
		},
		{name: "unreachable", down: true, wantErr: true, wantWarn: true},
		{name: "unparseable", describe: "not json", wantErr: true, wantWarn: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGcloud()
			g.retentionJSON = tc.describe
			g.down = tc.down
			s := newTestGCSSink(t, g)
			st, err := s.CheckRetentionLock(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if st.HasPolicy != tc.wantPolicy || st.Locked != tc.wantLocked || st.RetentionPeriod != tc.wantPeriod {
					t.Fatalf("status = %+v, want policy=%v locked=%v period=%q", st, tc.wantPolicy, tc.wantLocked, tc.wantPeriod)
				}
			}
			warn := RetentionLockWarning("gs://example-bucket/", st, err)
			if (warn != "") != tc.wantWarn {
				t.Fatalf("RetentionLockWarning = %q, want warning=%v", warn, tc.wantWarn)
			}
			if tc.wantWarn && !strings.Contains(warn, "NOT immutable") && !strings.Contains(warn, "could not check") {
				t.Fatalf("warning %q does not say the copy may not be immutable", warn)
			}
			if !tc.wantErr {
				last := g.calls[len(g.calls)-1]
				if strings.Join(last, " ") != "storage buckets describe gs://example-bucket --format=json" {
					t.Fatalf("describe call = %v", last)
				}
			}
		})
	}
}

// recordingSink logs each publish into a shared order slice so the tee's
// ordering is observable, and can be told to fail.
type recordingSink struct {
	name  string
	order *[]string
	fail  error
	inner RootSink
}

func (r *recordingSink) PublishRoot(ctx context.Context, cp int64, root string) error {
	*r.order = append(*r.order, fmt.Sprintf("%s:%d", r.name, cp))
	if r.fail != nil {
		return r.fail
	}
	return r.inner.PublishRoot(ctx, cp, root)
}

func (r *recordingSink) LastPublished(ctx context.Context) (int64, string, bool, error) {
	return r.inner.LastPublished(ctx)
}

func TestTeeSink_FileFirstThenBucket(t *testing.T) {
	var order []string
	file := &recordingSink{name: "file", order: &order, inner: tempSink(t)}
	bucket := &recordingSink{name: "bucket", order: &order, inner: newTestGCSSink(t, newFakeGcloud())}
	tee := NewTeeSink(file, bucket)
	if err := tee.PublishRoot(context.Background(), 10, "hash-at-10"); err != nil {
		t.Fatalf("PublishRoot: %v", err)
	}
	if strings.Join(order, ",") != "file:10,bucket:10" {
		t.Fatalf("publish order = %v, want file then bucket", order)
	}
}

func TestTeeSink_BucketFailureKeepsFileRecord(t *testing.T) {
	var order []string
	fileInner := tempSink(t)
	file := &recordingSink{name: "file", order: &order, inner: fileInner}
	bucket := &recordingSink{name: "bucket", order: &order, fail: errors.New("bucket unreachable"), inner: newTestGCSSink(t, newFakeGcloud())}
	tee := NewTeeSink(file, bucket)
	ctx := context.Background()

	err := tee.PublishRoot(ctx, 10, "hash-at-10")
	if err == nil || !strings.Contains(err.Error(), "bucket unreachable") {
		t.Fatalf("err = %v, want the bucket failure", err)
	}
	cp, root, ok, _ := fileInner.LastPublished(ctx)
	if !ok || cp != 10 || root != "hash-at-10" {
		t.Fatalf("file after bucket failure = (%d, %q, %v), want the record kept", cp, root, ok)
	}
	// LastPublished reports the local file, which is what verify-anchor
	// reads today.
	if cp, _, _, _ := tee.LastPublished(ctx); cp != 10 {
		t.Fatalf("tee.LastPublished checkpoint = %d, want 10 (the file)", cp)
	}
}

func TestTeeSink_FileFailureSkipsBucket(t *testing.T) {
	var order []string
	g := newFakeGcloud()
	file := &recordingSink{name: "file", order: &order, fail: errors.New("disk full"), inner: tempSink(t)}
	bucket := &recordingSink{name: "bucket", order: &order, inner: newTestGCSSink(t, g)}
	tee := NewTeeSink(file, bucket)
	if err := tee.PublishRoot(context.Background(), 10, "hash-at-10"); err == nil {
		t.Fatal("PublishRoot with a failing file returned nil")
	}
	if strings.Join(order, ",") != "file:10" || len(g.objectURIs()) != 0 {
		t.Fatalf("order = %v, objects = %v: the bucket must never hold a checkpoint the file does not", order, g.objectURIs())
	}
}

// What happens to a checkpoint whose bucket write failed: the manager does
// not advance, so the next tick publishes again — the file write is an
// idempotent no-op and the bucket gets the same checkpoint.
func TestAnchorManager_TeeRetriesBucketOnNextTick(t *testing.T) {
	g := newFakeGcloud()
	fileSink := tempSink(t)
	tee := NewTeeSink(fileSink, newTestGCSSink(t, g))
	store := &fakeChainStore{hashes: map[int64]string{10: "hash-at-10"}, maxID: 10}
	m := NewAnchorManager(store, tee, AnchorOptions{Interval: 1})
	ctx := context.Background()

	g.down = true
	m.tick(ctx)
	if cp, _, ok, _ := fileSink.LastPublished(ctx); !ok || cp != 10 {
		t.Fatalf("file not advanced while the bucket was down: (%d, %v)", cp, ok)
	}
	if len(g.objectURIs()) != 0 {
		t.Fatal("bucket has objects while down")
	}

	g.down = false
	m.tick(ctx)
	want := []string{"gs://example-bucket/audit-anchors/00000000000000000010.json"}
	if got := g.objectURIs(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("objects after recovery = %v, want %v", got, want)
	}
	if lines := splitNonEmptyLines(readFile(t, fileSink.path)); len(lines) != 1 {
		t.Fatalf("file has %d records after the retry, want 1 (republish is a no-op)", len(lines))
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestAnchorSinkFor(t *testing.T) {
	file := tempSink(t)
	g := newFakeGcloud()
	newBucket := func(uri string) (*GCSAnchorSink, error) { return newGCSAnchorSink(uri, g.run) }

	// No bucket configured: the file sink itself, exactly as before #2880.
	sink, bucket, err := AnchorSinkFor(file, "  ", newBucket)
	if err != nil || bucket != nil || sink != RootSink(file) {
		t.Fatalf("no bucket: got (%T, %v, %v), want the file sink alone", sink, bucket, err)
	}

	sink, bucket, err = AnchorSinkFor(file, "gs://example-bucket/audit-anchors", newBucket)
	if err != nil || bucket == nil {
		t.Fatalf("bucket configured: err = %v, bucket = %v", err, bucket)
	}
	if _, ok := sink.(*TeeSink); !ok {
		t.Fatalf("bucket configured: sink is %T, want *TeeSink", sink)
	}

	// A bad bucket config falls back to the file alone and says why.
	sink, bucket, err = AnchorSinkFor(file, "s3://not-gcs", newBucket)
	if err == nil || bucket != nil || sink != RootSink(file) {
		t.Fatalf("bad bucket: got (%T, %v, %v), want the file sink and an error", sink, bucket, err)
	}
}
