package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"
)

// #2560 slice A (#2880): an anchor sink outside the host.
//
// FileSink (anchor.go) defends against a Postgres-privileged attacker but
// not a host-root one, who can edit both the database and the file.
// GCSAnchorSink writes each anchored (checkpoint, root) to a GCS bucket
// whose retention policy is LOCKED (Bucket Lock): once written, an object
// cannot be deleted or overwritten by anyone — host root and the bucket's
// own admins included — until its retention period ends. That copy is what
// slice B's `audit verify-anchor` checks the database and the local file
// against.
//
// Like pkg/core/backup/gcs.go, it shells out to the host's `gcloud storage`
// rather than pulling in a cloud SDK; credentials are whatever the host's
// gcloud is configured with. One object per checkpoint, uploaded with
// --if-generation-match=0, so even an UNLOCKED bucket never has an anchor
// silently overwritten by this daemon.

// gcloudRunFunc runs `gcloud <args...>` with stdin and returns stdout. A
// non-nil error carries gcloud's stderr text. A field on the sink so tests
// substitute an in-memory bucket.
type gcloudRunFunc func(ctx context.Context, stdin []byte, args ...string) (string, error)

// gcloudCallTimeout bounds one gcloud invocation, so a hung network call
// cannot stall the anchor loop past its next tick.
const gcloudCallTimeout = 60 * time.Second

// GCSAnchorSink is a RootSink backed by objects in a GCS bucket.
type GCSAnchorSink struct {
	bucket string // bucket name, without gs://
	prefix string // "gs://<bucket>/<prefix>/", always ending in "/"
	run    gcloudRunFunc
}

// NewGCSAnchorSink builds a sink for uri ("gs://<bucket>" or
// "gs://<bucket>/<prefix>"), locating `gcloud` on PATH. It makes no network
// call; CheckRetentionLock is the startup check.
func NewGCSAnchorSink(uri string) (*GCSAnchorSink, error) {
	bin, err := exec.LookPath("gcloud")
	if err != nil {
		return nil, fmt.Errorf("audit: gcloud not found on PATH (required for the GCS anchor sink): %w", err)
	}
	run := func(ctx context.Context, stdin []byte, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, gcloudCallTimeout)
		defer cancel()
		// #nosec G204 -- bin is resolved via exec.LookPath("gcloud"); args are
		// fixed verbs plus gs:// URIs built from a validated bucket URI. No
		// shell is involved.
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stdout.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	}
	return newGCSAnchorSink(uri, run)
}

func newGCSAnchorSink(uri string, run gcloudRunFunc) (*GCSAnchorSink, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(uri), "gs://")
	if !ok {
		return nil, fmt.Errorf("audit: anchor bucket must be a gs:// URI, got %q", uri)
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return nil, fmt.Errorf("audit: anchor bucket URI %q has no bucket name", uri)
	}
	p := "gs://" + bucket + "/"
	if prefix = strings.Trim(prefix, "/"); prefix != "" {
		p += prefix + "/"
	}
	return &GCSAnchorSink{bucket: bucket, prefix: p, run: run}, nil
}

// URI is the sink's location, for log lines.
func (g *GCSAnchorSink) URI() string { return g.prefix }

// objectURI zero-pads the checkpoint (int64 fits in 19 digits) so object
// names sort in checkpoint order.
func (g *GCSAnchorSink) objectURI(checkpoint int64) string {
	return fmt.Sprintf("%s%020d.json", g.prefix, checkpoint)
}

func (g *GCSAnchorSink) PublishRoot(ctx context.Context, checkpoint int64, root string) error {
	rec := anchorRecord{Checkpoint: checkpoint, Root: root, AnchoredAt: time.Now().UTC().Format(time.RFC3339Nano)}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal anchor record: %w", err)
	}
	uri := g.objectURI(checkpoint)
	_, err = g.run(ctx, append(body, '\n'), "storage", "cp", "--if-generation-match=0", "-", uri)
	if err == nil {
		return nil
	}
	if !isGcloudPreconditionFailed(err) {
		return fmt.Errorf("audit: upload anchor %s: %w", uri, err)
	}
	// The object already exists: same root is an idempotent republish,
	// a different one is a conflict (RootSink contract).
	existing, err := g.readRecord(ctx, uri)
	if err != nil {
		return err
	}
	if existing.Root == root {
		return nil
	}
	return fmt.Errorf("%w: checkpoint=%d (%s)", ErrAnchorConflict, checkpoint, uri)
}

// LastPublished lists the anchor objects and reads the highest checkpoint.
// An empty prefix is ok=false; any other gcloud failure is an error, never
// "never anchored".
func (g *GCSAnchorSink) LastPublished(ctx context.Context) (int64, string, bool, error) {
	out, err := g.run(ctx, nil, "storage", "ls", g.prefix)
	if err != nil {
		if isGcloudNoMatch(err) {
			return 0, "", false, nil
		}
		return 0, "", false, fmt.Errorf("audit: list anchors under %s: %w", g.prefix, err)
	}
	var best int64 = -1
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, g.prefix) {
			continue
		}
		name, ok := strings.CutSuffix(path.Base(line), ".json")
		if !ok || len(name) != 20 {
			continue
		}
		cp, err := strconv.ParseInt(name, 10, 64)
		if err != nil || cp <= best {
			continue
		}
		best = cp
	}
	if best < 0 {
		return 0, "", false, nil
	}
	rec, err := g.readRecord(ctx, g.objectURI(best))
	if err != nil {
		return 0, "", false, err
	}
	return rec.Checkpoint, rec.Root, true, nil
}

func (g *GCSAnchorSink) readRecord(ctx context.Context, uri string) (anchorRecord, error) {
	out, err := g.run(ctx, nil, "storage", "cat", uri)
	if err != nil {
		return anchorRecord{}, fmt.Errorf("audit: read anchor %s: %w", uri, err)
	}
	var rec anchorRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		return anchorRecord{}, fmt.Errorf("audit: anchor %s is not a valid record: %w", uri, err)
	}
	if want := g.objectURI(rec.Checkpoint); want != uri {
		return anchorRecord{}, fmt.Errorf("audit: anchor %s records checkpoint %d, which belongs at %s", uri, rec.Checkpoint, want)
	}
	return rec, nil
}

// RetentionLockStatus is what the bucket's retention policy says.
type RetentionLockStatus struct {
	HasPolicy       bool
	Locked          bool
	RetentionPeriod string // seconds, as gcloud prints it
}

type gcsRetentionPolicy struct {
	IsLocked        bool   `json:"isLocked"`
	RetentionPeriod string `json:"retentionPeriod"`
}

// gcsBucketDescribe is the slice of `gcloud storage buckets describe
// --format=json` we read. gcloud prints the top-level key snake_case; the
// camelCase spelling is accepted too in case a gcloud release changes it.
type gcsBucketDescribe struct {
	RetentionPolicy      *gcsRetentionPolicy `json:"retention_policy"`
	RetentionPolicyCamel *gcsRetentionPolicy `json:"retentionPolicy"`
}

// CheckRetentionLock reports whether the bucket's retention policy is
// locked — the property that makes the anchors immutable.
func (g *GCSAnchorSink) CheckRetentionLock(ctx context.Context) (RetentionLockStatus, error) {
	out, err := g.run(ctx, nil, "storage", "buckets", "describe", "gs://"+g.bucket, "--format=json")
	if err != nil {
		return RetentionLockStatus{}, fmt.Errorf("audit: describe bucket gs://%s: %w", g.bucket, err)
	}
	var d gcsBucketDescribe
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return RetentionLockStatus{}, fmt.Errorf("audit: parse bucket gs://%s description: %w", g.bucket, err)
	}
	p := d.RetentionPolicy
	if p == nil {
		p = d.RetentionPolicyCamel
	}
	if p == nil {
		return RetentionLockStatus{}, nil
	}
	return RetentionLockStatus{HasPolicy: true, Locked: p.IsLocked, RetentionPeriod: p.RetentionPeriod}, nil
}

// RetentionLockWarning turns a CheckRetentionLock result into the loud
// warning the daemon logs, or "" when the bucket is locked. Decision Q18.3
// on #2727: an unlocked bucket is still used, with this warning.
func RetentionLockWarning(uri string, st RetentionLockStatus, err error) string {
	switch {
	case err != nil:
		return fmt.Sprintf("WARNING: could not check the retention lock on %s: %v — the external anchor copy may NOT be immutable", uri, err)
	case !st.HasPolicy:
		return fmt.Sprintf("WARNING: %s has no retention policy — anchors are still published, but the external copy is NOT immutable: anyone with delete rights on the bucket can remove them", uri)
	case !st.Locked:
		return fmt.Sprintf("WARNING: %s has a retention policy (%ss) that is not locked — anchors are still published, but the external copy is NOT immutable until the policy is locked", uri, st.RetentionPeriod)
	}
	return ""
}

func isGcloudPreconditionFailed(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "412") || strings.Contains(s, "precondition") || strings.Contains(s, "pre-condition")
}

func isGcloudNoMatch(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "matched no objects") || strings.Contains(s, "no urls matched")
}

// AnchorSinkFor picks the daemon's anchor sink from its config. An empty
// bucketURI returns the file sink alone (behaviour before #2880). Otherwise
// it returns TeeSink(file, bucket) and the bucket sink, for the startup lock
// check. If the bucket sink cannot be built (bad URI, no gcloud on PATH),
// it returns the file sink alone plus the error, so the daemon keeps
// anchoring locally and logs why external anchoring is off.
func AnchorSinkFor(file *FileSink, bucketURI string, newBucket func(string) (*GCSAnchorSink, error)) (RootSink, *GCSAnchorSink, error) {
	if strings.TrimSpace(bucketURI) == "" {
		return file, nil, nil
	}
	bucket, err := newBucket(bucketURI)
	if err != nil {
		return file, nil, err
	}
	return NewTeeSink(file, bucket), bucket, nil
}

// TeeSink publishes to the local file first, then the external sink.
//
// Ordering: the external sink is written only after the file write
// succeeded, so the bucket never holds a checkpoint the local file lacks
// (slice B flags a bucket checkpoint missing locally as tampering). If the
// file write fails, the external write is skipped and the error returned.
//
// If the external write fails, the file record stays and the error is
// returned, so AnchorManager does not advance: the next tick publishes
// again — the file write is an idempotent no-op and the bucket upload is
// retried. If the chain has grown by then, the next tick anchors the newer
// checkpoint instead, and the failed one exists only in the local file
// (the bucket holds a subset of the file's checkpoints, never a superset).
type TeeSink struct {
	file     RootSink
	external RootSink
}

// NewTeeSink builds a TeeSink. Neither sink may be nil.
func NewTeeSink(file, external RootSink) *TeeSink {
	if file == nil || external == nil {
		panic("audit: nil sink passed to NewTeeSink")
	}
	return &TeeSink{file: file, external: external}
}

func (t *TeeSink) PublishRoot(ctx context.Context, checkpoint int64, root string) error {
	if err := t.file.PublishRoot(ctx, checkpoint, root); err != nil {
		return fmt.Errorf("local anchor file (external anchor skipped): %w", err)
	}
	if err := t.external.PublishRoot(ctx, checkpoint, root); err != nil {
		return fmt.Errorf("external anchor (local file has checkpoint %d; retried next tick): %w", checkpoint, err)
	}
	return nil
}

// LastPublished reports the local file's last anchor — what `audit
// verify-anchor` reads today. Checking against the external copy is slice B.
func (t *TeeSink) LastPublished(ctx context.Context) (int64, string, bool, error) {
	return t.file.LastPublished(ctx)
}
