package sshsession

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The SSH session shipper (#2415): tails the JSONL sink the sshpiperd plugin
// writes and ships each record to the audit chain of the backend the session
// was routed to, through AuditService.IngestSSHSessionRecords. See
// docs/architecture/sentinel-ssh-session-audit-ingest.md.

const (
	// DefaultBatchSize caps records per ingest call (the server's own cap).
	DefaultBatchSize = 500
	// DefaultOrphanAfter is how long an "open" with no "close" is tolerated
	// before --reconcile calls it an orphan. It is a heuristic: a genuinely
	// long-lived session older than this is reported as an orphan too, and
	// its real close (if it ever arrives) is still recorded separately.
	DefaultOrphanAfter = 24 * time.Hour

	tokenExpiryWarnWithin = 14 * 24 * time.Hour
	tokenExpiryWarnEvery  = 24 * time.Hour

	backoffInitial = time.Second
	backoffMax     = time.Minute
)

// ErrBatchRejected marks a batch the backend refused as invalid or
// unauthorized (4xx-class). Resending the same batch fails the same way, so
// the checkpoint does not advance and the error is loud, not retried-quietly.
var ErrBatchRejected = errors.New("backend rejected the batch")

// IngestClient is the slice of the typed client the shipper needs. Both
// internal/client transports satisfy it.
type IngestClient interface {
	IngestSSHSessionRecords(ctx context.Context, req *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error)
}

// BackendResolver maps a record's login to the backend id it was routed to.
// *sentinel.KeyStore satisfies it.
type BackendResolver interface {
	BackendForLogin(login string) (backendID string, ok bool)
}

// TokenSource returns a backend's registered audit-ingest token. It is
// consulted on every pass, so a rotation takes effect without a restart.
type TokenSource interface {
	TokenFor(backendID string) (token string, ok bool, err error)
	// Backends lists every backend with a registered token, so near-expiry
	// warnings fire on every pass — including an idle one with nothing to
	// ship, which is exactly when a lapsing token would otherwise go unseen.
	Backends() ([]string, error)
}

// ClientFactory builds the ingest client for one backend and token.
type ClientFactory func(backendID, token string) (IngestClient, error)

// ShipConfig wires the shipper. Everything environment-specific is injected
// so the loop is testable with fakes and wrapped thinly by the CLI.
type ShipConfig struct {
	RecordsFile    string
	CheckpointFile string
	// RotatedFiles are where the previous sink may be found after a
	// rename-style rotation, newest first. Default: RecordsFile + ".1".
	RotatedFiles []string

	SentinelID string
	// BatchSize defaults to DefaultBatchSize.
	BatchSize int
	// DefaultBackend receives records whose login routes nowhere (e.g. the
	// user was deleted before the record shipped). Empty means such records
	// are skipped and counted.
	DefaultBackend string

	Resolver  BackendResolver
	Tokens    TokenSource
	NewClient ClientFactory
	// Rejected classifies a client error as a non-retryable rejection.
	// Nil treats every error as retryable.
	Rejected func(error) bool

	// OrphanAfter is Reconcile's threshold; it must be positive.
	OrphanAfter time.Duration

	// Test seams; production leaves them nil.
	Now   func() time.Time
	Logf  func(format string, args ...any)
	Sleep func(ctx context.Context, d time.Duration) error
}

func (c *ShipConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *ShipConfig) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c *ShipConfig) batchSize() int {
	if c.BatchSize > 0 {
		return c.BatchSize
	}
	return DefaultBatchSize
}

func (c *ShipConfig) rotatedFiles() []string {
	if len(c.RotatedFiles) > 0 {
		return c.RotatedFiles
	}
	return []string{c.RecordsFile + ".1"}
}

// ShipStats counts what a pass did. Skips are counted, never silent.
type ShipStats struct {
	Shipped            int // records accepted as new rows
	Duplicates         int // records the backend already had
	SkippedUnroutable  int // login routes to no backend and no default is set
	SkippedMalformed   int // line is not a valid record
	RotatedFileMissing int // the rotated file was gone; its unshipped tail is lost
	OrphansClosed      int // Reconcile: orphan closes sent
}

// ---- one backend's pending batch ------------------------------------------

type pendingRec struct {
	rec Record
	end int64 // byte offset just past this record's line
}

type backendRun struct {
	pending   []pendingRec
	confirmed int64 // offset after the last record confirmed shipped
	failed    bool
	err       error
	client    IngestClient
}

// sender ships batches to backends for the duration of one pass, caching
// each backend's client and recording failures without aborting the others.
type sender struct {
	cfg  *ShipConfig
	runs map[string]*backendRun
	st   *ShipStats
	ctx  context.Context
}

func newSender(ctx context.Context, cfg *ShipConfig, st *ShipStats) *sender {
	return &sender{cfg: cfg, runs: map[string]*backendRun{}, st: st, ctx: ctx}
}

func (s *sender) run(backend string, startOffset int64) *backendRun {
	r, ok := s.runs[backend]
	if !ok {
		r = &backendRun{confirmed: startOffset}
		s.runs[backend] = r
	}
	return r
}

// clientFor resolves the backend's token and client once per pass. A backend
// with no registered token is a FAILURE, not a skip: its records stay
// unshipped (the checkpoint holds) and ship once the operator registers the
// token. Skipping past them would lose audit records on first deploy.
func (s *sender) clientFor(backend string, r *backendRun) error {
	if r.client != nil {
		return nil
	}
	tok, ok, err := s.cfg.Tokens.TokenFor(backend)
	if err != nil {
		return fmt.Errorf("backend %q: read audit-ingest token: %w", backend, err)
	}
	if !ok || tok == "" {
		return fmt.Errorf("backend %q: no audit-ingest token registered (run: containarium sentinel register-token --kind audit-ingest --backend %s ...)", backend, backend)
	}
	c, err := s.cfg.NewClient(backend, tok)
	if err != nil {
		return fmt.Errorf("backend %q: build ingest client: %w", backend, err)
	}
	r.client = c
	return nil
}

// warnTokensNearExpiry logs, at most once a day per backend, that a
// registered token is about to lapse (or has). The bookkeeping lives in the
// checkpoint so it survives a restart.
func warnTokensNearExpiry(cfg *ShipConfig, ck *Checkpoint) {
	if cfg.Tokens == nil {
		return
	}
	backends, err := cfg.Tokens.Backends()
	if err != nil {
		cfg.logf("WARNING: list audit-ingest tokens: %v", err)
		return
	}
	now := cfg.now()
	for _, backend := range backends {
		tok, ok, err := cfg.Tokens.TokenFor(backend)
		if err != nil || !ok {
			continue
		}
		exp, ok := TokenExpiry(tok)
		if !ok {
			continue
		}
		left := exp.Sub(now)
		if left > tokenExpiryWarnWithin {
			continue
		}
		if last, seen := ck.ExpiryWarned[backend]; seen && now.Sub(time.Unix(last, 0)) < tokenExpiryWarnEvery {
			continue
		}
		if ck.ExpiryWarned == nil {
			ck.ExpiryWarned = map[string]int64{}
		}
		ck.ExpiryWarned[backend] = now.Unix()
		if left <= 0 {
			cfg.logf("WARNING: audit-ingest token for backend %q expired at %s — rotate it (register-token --kind audit-ingest)", backend, exp.Format(time.RFC3339))
		} else {
			cfg.logf("WARNING: audit-ingest token for backend %q expires %s (%d days left) — rotate it (register-token --kind audit-ingest)", backend, exp.Format(time.RFC3339), int(left.Hours()/24))
		}
	}
}

// flush sends backend's pending batch. On success it advances the backend's
// confirmed offset; on any failure it marks the backend failed and leaves
// the offset where it was.
func (s *sender) flush(backend string, r *backendRun) {
	if r.failed || len(r.pending) == 0 {
		return
	}
	if err := s.clientFor(backend, r); err != nil {
		r.failed, r.err = true, err
		return
	}
	req := &pb.IngestSSHSessionRecordsRequest{SentinelId: s.cfg.SentinelID, Records: make([]*pb.SSHSessionRecord, len(r.pending))}
	for i, p := range r.pending {
		req.Records[i] = ToProto(p.rec)
	}
	resp, err := r.client.IngestSSHSessionRecords(s.ctx, req)
	if err != nil {
		if s.cfg.Rejected != nil && s.cfg.Rejected(err) {
			err = fmt.Errorf("backend %q: %w: %w", backend, ErrBatchRejected, err)
		} else {
			err = fmt.Errorf("backend %q: %w", backend, err)
		}
		r.failed, r.err = true, err
		return
	}
	if len(resp.GetOutcomes()) != len(req.Records) {
		r.failed, r.err = true, fmt.Errorf("backend %q: sent %d records, got %d outcomes", backend, len(req.Records), len(resp.GetOutcomes()))
		return
	}
	s.st.Shipped += int(resp.GetInserted())
	s.st.Duplicates += int(resp.GetDuplicates())
	r.confirmed = r.pending[len(r.pending)-1].end
	r.pending = r.pending[:0]
}

func (s *sender) add(backend string, r *backendRun, p pendingRec) {
	if r.failed {
		return
	}
	r.pending = append(r.pending, p)
	if len(r.pending) >= s.cfg.batchSize() {
		s.flush(backend, r)
	}
}

func (s *sender) flushAll() {
	for b, r := range s.runs {
		s.flush(b, r)
	}
}

func (s *sender) errs() error {
	var out []error
	names := make([]string, 0, len(s.runs))
	for b := range s.runs {
		names = append(names, b)
	}
	sort.Strings(names)
	for _, b := range names {
		if r := s.runs[b]; r.failed {
			out = append(out, r.err)
		}
	}
	return errors.Join(out...)
}

// resolve picks the backend for rec's login.
func (c *ShipConfig) resolve(rec Record) (string, bool) {
	if c.Resolver != nil {
		if b, ok := c.Resolver.BackendForLogin(rec.Login); ok {
			return b, true
		}
	}
	if c.DefaultBackend != "" {
		return c.DefaultBackend, true
	}
	return "", false
}

// parseLine decodes one JSONL line into a validated Record. Validation is
// the server's own (FromProto), so a record that would be rejected is caught
// here, counted, and skipped instead of poisoning a whole batch.
func parseLine(line []byte) (Record, error) {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return Record{}, err
	}
	if _, err := FromProto(ToProto(rec)); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// ---- ShipOnce ---------------------------------------------------------------

// ShipOnce runs a single pass: ship everything past the checkpoint to its
// backends, then persist the checkpoint. It returns the stats and, if any
// backend could not be fully shipped, a joined error — the other backends
// still advanced.
func ShipOnce(ctx context.Context, cfg ShipConfig) (ShipStats, error) {
	var st ShipStats
	ck, err := LoadCheckpoint(cfg.CheckpointFile)
	if err != nil {
		return st, err
	}
	warnTokensNearExpiry(&cfg, ck)
	fi, err := os.Stat(cfg.RecordsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if saveErr := SaveCheckpoint(cfg.CheckpointFile, ck); saveErr != nil {
				return st, saveErr
			}
			return st, nil // nothing has been recorded yet
		}
		return st, fmt.Errorf("stat %s: %w", cfg.RecordsFile, err)
	}
	ino, haveIno := inodeOf(fi)
	head := firstLineHash(cfg.RecordsFile)

	// The path holds a different file than the checkpoint describes when its
	// inode changed (rename rotation) OR its first line did (the inode was
	// reused, or the file was rewritten in place). The inode alone is not
	// enough: a delete-and-recreate can hand the new file the old number.
	replaced := (haveIno && ck.Inode != 0 && ck.Inode != ino) ||
		(ck.Head != "" && head != "" && head != ck.Head)

	switch {
	case ck.Inode == 0:
		ck.Inode = ino
	case replaced:
		// The file was rotated away. Finish the old file's tail first.
		if old := findByInode(cfg.rotatedFiles(), ck.Inode); old != "" {
			passErr := shipFile(ctx, &cfg, old, ck, &st)
			if saveErr := SaveCheckpoint(cfg.CheckpointFile, ck); saveErr != nil {
				return st, errors.Join(passErr, saveErr)
			}
			if passErr != nil {
				return st, passErr // retry the old tail before touching the new file
			}
		} else {
			st.RotatedFileMissing++
			cfg.logf("WARNING: %s was replaced (rotated, deleted or rewritten) but the previous file (inode %d) is not at %v — records written after the last pass may be unshipped",
				cfg.RecordsFile, ck.Inode, cfg.rotatedFiles())
		}
		warned := ck.ExpiryWarned
		*ck = Checkpoint{Inode: ino, Head: head, ExpiryWarned: warned}
	}

	passErr := shipFile(ctx, &cfg, cfg.RecordsFile, ck, &st)
	if ck.Head == "" {
		// The first line may only have become complete during this pass.
		ck.Head = firstLineHash(cfg.RecordsFile)
	}
	if saveErr := SaveCheckpoint(cfg.CheckpointFile, ck); saveErr != nil {
		return st, errors.Join(passErr, saveErr)
	}
	return st, passErr
}

// firstLineHash fingerprints the file's first complete line, or returns ""
// if there is none yet (empty file, or the first record is still being
// written) or the file cannot be read. Bounded to 64KiB: a session record is
// a few hundred bytes.
func firstLineHash(path string) string {
	f, err := os.Open(path) // #nosec G304 -- operator-configured sink path
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return ""
	}
	i := bytes.IndexByte(buf, '\n')
	if i < 0 {
		return ""
	}
	sum := sha256.Sum256(buf[:i])
	return hex.EncodeToString(sum[:])
}

func findByInode(candidates []string, want uint64) string {
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if ino, ok := inodeOf(fi); ok && ino == want {
			return p
		}
	}
	return ""
}

// shipFile scans path from ck.Base, ships every complete record not yet
// confirmed for its backend, and updates ck in place.
func shipFile(ctx context.Context, cfg *ShipConfig, path string, ck *Checkpoint, st *ShipStats) error {
	f, err := os.Open(path) // #nosec G304 -- operator-configured sink path
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if fi, err := f.Stat(); err == nil && fi.Size() < ck.Base {
		cfg.logf("WARNING: %s is smaller than the checkpoint (%d < %d): truncated in place; restarting from the beginning", path, fi.Size(), ck.Base)
		ck.Base, ck.Offsets = 0, nil
	}
	if _, err := f.Seek(ck.Base, io.SeekStart); err != nil {
		return fmt.Errorf("seek %s: %w", path, err)
	}

	sd := newSender(ctx, cfg, st)
	rd := bufio.NewReaderSize(f, 64*1024)
	pos := ck.Base
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, rerr := rd.ReadBytes('\n')
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
			// A final fragment without a newline is a record the plugin is
			// still writing: leave it for the next pass.
			break
		}
		end := pos + int64(len(raw))
		text := bytes.TrimSpace(raw)
		if len(text) == 0 {
			pos = end
			continue
		}
		rec, perr := parseLine(text)
		if perr != nil {
			st.SkippedMalformed++
			cfg.logf("WARNING: %s: skipping malformed record ending at byte %d: %v", path, end, perr)
			pos = end
			continue
		}
		backend, ok := cfg.resolve(rec)
		if !ok {
			st.SkippedUnroutable++
			cfg.logf("WARNING: %s: session %s login %q routes to no backend; skipping", path, rec.SessionID, rec.Login)
			pos = end
			continue
		}
		pos = end
		if end <= ck.offsetFor(backend) {
			continue // already confirmed shipped to this backend
		}
		r := sd.run(backend, ck.offsetFor(backend))
		sd.add(backend, r, pendingRec{rec: rec, end: end})
	}
	scanEnd := pos
	sd.flushAll()

	// New checkpoint: a backend that is not failed is caught up to scanEnd;
	// a failed one stays at its last confirmed offset. Base is the lowest
	// failed offset (or scanEnd if nothing failed), so the next pass rescans
	// only what some backend still needs.
	next := map[string]int64{}
	for b := range ck.Offsets {
		next[b] = scanEnd
	}
	base := scanEnd
	for b, r := range sd.runs {
		if r.failed {
			next[b] = r.confirmed
			if r.confirmed < base {
				base = r.confirmed
			}
		} else {
			next[b] = scanEnd
		}
	}
	ck.Base = base
	ck.Offsets = map[string]int64{}
	for b, o := range next {
		if o > base {
			ck.Offsets[b] = o
		}
	}
	if len(ck.Offsets) == 0 {
		ck.Offsets = nil
	}
	return sd.errs()
}

// ---- Reconcile --------------------------------------------------------------

// Reconcile finds sessions that have an "open" record but no "close" and are
// older than cfg.OrphanAfter — what a plugin hard-kill (kill -9, OOM) leaves
// behind — and ships a synthesized close with CloseReasonUnknownOrphan to the
// session's backend. It reads the rotated and current sinks (so an open and
// its close straddling a rotation are not mistaken for an orphan) and never
// rewrites either. It is independent of the checkpoint: re-running re-sends
// the same orphan records, which the backend deduplicates.
func Reconcile(ctx context.Context, cfg ShipConfig) (ShipStats, error) {
	var st ShipStats
	if cfg.OrphanAfter <= 0 {
		return st, errors.New("reconcile needs a positive orphan threshold: 0 would flag every live session")
	}

	var files []string
	for _, p := range cfg.rotatedFiles() {
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
			break
		}
	}
	files = append(files, cfg.RecordsFile)

	opens := map[string]Record{}
	var order []string
	closed := map[string]bool{}
	for _, p := range files {
		f, err := os.Open(p) // #nosec G304 -- operator-configured sink path
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return st, fmt.Errorf("open %s: %w", p, err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			text := strings.TrimSpace(sc.Text())
			if text == "" {
				continue
			}
			rec, perr := parseLine([]byte(text))
			if perr != nil {
				continue
			}
			switch rec.Phase {
			case SessionPhaseOpen:
				if _, dup := opens[rec.SessionID]; !dup {
					opens[rec.SessionID] = rec
					order = append(order, rec.SessionID)
				}
			case SessionPhaseClose:
				closed[rec.SessionID] = true
			}
		}
		scErr := sc.Err()
		_ = f.Close()
		if scErr != nil {
			return st, fmt.Errorf("read %s: %w", p, scErr)
		}
	}

	now := cfg.now()
	cutoff := now.Add(-cfg.OrphanAfter)
	var sendSt ShipStats
	sd := newSender(ctx, &cfg, &sendSt)
	orphans := 0
	for _, id := range order {
		open := opens[id]
		if closed[id] || open.OccurredAt.After(cutoff) {
			continue
		}
		backend, ok := cfg.resolve(open)
		if !ok {
			st.SkippedUnroutable++
			continue
		}
		cl := open
		cl.Phase = SessionPhaseClose
		cl.OccurredAt = now
		cl.CloseReason = CloseReasonUnknownOrphan
		sd.add(backend, sd.run(backend, 0), pendingRec{rec: cl})
		orphans++
	}
	sd.flushAll()
	if err := sd.errs(); err != nil {
		return st, err
	}
	st.OrphansClosed = orphans
	st.Duplicates = sendSt.Duplicates
	return st, nil
}

// ---- Ship loop ---------------------------------------------------------------

// Ship runs ShipOnce every interval until ctx is cancelled, backing off
// exponentially (1s to 1m, jittered) while passes fail and returning to the
// plain interval once one succeeds. It returns ctx's error.
func Ship(ctx context.Context, cfg ShipConfig, interval time.Duration) error {
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	backoff := backoffInitial
	for {
		_, err := ShipOnce(ctx, cfg)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		wait := interval
		if err != nil {
			cfg.logf("ssh-session shipper pass failed (retrying in ~%s): %v", backoff, err)
			wait = jitter(backoff)
			if backoff *= 2; backoff > backoffMax {
				backoff = backoffMax
			}
		} else {
			backoff = backoffInitial
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) // #nosec G404 -- retry jitter, not security
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- token expiry ---------------------------------------------------------------

// TokenExpiry reads a JWT's exp claim without verifying it (the shipper has
// no signing key and only wants to warn before the token lapses).
func TokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0).UTC(), true
}
