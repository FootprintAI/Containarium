//go:build !windows

package sshsession

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2415 — the SSH session shipper: tail the JSONL sink from a durable
// checkpoint and ship to each record's backend, advancing only after OK.

// ---- fakes ---------------------------------------------------------------

type fakeBackend struct {
	mu       sync.Mutex
	reqs     []*pb.IngestSSHSessionRecordsRequest
	failFrom int   // 1-based call number from which calls fail (0 = never)
	failErr  error // error returned for failing calls
	calls    int
	seen     map[string]bool // dedupe on session:phase:reason, like the server
}

func (f *fakeBackend) IngestSSHSessionRecords(_ context.Context, req *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failFrom > 0 && f.calls >= f.failFrom {
		return nil, f.failErr
	}
	f.reqs = append(f.reqs, req)
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	resp := &pb.IngestSSHSessionRecordsResponse{}
	for _, r := range req.Records {
		k := fmt.Sprintf("%s:%v:%v", r.SessionId, r.Phase, r.CloseReason)
		if f.seen[k] {
			resp.Outcomes = append(resp.Outcomes, pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE)
			resp.Duplicates++
		} else {
			f.seen[k] = true
			resp.Outcomes = append(resp.Outcomes, pb.IngestOutcome_INGEST_OUTCOME_INSERTED)
			resp.Inserted++
		}
	}
	return resp, nil
}

// shipped returns the session_id:phase of every record the backend received, in order.
func (f *fakeBackend) shipped() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, rq := range f.reqs {
		for _, r := range rq.Records {
			out = append(out, fmt.Sprintf("%s:%s", r.SessionId, strings.TrimPrefix(r.Phase.String(), "SSH_SESSION_PHASE_")))
		}
	}
	return out
}

type mapResolver map[string]string

func (m mapResolver) BackendForLogin(l string) (string, bool) { b, ok := m[l]; return b, ok }

type mapTokens map[string]string

func (m mapTokens) TokenFor(b string) (string, bool, error) { t, ok := m[b]; return t, ok, nil }
func (m mapTokens) Backends() ([]string, error) {
	var out []string
	for b := range m {
		out = append(out, b)
	}
	return out, nil
}

type harness struct {
	t        *testing.T
	dir      string
	cfg      ShipConfig
	backends map[string]*fakeBackend
	logs     []string
	now      time.Time
}

func newHarness(t *testing.T, logins map[string]string) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, backends: map[string]*fakeBackend{}, now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	tokens := mapTokens{}
	for _, b := range logins {
		h.backends[b] = &fakeBackend{}
		tokens[b] = "tok-" + b
	}
	h.cfg = ShipConfig{
		RecordsFile:    filepath.Join(dir, "ssh-sessions.jsonl"),
		CheckpointFile: filepath.Join(dir, "state", "checkpoint.json"),
		SentinelID:     "sentinel-test",
		BatchSize:      500,
		Resolver:       mapResolver(logins),
		Tokens:         tokens,
		NewClient: func(backendID, token string) (IngestClient, error) {
			if token != "tok-"+backendID {
				return nil, fmt.Errorf("wrong token %q for %s", token, backendID)
			}
			return h.backends[backendID], nil
		},
		Now:  func() time.Time { return h.now },
		Logf: func(f string, a ...any) { h.logs = append(h.logs, fmt.Sprintf(f, a...)) },
	}
	return h
}

func rec(id string, phase SessionPhase, login string, at time.Time) Record {
	r := Record{SessionID: id, Phase: phase, OccurredAt: at, ClientIP: "203.0.113.5", Login: login, AuthMethod: AuthMethodPublicKey,
		Credential: Credential{KeyFingerprint: "SHA256:k"}}
	if phase == SessionPhaseClose {
		r.CloseReason = CloseReasonNormal
	}
	return r
}

func (h *harness) append(path string, lines ...string) {
	h.t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l); err != nil {
			h.t.Fatal(err)
		}
	}
}

func line(t *testing.T, r Record) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func (h *harness) appendRecs(rs ...Record) {
	h.t.Helper()
	var ls []string
	for _, r := range rs {
		ls = append(ls, line(h.t, r))
	}
	h.append(h.cfg.RecordsFile, ls...)
}

func (h *harness) once() (ShipStats, error) {
	h.t.Helper()
	return ShipOnce(context.Background(), h.cfg)
}

func mustOnce(h *harness) ShipStats {
	h.t.Helper()
	st, err := h.once()
	if err != nil {
		h.t.Fatalf("ShipOnce: %v", err)
	}
	return st
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

// ---- tests ---------------------------------------------------------------

func TestShipOnce_ShipsEveryRecordThenNothingOnRerun(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1", "bob": "b1"})
	at := h.now.Add(-time.Hour)
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", at), rec("s2", SessionPhaseOpen, "bob", at), rec("s1", SessionPhaseClose, "alice", at))

	st := mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN", "s1:CLOSE"})
	if st.Shipped != 3 {
		t.Fatalf("stats.Shipped = %d, want 3", st.Shipped)
	}
	if h.backends["b1"].reqs[0].SentinelId != "sentinel-test" {
		t.Fatalf("sentinel_id = %q", h.backends["b1"].reqs[0].SentinelId)
	}

	callsBefore := h.backends["b1"].calls
	st = mustOnce(h)
	if h.backends["b1"].calls != callsBefore || st.Shipped != 0 {
		t.Fatalf("a rerun with no new records must send nothing (calls %d->%d, shipped %d)", callsBefore, h.backends["b1"].calls, st.Shipped)
	}
}

func TestShipOnce_OnlyNewRecordsAfterAppend(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	h.appendRecs(rec("s2", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN"})
}

func TestShipOnce_BatchesAreBoundedAndInOrder(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.cfg.BatchSize = 2
	for i := 0; i < 5; i++ {
		h.appendRecs(rec(fmt.Sprintf("s%d", i), SessionPhaseOpen, "alice", h.now))
	}
	mustOnce(h)
	b := h.backends["b1"]
	if len(b.reqs) != 3 || len(b.reqs[0].Records) != 2 || len(b.reqs[2].Records) != 1 {
		t.Fatalf("batch sizes wrong: %d requests", len(b.reqs))
	}
	eq(t, b.shipped(), []string{"s0:OPEN", "s1:OPEN", "s2:OPEN", "s3:OPEN", "s4:OPEN"})
}

// The checkpoint rule: advance only after OK. A failure mid-file leaves the
// offset after the last confirmed batch; the retry resends exactly the rest.
func TestShipOnce_FailureKeepsCheckpointAndRetryResumes(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.cfg.BatchSize = 2
	for i := 0; i < 5; i++ {
		h.appendRecs(rec(fmt.Sprintf("s%d", i), SessionPhaseOpen, "alice", h.now))
	}
	b := h.backends["b1"]
	b.failFrom, b.failErr = 2, errors.New("backend unavailable") // batch 1 OK, batch 2 fails

	if _, err := h.once(); err == nil {
		t.Fatal("a failed batch must surface as an error")
	}
	eq(t, b.shipped(), []string{"s0:OPEN", "s1:OPEN"})

	// "Restart": a brand-new call with the same files, backend healthy again.
	b.failFrom = 0
	mustOnce(h)
	eq(t, b.shipped(), []string{"s0:OPEN", "s1:OPEN", "s2:OPEN", "s3:OPEN", "s4:OPEN"})
}

func TestShipOnce_PartialTrailingLineWaitsForItsNewline(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	full := line(t, rec("s1", SessionPhaseOpen, "alice", h.now))
	next := line(t, rec("s2", SessionPhaseOpen, "alice", h.now))
	h.append(h.cfg.RecordsFile, full, next[:len(next)/2]) // plugin mid-write

	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN"})

	h.append(h.cfg.RecordsFile, next[len(next)/2:])
	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN"})
}

func TestShipOnce_BackendsAreIndependent(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1", "bob": "b2"})
	h.appendRecs(rec("a1", SessionPhaseOpen, "alice", h.now), rec("b1s", SessionPhaseOpen, "bob", h.now), rec("a2", SessionPhaseOpen, "alice", h.now))
	h.backends["b2"].failFrom, h.backends["b2"].failErr = 1, errors.New("down")

	if _, err := h.once(); err == nil {
		t.Fatal("expected an error from the failing backend")
	}
	eq(t, h.backends["b1"].shipped(), []string{"a1:OPEN", "a2:OPEN"})
	eq(t, h.backends["b2"].shipped(), nil)

	h.backends["b2"].failFrom = 0
	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"a1:OPEN", "a2:OPEN"}) // not resent
	eq(t, h.backends["b2"].shipped(), []string{"b1s:OPEN"})
}

func TestShipOnce_UnroutableLoginIsSkippedAndCounted_DefaultBackendCatchesIt(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "ghost", h.now), rec("s2", SessionPhaseOpen, "alice", h.now))
	st := mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s2:OPEN"})
	if st.SkippedUnroutable != 1 {
		t.Fatalf("SkippedUnroutable = %d, want 1", st.SkippedUnroutable)
	}

	h2 := newHarness(t, map[string]string{"alice": "b1"})
	h2.cfg.DefaultBackend = "b1"
	h2.appendRecs(rec("s1", SessionPhaseOpen, "ghost", h2.now))
	mustOnce(h2)
	eq(t, h2.backends["b1"].shipped(), []string{"s1:OPEN"})
}

// A backend with no registered token must NOT lose its records: nothing is
// skipped past, so they ship once the operator registers the token.
func TestShipOnce_MissingTokenBlocksThatBackendWithoutLoss(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1", "bob": "b2"})
	delete(h.cfg.Tokens.(mapTokens), "b2")
	h.appendRecs(rec("a1", SessionPhaseOpen, "alice", h.now), rec("b1s", SessionPhaseOpen, "bob", h.now))

	_, err := h.once()
	if err == nil || !strings.Contains(err.Error(), "b2") {
		t.Fatalf("want an error naming the backend with no token, got %v", err)
	}
	eq(t, h.backends["b1"].shipped(), []string{"a1:OPEN"})
	eq(t, h.backends["b2"].shipped(), nil)

	h.cfg.Tokens.(mapTokens)["b2"] = "tok-b2" // operator registers it
	mustOnce(h)
	eq(t, h.backends["b2"].shipped(), []string{"b1s:OPEN"})
}

func TestShipOnce_MalformedLineIsSkippedAndCounted(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.append(h.cfg.RecordsFile, "not json at all\n", "\n", `{"session_id":"x","phase":"weird","login":"alice"}`+"\n")
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	st := mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN"})
	if st.SkippedMalformed != 2 { // garbage + unknown phase; the blank line is not a record
		t.Fatalf("SkippedMalformed = %d, want 2", st.SkippedMalformed)
	}
}

// A 4xx-class rejection is a contract bug or a bad token: surface it, never
// advance past it.
func TestShipOnce_RejectedBatchIsFatalAndNotAdvanced(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	rejected := errors.New("403 forbidden")
	h.cfg.Rejected = func(err error) bool { return errors.Is(err, rejected) }
	h.backends["b1"].failFrom, h.backends["b1"].failErr = 1, rejected

	_, err := h.once()
	if err == nil || !errors.Is(err, ErrBatchRejected) {
		t.Fatalf("want ErrBatchRejected, got %v", err)
	}
	h.backends["b1"].failFrom = 0
	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN"})
}

func TestShipOnce_OutcomeCountMismatchIsAnError(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	h.cfg.NewClient = func(string, string) (IngestClient, error) { return shortClient{}, nil }
	if _, err := h.once(); err == nil {
		t.Fatal("a response with the wrong number of outcomes must not advance the checkpoint")
	}
}

type shortClient struct{}

func (shortClient) IngestSSHSessionRecords(context.Context, *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error) {
	return &pb.IngestSSHSessionRecordsResponse{}, nil
}

func TestShipOnce_CheckpointFileMode0600(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	info, err := os.Stat(h.cfg.CheckpointFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestShipOnce_MissingRecordsFileIsNotAnError(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	if _, err := h.once(); err != nil {
		t.Fatalf("no sink yet must be a quiet no-op, got %v", err)
	}
}

// ---- rotation ------------------------------------------------------------

func TestShipOnce_RotationShipsOldTailThenNewFile(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)

	// More records land in the old file after the last pass, then logrotate
	// renames it (create mode) and the plugin's new file starts fresh.
	h.appendRecs(rec("s2", SessionPhaseOpen, "alice", h.now))
	if err := os.Rename(h.cfg.RecordsFile, h.cfg.RecordsFile+".1"); err != nil {
		t.Fatal(err)
	}
	h.appendRecs(rec("s3", SessionPhaseOpen, "alice", h.now)) // new file

	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN", "s3:OPEN"})

	h.appendRecs(rec("s4", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN", "s3:OPEN", "s4:OPEN"})
}

func TestShipOnce_RotationWithOldFileGoneWarnsAndContinues(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	if err := os.Remove(h.cfg.RecordsFile); err != nil {
		t.Fatal(err)
	}
	h.appendRecs(rec("s2", SessionPhaseOpen, "alice", h.now))
	st := mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN"})
	if st.RotatedFileMissing != 1 {
		t.Fatalf("RotatedFileMissing = %d, want 1", st.RotatedFileMissing)
	}
	if !strings.Contains(strings.Join(h.logs, "\n"), "rotated") {
		t.Fatalf("expected a warning about the unreadable rotated file, logs: %v", h.logs)
	}
}

// A failure on the old file must not drop the checkpoint to the new one.
func TestShipOnce_RotationOldTailFailureIsRetried(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	h.appendRecs(rec("s2", SessionPhaseOpen, "alice", h.now))
	_ = os.Rename(h.cfg.RecordsFile, h.cfg.RecordsFile+".1")
	h.appendRecs(rec("s3", SessionPhaseOpen, "alice", h.now))

	b := h.backends["b1"]
	b.failFrom, b.failErr = b.calls+1, errors.New("down")
	if _, err := h.once(); err == nil {
		t.Fatal("expected failure")
	}
	b.failFrom = 0
	mustOnce(h)
	eq(t, b.shipped(), []string{"s1:OPEN", "s2:OPEN", "s3:OPEN"})
}

func TestShipOnce_TruncationResetsToStart(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now), rec("s2", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	if err := os.Truncate(h.cfg.RecordsFile, 0); err != nil { // same inode, shorter file
		t.Fatal(err)
	}
	h.appendRecs(rec("s3", SessionPhaseOpen, "alice", h.now))
	mustOnce(h)
	eq(t, h.backends["b1"].shipped(), []string{"s1:OPEN", "s2:OPEN", "s3:OPEN"})
}

// ---- reconcile -----------------------------------------------------------

func TestReconcile_OrphanOpenGetsUnknownOrphanClose(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.cfg.OrphanAfter = 24 * time.Hour
	old := h.now.Add(-48 * time.Hour)
	recent := h.now.Add(-time.Hour)
	h.appendRecs(
		rec("orphan", SessionPhaseOpen, "alice", old),
		rec("closed", SessionPhaseOpen, "alice", old),
		rec("closed", SessionPhaseClose, "alice", old.Add(time.Minute)),
		rec("young", SessionPhaseOpen, "alice", recent),
	)
	st, err := Reconcile(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.OrphansClosed != 1 {
		t.Fatalf("OrphansClosed = %d, want 1", st.OrphansClosed)
	}
	b := h.backends["b1"]
	if len(b.reqs) != 1 || len(b.reqs[0].Records) != 1 {
		t.Fatalf("want exactly one synthesized record, got %+v", b.reqs)
	}
	got := b.reqs[0].Records[0]
	if got.SessionId != "orphan" || got.Phase != pb.SSHSessionPhase_SSH_SESSION_PHASE_CLOSE ||
		got.CloseReason != pb.SSHCloseReason_SSH_CLOSE_REASON_UNKNOWN_ORPHAN || got.Login != "alice" {
		t.Fatalf("synthesized record wrong: %+v", got)
	}
	if !got.OccurredAt.AsTime().Equal(h.now) {
		t.Fatalf("orphan close occurred_at = %v, want the reconcile time %v", got.OccurredAt.AsTime(), h.now)
	}

	// Idempotent at the server (same dedupe identity); the source file is untouched.
	before, _ := os.ReadFile(h.cfg.RecordsFile)
	if _, err := Reconcile(context.Background(), h.cfg); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(h.cfg.RecordsFile)
	if string(before) != string(after) {
		t.Fatal("reconcile must never rewrite the source file")
	}
}

func TestReconcile_CloseInCurrentFileCoversOpenInRotatedFile(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.cfg.OrphanAfter = time.Hour
	old := h.now.Add(-48 * time.Hour)
	h.appendRecs(rec("long", SessionPhaseOpen, "alice", old))
	_ = os.Rename(h.cfg.RecordsFile, h.cfg.RecordsFile+".1")
	h.appendRecs(rec("long", SessionPhaseClose, "alice", h.now.Add(-time.Minute)))

	st, err := Reconcile(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.OrphansClosed != 0 {
		t.Fatalf("a session closed in the next file is not an orphan (OrphansClosed=%d)", st.OrphansClosed)
	}
}

func TestReconcile_RequiresPositiveThreshold(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	if _, err := Reconcile(context.Background(), h.cfg); err == nil {
		t.Fatal("OrphanAfter == 0 would flag every live session; Reconcile must refuse")
	}
}

// ---- loop ----------------------------------------------------------------

func TestShip_LoopsUntilCancelledAndBacksOffOnError(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))
	b := h.backends["b1"]
	b.failFrom, b.failErr = 1, errors.New("down")

	ctx, cancel := context.WithCancel(context.Background())
	var sleeps []time.Duration
	h.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		if len(sleeps) == 3 {
			b.failFrom = 0 // backend recovers
		}
		if len(sleeps) >= 5 {
			cancel()
		}
		return ctx.Err()
	}
	err := Ship(ctx, h.cfg, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ship returned %v, want context.Canceled", err)
	}
	eq(t, b.shipped(), []string{"s1:OPEN"})
	if len(sleeps) < 3 || sleeps[1] <= sleeps[0] || sleeps[2] <= sleeps[1] {
		t.Fatalf("error backoff must grow: %v", sleeps)
	}
	if last := sleeps[len(sleeps)-1]; last != 5*time.Second {
		t.Fatalf("after recovery the loop returns to the poll interval, got %v (all %v)", last, sleeps)
	}
}

// ---- token expiry --------------------------------------------------------

func jwtWithExp(exp int64) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256"}`) + "." + enc(fmt.Sprintf(`{"exp":%d}`, exp)) + ".sig"
}

func TestTokenExpiry(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	got, ok := TokenExpiry(jwtWithExp(exp.Unix()))
	if !ok || !got.Equal(exp) {
		t.Fatalf("TokenExpiry = %v,%v want %v", got, ok, exp)
	}
	for _, bad := range []string{"", "nodots", "a.b", "a.!!!.c", jwtWithExp(0)} {
		if _, ok := TokenExpiry(bad); ok {
			t.Errorf("TokenExpiry(%q) must report not-ok", bad)
		}
	}
}

func TestShipOnce_WarnsOncePerDayWhenTokenNearExpiry(t *testing.T) {
	h := newHarness(t, map[string]string{"alice": "b1"})
	soon := jwtWithExp(h.now.Add(10 * 24 * time.Hour).Unix())
	h.cfg.Tokens = mapTokens{"b1": soon}
	h.cfg.NewClient = func(string, string) (IngestClient, error) { return h.backends["b1"], nil }
	h.appendRecs(rec("s1", SessionPhaseOpen, "alice", h.now))

	warns := func() int {
		n := 0
		for _, l := range h.logs {
			if strings.Contains(l, "expires") {
				n++
			}
		}
		return n
	}
	mustOnce(h)
	mustOnce(h)
	if warns() != 1 {
		t.Fatalf("want one expiry warning within a day, got %d (%v)", warns(), h.logs)
	}
	h.now = h.now.Add(25 * time.Hour)
	mustOnce(h)
	if warns() != 2 {
		t.Fatalf("want a second warning after a day, got %d", warns())
	}
}
