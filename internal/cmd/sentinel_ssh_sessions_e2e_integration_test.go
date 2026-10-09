//go:build integration && !windows && !containarium_client

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/footprintai/containarium/internal/server"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2415 — the whole path, against a real Postgres: sink file -> shipper ->
// typed client -> REST gateway -> gRPC AuditService -> Store.LogBatch ->
// hash chain -> `containarium audit verify`. Auth is a stand-in interceptor
// that maps three bearer strings to a scoped, an unscoped and no principal;
// every other layer is the production code.

const (
	tokScoped   = "scoped-token"
	tokUnscoped = "unscoped-token"
)

type e2eStack struct {
	t       *testing.T
	pool    *pgxpool.Pool
	store   *audit.Store
	grpcAdr string
	restURL string
	dsn     string
}

func newE2EStack(t *testing.T) *e2eStack {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping: a skipped test and a passing one are indistinguishable.")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS audit_logs`); err != nil {
		t.Fatal(err)
	}
	store, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}

	authn := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		switch strings.Join(md.Get("authorization"), "") {
		case "Bearer " + tokScoped:
			ctx = auth.ContextWithTestSubjectScopes(ctx, "sentinel-shipper", []string{"service"}, []string{auth.ScopeAuditIngest})
			ctx = context.WithValue(ctx, auth.ContextKeyJTI, "jti-e2e")
		case "Bearer " + tokUnscoped:
			ctx = auth.ContextWithTestSubject(ctx, "old-admin", "admin")
		default:
			return nil, status.Error(codes.Unauthenticated, "no valid bearer token")
		}
		return h(ctx, req)
	}
	gs := grpc.NewServer(grpc.UnaryInterceptor(authn))
	pb.RegisterAuditServiceServer(gs, server.NewAuditServer(store))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	gctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	mux := runtime.NewServeMux()
	if err := pb.RegisterAuditServiceHandlerFromEndpoint(gctx, mux, lis.Addr().String(),
		[]grpc.DialOption{grpc.WithTransportCredentials(grpcinsecure.NewCredentials())}); err != nil {
		t.Fatal(err)
	}
	rest := httptest.NewServer(mux)
	t.Cleanup(rest.Close)

	// The audit CLI reads its DSN from here (direct Postgres, like production).
	t.Setenv("CONTAINARIUM_POSTGRES_URL", dsn)
	return &e2eStack{t: t, pool: pool, store: store, grpcAdr: lis.Addr().String(), restURL: rest.URL, dsn: dsn}
}

func (s *e2eStack) count(where string, args ...any) int {
	s.t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE `+where, args...).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s *e2eStack) verifyCLI() error {
	s.t.Helper()
	auditVerifyFromID, auditVerifyBatch = 0, 1000
	return runAuditVerify(nil, nil)
}

type e2eTokens map[string]string

func (m e2eTokens) TokenFor(b string) (string, bool, error) { t, ok := m[b]; return t, ok, nil }
func (m e2eTokens) Backends() ([]string, error) {
	var out []string
	for b := range m {
		out = append(out, b)
	}
	return out, nil
}

type e2eResolver map[string]string

func (m e2eResolver) BackendForLogin(l string) (string, bool) { b, ok := m[l]; return b, ok }

func (s *e2eStack) shipCfg(dir, token string) sshsession.ShipConfig {
	return sshsession.ShipConfig{
		RecordsFile:    filepath.Join(dir, "ssh-sessions.jsonl"),
		CheckpointFile: filepath.Join(dir, "ckpt", "checkpoint.json"),
		SentinelID:     "sentinel-e2e",
		Resolver:       e2eResolver{"alice": "be1", "bob": "be1"},
		Tokens:         e2eTokens{"be1": token},
		NewClient: func(_, tok string) (sshsession.IngestClient, error) {
			return client.NewHTTPClient(s.restURL, tok)
		},
		Rejected: client.IsIngestRejected,
		Logf:     func(f string, a ...any) { s.t.Logf(f, a...) },
	}
}

func e2eWrite(t *testing.T, path string, recs ...sshsession.Record) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, r := range recs {
		b, _ := json.Marshal(r)
		_, _ = f.Write(append(b, '\n'))
	}
}

func e2eRec(id string, ph sshsession.SessionPhase, login string, at time.Time) sshsession.Record {
	r := sshsession.Record{
		SessionID: id, Phase: ph, OccurredAt: at.Truncate(time.Microsecond), ClientIP: "203.0.113.20", ClientPort: 50000,
		Login: login, Target: "10.0.0.9:22", AuthMethod: sshsession.AuthMethodCertificate,
		Credential: sshsession.Credential{KeyID: "kid-" + login, Serial: 3, CAFingerprint: "SHA256:ca"},
	}
	if ph == sshsession.SessionPhaseClose {
		r.CloseReason = sshsession.CloseReasonNormal
	}
	return r
}

func fixture(base time.Time) []sshsession.Record {
	return []sshsession.Record{
		e2eRec("s1", sshsession.SessionPhaseOpen, "alice", base),
		e2eRec("s2", sshsession.SessionPhaseOpen, "bob", base.Add(time.Second)),
		e2eRec("s1", sshsession.SessionPhaseClose, "alice", base.Add(2*time.Second)),
		e2eRec("s3", sshsession.SessionPhaseOpen, "alice", base.Add(3*time.Second)),
		e2eRec("s2", sshsession.SessionPhaseClose, "bob", base.Add(4*time.Second)),
		e2eRec("s3", sshsession.SessionPhaseClose, "alice", base.Add(5*time.Second)),
	}
}

// Acceptance: ship a JSONL fixture; rows appear with typed actions and pass
// `audit verify`; re-running adds 0 ssh_session rows; a replay with the
// checkpoint lost is absorbed by the server's dedupe.
func TestE2E_SSHSessionShipVerifyAndRerun(t *testing.T) {
	s := newE2EStack(t)
	dir := t.TempDir()
	cfg := s.shipCfg(dir, tokScoped)
	e2eWrite(t, cfg.RecordsFile, fixture(time.Now().Add(-time.Hour))...)

	st, err := sshsession.ShipOnce(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Shipped != 6 || st.Duplicates != 0 {
		t.Fatalf("stats = %+v, want 6 shipped", st)
	}
	if got := s.count(`action = 'ssh_session_open'`); got != 3 {
		t.Fatalf("ssh_session_open rows = %d, want 3", got)
	}
	if got := s.count(`action = 'ssh_session_close'`); got != 3 {
		t.Fatalf("ssh_session_close rows = %d, want 3", got)
	}
	if err := s.verifyCLI(); err != nil {
		t.Fatalf("containarium audit verify on the shipped rows: %v", err)
	}

	// The audit query CLI finds them by typed action.
	auditQueryAction, auditQueryLimit = "ssh_session_open", 100
	t.Cleanup(func() { auditQueryAction, auditQueryLimit = "", 0 })
	if err := runAuditQuery(nil, nil); err != nil {
		t.Fatalf("containarium audit query: %v", err)
	}
	rows, _, err := s.store.Query(context.Background(), audit.QueryParams{Action: "ssh_session_open", Limit: 100})
	if err != nil || len(rows) != 3 {
		t.Fatalf("Query = %d rows, %v", len(rows), err)
	}
	for _, r := range rows {
		if r.ResourceType != "ssh_session" || r.TokenID != "jti-e2e" || r.SourceIP != "203.0.113.20" || r.StatusCode != 0 {
			t.Fatalf("row not mapped as designed: %+v", r)
		}
		var d server.SSHSessionDetail
		if err := json.Unmarshal([]byte(r.Detail), &d); err != nil || d.SentinelID != "sentinel-e2e" || d.KeyID == "" || d.Target != "10.0.0.9:22" {
			t.Fatalf("detail = %q (%v)", r.Detail, err)
		}
	}

	total := s.count(`resource_type = 'ssh_session'`)

	// Re-run: nothing past the checkpoint.
	if st, err = sshsession.ShipOnce(context.Background(), cfg); err != nil || st.Shipped != 0 {
		t.Fatalf("rerun: %+v, %v", st, err)
	}
	// Kill-and-lose-the-checkpoint: the whole file is re-sent and the server absorbs it.
	if err := os.RemoveAll(filepath.Dir(cfg.CheckpointFile)); err != nil {
		t.Fatal(err)
	}
	if st, err = sshsession.ShipOnce(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if st.Shipped != 0 || st.Duplicates != 6 {
		t.Fatalf("replay stats = %+v, want 0 shipped / 6 duplicates", st)
	}
	if got := s.count(`resource_type = 'ssh_session'`); got != total {
		t.Fatalf("ssh_session rows %d -> %d: a replay must add none", total, got)
	}
	if err := s.verifyCLI(); err != nil {
		t.Fatalf("chain after replay: %v", err)
	}
}

// The shipped rows are inside the tamper-evident chain: editing one is
// caught by `audit verify`. This is the claim #2415 exists to make true.
func TestE2E_TamperingWithAShippedRowIsDetected(t *testing.T) {
	s := newE2EStack(t)
	cfg := s.shipCfg(t.TempDir(), tokScoped)
	e2eWrite(t, cfg.RecordsFile, fixture(time.Now().Add(-time.Hour))...)
	if _, err := sshsession.ShipOnce(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyCLI(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE audit_logs SET source_ip = '198.51.100.99' WHERE action = 'ssh_session_open' AND resource_id = 's2'`); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyCLI(); err == nil {
		t.Fatal("audit verify must fail after a shipped row's source_ip is rewritten")
	}
}

// gRPC and REST are two transports of one contract: the same records
// produce byte-identical rows (including hashes) through either.
func TestE2E_GRPCAndRESTProduceIdenticalRows(t *testing.T) {
	s := newE2EStack(t)
	recs := fixture(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	req := &pb.IngestSSHSessionRecordsRequest{SentinelId: "sentinel-e2e"}
	for _, r := range recs {
		req.Records = append(req.Records, sshsession.ToProto(r))
	}

	snapshot := func() []string {
		rows, err := s.pool.Query(context.Background(),
			`SELECT id, timestamp, username, action, resource_type, resource_id, detail, source_ip, token_id, row_hash, prev_hash, coalesce(dedupe_key,'') FROM audit_logs ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			vals, _ := rows.Values()
			b, _ := json.Marshal(vals)
			out = append(out, string(b))
		}
		return out
	}
	reset := func() {
		if _, err := s.pool.Exec(context.Background(), `DROP TABLE audit_logs`); err != nil {
			t.Fatal(err)
		}
		st, err := audit.NewStore(context.Background(), s.pool)
		if err != nil {
			t.Fatal(err)
		}
		_ = st // the server holds s.store, which shares the pool and re-reads the table
	}

	hc, _ := client.NewHTTPClient(s.restURL, tokScoped)
	if _, err := hc.IngestSSHSessionRecords(context.Background(), req); err != nil {
		t.Fatalf("REST: %v", err)
	}
	viaREST := snapshot()

	reset()
	conn, err := grpc.NewClient(s.grpcAdr, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	gctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tokScoped)
	if _, err := pb.NewAuditServiceClient(conn).IngestSSHSessionRecords(gctx, req); err != nil {
		t.Fatalf("gRPC: %v", err)
	}
	viaGRPC := snapshot()

	if len(viaREST) != 6 || strings.Join(viaREST, "\n") != strings.Join(viaGRPC, "\n") {
		t.Fatalf("transports diverged:\nREST: %v\ngRPC: %v", viaREST, viaGRPC)
	}
}

// The ingest RPC refuses a token without the explicit scope — including a
// pre-scope admin token that RequireScope would have let through — and
// writes nothing.
func TestE2E_IngestRequiresTheExplicitScope(t *testing.T) {
	s := newE2EStack(t)
	for name, tok := range map[string]string{"unscoped admin token": tokUnscoped, "unknown token": "garbage"} {
		t.Run(name, func(t *testing.T) {
			cfg := s.shipCfg(t.TempDir(), tok)
			e2eWrite(t, cfg.RecordsFile, e2eRec("s1", sshsession.SessionPhaseOpen, "alice", time.Now()))
			_, err := sshsession.ShipOnce(context.Background(), cfg)
			if !errors.Is(err, sshsession.ErrBatchRejected) {
				t.Fatalf("err = %v, want ErrBatchRejected (4xx is never retried quietly)", err)
			}
			if got := s.count(`resource_type = 'ssh_session'`); got != 0 {
				t.Fatalf("a rejected batch wrote %d rows", got)
			}
		})
	}
}

// --reconcile: an orphan open gets an unknown_orphan close; the session's
// genuine close arriving later is still recorded; re-reconciling is a no-op.
func TestE2E_OrphanCloseThenLateGenuineClose(t *testing.T) {
	s := newE2EStack(t)
	cfg := s.shipCfg(t.TempDir(), tokScoped)
	cfg.OrphanAfter = 24 * time.Hour
	old := time.Now().Add(-72 * time.Hour)
	e2eWrite(t, cfg.RecordsFile, e2eRec("orphan", sshsession.SessionPhaseOpen, "alice", old))

	if _, err := sshsession.ShipOnce(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	st, err := sshsession.Reconcile(context.Background(), cfg)
	if err != nil || st.OrphansClosed != 1 {
		t.Fatalf("reconcile: %+v, %v", st, err)
	}
	if got := s.count(`action = 'ssh_session_close' AND resource_id = 'orphan' AND detail LIKE '%unknown_orphan%'`); got != 1 {
		t.Fatalf("orphan close rows = %d, want 1", got)
	}

	// Idempotent.
	if _, err := sshsession.Reconcile(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := s.count(`resource_id = 'orphan'`); got != 2 {
		t.Fatalf("rows for the session after a second reconcile = %d, want 2 (open + orphan close)", got)
	}

	// The real close finally lands in the sink.
	e2eWrite(t, cfg.RecordsFile, e2eRec("orphan", sshsession.SessionPhaseClose, "alice", old.Add(80*time.Hour)))
	if _, err := sshsession.ShipOnce(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := s.count(`resource_id = 'orphan'`); got != 3 {
		t.Fatalf("rows for the session = %d, want 3 (open, orphan close, genuine close)", got)
	}
	if err := s.verifyCLI(); err != nil {
		t.Fatal(err)
	}
}
