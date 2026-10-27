package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/proofpack"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3064 — ProofPackService.VerifyProofPack. The digests are the real ones
// (proofpack.Seal/Verify); only the chain's storage is faked, as in
// internal/proofpack/seal_test.go. The Postgres-backed chain walk is covered
// by internal/proofpack/seal_integration_test.go.

type fakeSealChain struct {
	rows   map[int64]audit.ChainEntry
	next   int64
	base   audit.ChainBase
	purged bool
	bad    int64
}

func (f *fakeSealChain) Append(_ context.Context, e *audit.AuditEntry) (int64, error) {
	f.next++
	r := audit.ChainEntry{AuditEntry: *e, RowHash: fmt.Sprintf("hash-%d", f.next)}
	r.ID = f.next
	f.rows[f.next] = r
	return f.next, nil
}
func (f *fakeSealChain) ChainEntryAt(_ context.Context, id int64) (audit.ChainEntry, bool, error) {
	r, ok := f.rows[id]
	return r, ok, nil
}
func (f *fakeSealChain) ChainBase(context.Context) (audit.ChainBase, bool, error) {
	return f.base, f.purged, nil
}
func (f *fakeSealChain) MaxRowID(context.Context) (int64, error) { return f.next, nil }
func (f *fakeSealChain) VerifyChainSinceID(context.Context, int64, int) (int64, error) {
	return f.bad, nil
}

func proofStep(name, log string) *pb.ProofStep {
	return &pb.ProofStep{Name: name, Kind: pb.ProofPartKind_PROOF_PART_KIND_UNIT, Log: []byte(log),
		LogSha256: proofpack.LogDigest([]byte(log)), LogOriginalBytes: int64(len(log))}
}

func sealedFixture(t *testing.T) (*fakeSealChain, *pb.SealedProofPack) {
	t.Helper()
	chain := &fakeSealChain{rows: map[int64]audit.ChainEntry{}}
	pack := &pb.ProofPack{
		SchemaVersion: proofpack.SchemaVersion,
		Steps:         []*pb.ProofStep{proofStep("unit", "ok\n"), proofStep("lint", "0 issues\n")},
		Status:        pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED,
	}
	sealed, err := proofpack.Seal(context.Background(), chain, "tenant", "run-1", pack)
	if err != nil {
		t.Fatal(err)
	}
	// Two later rows so the tip is not the seal row.
	for i := 0; i < 2; i++ {
		_, _ = chain.Append(context.Background(), &audit.AuditEntry{Action: "x"})
	}
	return chain, sealed
}

func auditReadCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), "auditor", []string{"user"}, []string{auth.ScopeAuditRead})
}

func verify(t *testing.T, s *ProofPackServer, ctx context.Context, sealed *pb.SealedProofPack) *pb.VerifyProofPackResponse {
	t.Helper()
	resp, err := s.VerifyProofPack(ctx, &pb.VerifyProofPackRequest{Sealed: sealed})
	if err != nil {
		t.Fatalf("VerifyProofPack: %v", err)
	}
	return resp
}

func TestVerifyProofPack_OKReportsChainTip(t *testing.T) {
	chain, sealed := sealedFixture(t)
	resp := verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	if !resp.Ok || resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_OK {
		t.Fatalf("resp = %v", resp)
	}
	if resp.ChainTipId != 3 || resp.ChainTipHash != chain.rows[3].RowHash || resp.AuditRowId != sealed.Seal.AuditRowId || resp.StepsChecked != 2 {
		t.Errorf("tip/seal fields wrong: %v", resp)
	}
}

func TestVerifyProofPack_ChangedStepNamesThatStep(t *testing.T) {
	chain, sealed := sealedFixture(t)
	// The log and its digest are rewritten consistently: only the seal in
	// the chain can catch it.
	sealed.Pack.Steps[1].Log = []byte("FAIL\n")
	sealed.Pack.Steps[1].LogSha256 = proofpack.LogDigest(sealed.Pack.Steps[1].Log)
	resp := verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	if resp.Ok || resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_MISMATCH {
		t.Fatalf("resp = %v", resp)
	}
	m := resp.FirstMismatch
	if m == nil || m.Header || m.StepIndex != 1 || m.Name != "lint" || m.Reason == "" {
		t.Errorf("first_mismatch = %v, want step 1 lint", m)
	}
}

func TestVerifyProofPack_HeaderMismatch(t *testing.T) {
	chain, sealed := sealedFixture(t)
	sealed.Pack.GitCommit = strings.Repeat("f", 40)
	resp := verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	if resp.Ok || resp.FirstMismatch == nil || !resp.FirstMismatch.Header {
		t.Fatalf("resp = %v", resp)
	}
}

func TestVerifyProofPack_PurgedIsATypedState(t *testing.T) {
	chain, sealed := sealedFixture(t)
	delete(chain.rows, sealed.Seal.AuditRowId)
	chain.purged, chain.base = true, audit.ChainBase{ID: sealed.Seal.AuditRowId}
	resp := verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	if resp.Ok || resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_PURGED || resp.FirstMismatch != nil {
		t.Fatalf("resp = %v", resp)
	}
}

func TestVerifyProofPack_MissingSealRowIsNotPurged(t *testing.T) {
	chain, sealed := sealedFixture(t)
	delete(chain.rows, sealed.Seal.AuditRowId)
	resp := verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	if resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_NOT_FOUND {
		t.Fatalf("resp = %v", resp)
	}
}

func TestVerifyProofPack_BrokenChain(t *testing.T) {
	chain, sealed := sealedFixture(t)
	chain.bad = 3
	resp := verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	if resp.Ok || resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_CHAIN_BROKEN {
		t.Fatalf("resp = %v", resp)
	}
}

func TestVerifyProofPack_ScopeGate(t *testing.T) {
	chain, sealed := sealedFixture(t)
	s := NewProofPackServer(chain)
	sub := func(roles, scopes []string) context.Context {
		return auth.ContextWithTestSubjectScopes(context.Background(), "a", roles, scopes)
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no subject", context.Background(), codes.Unauthenticated},
		{"wrong scope", sub([]string{"user"}, []string{auth.ScopeAuditIngest}), codes.PermissionDenied},
		{"empty scopes", sub([]string{"user"}, []string{}), codes.PermissionDenied},
		// Same gate as /v1/audit/logs: a token with no scopes claim does not
		// pass by being unrestricted.
		{"non-admin, no scopes claim", sub([]string{"user"}, nil), codes.PermissionDenied},
		{"admin", sub([]string{"admin"}, nil), codes.OK},
		{"explicit audit:read", sub([]string{"user"}, []string{auth.ScopeAuditRead}), codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.VerifyProofPack(tc.ctx, &pb.VerifyProofPackRequest{Sealed: sealed})
			if status.Code(err) != tc.want {
				t.Errorf("code = %v, want %v (%v)", status.Code(err), tc.want, err)
			}
		})
	}
}

// The audit chain is global: what the response says must not depend on which
// row, base id or purge date is behind the verdict.
func TestVerifyProofPack_MessagesAreFixedPerVerdict(t *testing.T) {
	msg := func(mutate func(c *fakeSealChain, sealed *pb.SealedProofPack)) *pb.VerifyProofPackResponse {
		chain, sealed := sealedFixture(t)
		mutate(chain, sealed)
		return verify(t, NewProofPackServer(chain), auditReadCtx(), sealed)
	}
	purged := func(base int64) *pb.VerifyProofPackResponse {
		return msg(func(c *fakeSealChain, s *pb.SealedProofPack) {
			delete(c.rows, s.Seal.AuditRowId)
			c.purged, c.base = true, audit.ChainBase{ID: base, PurgedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
		})
	}
	a, b := purged(1), purged(900)
	if a.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_PURGED || a.Message != b.Message {
		t.Errorf("purged messages differ: %q vs %q", a.Message, b.Message)
	}
	missing := msg(func(c *fakeSealChain, s *pb.SealedProofPack) { delete(c.rows, s.Seal.AuditRowId) })
	notSeal := msg(func(c *fakeSealChain, s *pb.SealedProofPack) {
		s.Seal.AuditRowId = 3 // a real row, not the seal of this pack
	})
	if missing.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_NOT_FOUND || missing.Message != notSeal.Message {
		t.Errorf("not-found messages differ: %q vs %q", missing.Message, notSeal.Message)
	}
	for _, r := range []*pb.VerifyProofPackResponse{a, missing, notSeal} {
		if strings.ContainsAny(r.Message, "0123456789") || strings.Contains(r.Message, "2026") {
			t.Errorf("message %q carries an id or date", r.Message)
		}
	}
}

type failingChain struct{ *fakeSealChain }

func (failingChain) MaxRowID(context.Context) (int64, error) {
	return 0, errors.New(`ERROR: relation "audit_logs" does not exist (SQLSTATE 42P01): audit: begin verify snapshot`)
}

func TestVerifyProofPack_NoInternalTextInResponses(t *testing.T) {
	inner, sealed := sealedFixture(t)
	_, err := NewProofPackServer(failingChain{inner}).VerifyProofPack(auditReadCtx(), &pb.VerifyProofPackRequest{Sealed: sealed})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	for _, leak := range []string{"SQLSTATE", "audit_logs", "snapshot", "relation"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}

	inner, sealed = sealedFixture(t)
	inner.bad = 3
	resp := verify(t, NewProofPackServer(inner), auditReadCtx(), sealed)
	if resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_CHAIN_BROKEN || strings.ContainsAny(resp.Message, "0123456789") || strings.Contains(resp.Message, "row") {
		t.Errorf("chain-broken message %q names a row or carries detail", resp.Message)
	}

	// A mismatch names the part but carries no digest values.
	inner, sealed = sealedFixture(t)
	sealed.Pack.GitCommit = "changed"
	resp = verify(t, NewProofPackServer(inner), auditReadCtx(), sealed)
	if strings.Contains(resp.Message+resp.FirstMismatch.GetReason(), hexOf(sealed)) {
		t.Errorf("mismatch carries a digest: %v", resp)
	}
	if resp.FirstMismatch.GetReason() == "" || len(resp.FirstMismatch.GetReason()) > 80 {
		t.Errorf("reason = %q, want a short fixed text", resp.FirstMismatch.GetReason())
	}
}

func hexOf(sealed *pb.SealedProofPack) string { return sealed.Seal.HeaderSha256 }

// A pack that does not match its seal is answered without walking the chain.
type countingChain struct {
	*fakeSealChain
	walks int
}

func (c *countingChain) VerifyChainSinceID(ctx context.Context, from int64, n int) (int64, error) {
	c.walks++
	return c.fakeSealChain.VerifyChainSinceID(ctx, from, n)
}

func TestVerifyProofPack_MismatchSkipsTheChainWalk(t *testing.T) {
	inner, sealed := sealedFixture(t)
	sealed.Pack.GitCommit = "changed"
	c := &countingChain{fakeSealChain: inner}
	resp := verify(t, NewProofPackServer(c), auditReadCtx(), sealed)
	if resp.Verdict != pb.ProofPackVerdict_PROOF_PACK_VERDICT_MISMATCH || c.walks != 0 {
		t.Errorf("verdict %v after %d walks, want MISMATCH after 0", resp.Verdict, c.walks)
	}
	inner2, sealed2 := sealedFixture(t)
	c2 := &countingChain{fakeSealChain: inner2}
	verify(t, NewProofPackServer(c2), auditReadCtx(), sealed2)
	if c2.walks == 0 {
		t.Error("a matching pack was not walked against the chain")
	}
}

// Chain walks are linear in the chain, so only a few run at once; the rest
// are refused with a retry hint rather than queued.
type blockingChain struct {
	*fakeSealChain
	entered chan struct{}
	release chan struct{}
}

func (c *blockingChain) MaxRowID(ctx context.Context) (int64, error) {
	c.entered <- struct{}{}
	<-c.release
	return c.fakeSealChain.MaxRowID(ctx)
}

func TestVerifyProofPack_ConcurrencyIsCapped(t *testing.T) {
	// The documented cap, written out so raising or lowering it fails here.
	const n = 4
	inner, sealed := sealedFixture(t)
	c := &blockingChain{fakeSealChain: inner, entered: make(chan struct{}, n+2), release: make(chan struct{})}
	s := NewProofPackServer(c)
	call := func() <-chan error {
		ch := make(chan error, 1)
		go func() {
			_, err := s.VerifyProofPack(auditReadCtx(), &pb.VerifyProofPackRequest{Sealed: sealed})
			ch <- err
		}()
		return ch
	}
	released := false
	release := func() {
		if !released {
			released = true
			close(c.release)
		}
	}
	defer release()

	// n verifies in flight, each parked inside the chain walk.
	inflight := make([]<-chan error, n)
	for i := range inflight {
		inflight[i] = call()
	}
	for i := 0; i < n; i++ {
		select {
		case <-c.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d verifies started", i, n)
		}
	}

	// The (n+1)th is refused with a retry hint and never reaches the chain.
	extra := call()
	select {
	case err := <-extra:
		if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "retry") {
			t.Fatalf("call %d: %v, want ResourceExhausted with a retry hint", n+1, err)
		}
	case <-c.entered:
		t.Fatalf("call %d was admitted past the cap of %d", n+1, n)
	case <-time.After(5 * time.Second):
		t.Fatalf("call %d neither refused nor started", n+1)
	}

	release()
	for _, ch := range inflight {
		if err := <-ch; err != nil {
			t.Errorf("in-flight verify: %v", err)
		}
	}
	// Slots are returned.
	if _, err := s.VerifyProofPack(auditReadCtx(), &pb.VerifyProofPackRequest{Sealed: sealed}); err != nil {
		t.Errorf("after release: %v", err)
	}
}

func TestVerifyProofPack_MalformedAndOversizedAreRejected(t *testing.T) {
	chain, sealed := sealedFixture(t)
	s := NewProofPackServer(chain)

	tooMany := proto.Clone(sealed).(*pb.SealedProofPack)
	for len(tooMany.Pack.Steps) <= proofpack.MaxSteps {
		tooMany.Pack.Steps = append(tooMany.Pack.Steps, proofStep("s", "x"))
	}
	huge := proto.Clone(sealed).(*pb.SealedProofPack)
	huge.Pack.Steps[0].Log = make([]byte, maxVerifyPackBytes+1)

	for name, req := range map[string]*pb.VerifyProofPackRequest{
		"nil request":    nil,
		"no sealed":      {},
		"no pack":        {Sealed: &pb.SealedProofPack{Seal: sealed.Seal}},
		"no seal":        {Sealed: &pb.SealedProofPack{Pack: sealed.Pack}},
		"no row id":      {Sealed: &pb.SealedProofPack{Pack: sealed.Pack, Seal: &pb.ProofPackSeal{PackSha256: "x"}}},
		"too many steps": {Sealed: tooMany},
		"oversized":      {Sealed: huge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.VerifyProofPack(auditReadCtx(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("code = %v, want InvalidArgument (%v)", status.Code(err), err)
			}
		})
	}
}

func TestVerifyProofPack_NoStoreIsUnavailable(t *testing.T) {
	_, err := NewProofPackServer(nil).VerifyProofPack(auditReadCtx(), &pb.VerifyProofPackRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
}
