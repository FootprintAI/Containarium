package server

import (
	"context"
	"strings"
	"testing"

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
	r := audit.ChainEntry{AuditEntry: *e, RowHash: "hash-" + string(rune('a'+f.next))}
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
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no subject", context.Background(), codes.Unauthenticated},
		{"wrong scope", auth.ContextWithTestSubjectScopes(context.Background(), "a", []string{"user"}, []string{auth.ScopeAuditIngest}), codes.PermissionDenied},
		{"empty scopes", auth.ContextWithTestSubjectScopes(context.Background(), "a", []string{"user"}, []string{}), codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.VerifyProofPack(tc.ctx, &pb.VerifyProofPackRequest{Sealed: sealed})
			if status.Code(err) != tc.want {
				t.Errorf("code = %v, want %v (%v)", status.Code(err), tc.want, err)
			}
		})
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
