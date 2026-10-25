package proofpack

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/audit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeChain is an in-memory audit chain. Row hashes are not computed here:
// VerifyChainSinceID reports whatever bad is set to, and the real chain is
// exercised by seal_integration_test.go against Postgres.
type fakeChain struct {
	rows       map[int64]audit.ChainEntry
	next       int64
	base       audit.ChainBase
	purged     bool
	bad        int64
	verifyFrom []int64
}

func newFakeChain() *fakeChain { return &fakeChain{rows: map[int64]audit.ChainEntry{}} }

func (f *fakeChain) Append(_ context.Context, e *audit.AuditEntry) (int64, error) {
	f.next++
	row := audit.ChainEntry{AuditEntry: *e}
	row.ID = f.next
	f.rows[f.next] = row
	return f.next, nil
}

func (f *fakeChain) ChainEntryAt(_ context.Context, id int64) (audit.ChainEntry, bool, error) {
	r, ok := f.rows[id]
	return r, ok, nil
}

func (f *fakeChain) ChainBase(context.Context) (audit.ChainBase, bool, error) {
	return f.base, f.purged, nil
}

func (f *fakeChain) MaxRowID(context.Context) (int64, error) { return f.next, nil }

func (f *fakeChain) VerifyChainSinceID(_ context.Context, from int64, _ int) (int64, error) {
	f.verifyFrom = append(f.verifyFrom, from)
	return f.bad, nil
}

func samplePack() *pb.ProofPack {
	step := func(name string, kind pb.ProofPartKind, log string) *pb.ProofStep {
		return &pb.ProofStep{Name: name, Kind: kind, Log: []byte(log), LogSha256: LogDigest([]byte(log)), LogOriginalBytes: int64(len(log))}
	}
	return &pb.ProofPack{
		SchemaVersion: SchemaVersion,
		Producer:      "tenant-container",
		RepoDir:       DefaultRepoDir,
		GitCommit:     "0123456789abcdef0123456789abcdef01234567",
		CommandSource: pb.ProofCommandSource_PROOF_COMMAND_SOURCE_DECLARED,
		Steps: []*pb.ProofStep{
			step("unit", pb.ProofPartKind_PROOF_PART_KIND_UNIT, "ok  pkg 0.1s\n"),
			step("lint", pb.ProofPartKind_PROOF_PART_KIND_STATIC_ANALYSIS, "0 issues.\n"),
		},
		Status:        pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED,
		LogLimitBytes: LogLimitBytes,
	}
}

func sealSample(t *testing.T, chain *fakeChain) *pb.SealedProofPack {
	t.Helper()
	logN := 3 // unrelated rows before the seal, so its id is not 1
	for i := 0; i < logN; i++ {
		_, _ = chain.Append(context.Background(), &audit.AuditEntry{Action: "container_create"})
	}
	sealed, err := Seal(context.Background(), chain, "tenant", "run-1", samplePack())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func TestSeal_AppendsPackDigestToChain(t *testing.T) {
	chain := newFakeChain()
	sealed := sealSample(t, chain)

	digest, _ := PackDigest(samplePack())
	if sealed.GetSeal().GetPackSha256() != digest {
		t.Fatalf("seal pack_sha256 = %s, want PackDigest %s", sealed.GetSeal().GetPackSha256(), digest)
	}
	if got := sealed.GetSeal().GetAuditRowId(); got != 4 {
		t.Fatalf("audit_row_id = %d, want the appended row 4", got)
	}
	row := chain.rows[4]
	if row.Action != SealAction || row.ResourceType != SealResourceType || row.ResourceID != digest {
		t.Errorf("row = %s %s %s, want %s %s %s", row.Action, row.ResourceType, row.ResourceID, SealAction, SealResourceType, digest)
	}
	if row.Username != "tenant" || row.RunID != "run-1" {
		t.Errorf("row attribution = %q %q", row.Username, row.RunID)
	}
	if len(sealed.GetSeal().GetParts()) != 2 || sealed.GetSeal().GetParts()[1].GetName() != "lint" {
		t.Errorf("parts = %v, want one per step in order", sealed.GetSeal().GetParts())
	}
	if !proto.Equal(sealed.GetPack(), samplePack()) {
		t.Errorf("sealed pack differs from the input pack")
	}

	res, err := Verify(context.Background(), chain, sealed)
	if err != nil {
		t.Fatalf("Verify on an untouched sealed pack: %v", err)
	}
	if res.AuditRowID != 4 || res.PackSHA256 != digest || res.Steps != 2 {
		t.Errorf("result = %+v", res)
	}
	if len(chain.verifyFrom) == 0 || chain.verifyFrom[0] != 3 {
		t.Errorf("chain walk started at %v, want from the row before the seal (3)", chain.verifyFrom)
	}
}

// Editing any part of a sealed pack makes verify fail and name the part.
func TestVerify_EditedPartIsNamed(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(p *pb.ProofPack)
		wantStep int
		wantName string
	}{
		{"one log byte", func(p *pb.ProofPack) { p.Steps[1].Log[0] ^= 1 }, 1, "lint"},
		{"log rewritten with a matching log_sha256", func(p *pb.ProofPack) {
			p.Steps[0].Log = []byte("FAIL\n")
			p.Steps[0].LogSha256 = LogDigest(p.Steps[0].Log)
		}, 0, "unit"},
		{"exit code", func(p *pb.ProofPack) { p.Steps[0].ExitCode = 0; p.Steps[1].ExitCode = 2 }, 1, "lint"},
		{"timed out flag", func(p *pb.ProofPack) { p.Steps[0].TimedOut = true }, 0, "unit"},
		{"step renamed", func(p *pb.ProofPack) { p.Steps[1].Name = "lint2" }, 1, "lint"},
		{"git commit", func(p *pb.ProofPack) { p.GitCommit = strings.Repeat("f", 40) }, HeaderPart, ""},
		{"status", func(p *pb.ProofPack) { p.Status = pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED }, HeaderPart, ""},
		{"step dropped", func(p *pb.ProofPack) { p.Steps = p.Steps[:1] }, 1, "lint"},
		{"step added", func(p *pb.ProofPack) { p.Steps = append(p.Steps, proto.Clone(p.Steps[0]).(*pb.ProofStep)) }, 2, "unit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := newFakeChain()
			sealed := sealSample(t, chain)
			tc.edit(sealed.Pack)

			_, err := Verify(context.Background(), chain, sealed)
			var tp *TamperedPart
			if !errors.As(err, &tp) {
				t.Fatalf("Verify err = %v, want a *TamperedPart", err)
			}
			if tp.Step != tc.wantStep || tp.Name != tc.wantName {
				t.Errorf("named step %d %q, want %d %q (err: %v)", tp.Step, tp.Name, tc.wantStep, tc.wantName, err)
			}
			if tc.wantName != "" && !strings.Contains(err.Error(), `"`+tc.wantName+`"`) {
				t.Errorf("message %q does not name the step", err)
			}
		})
	}
}

func TestVerify_ChainEntry(t *testing.T) {
	t.Run("chain broken at or after the seal row", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		chain.bad = 4
		_, err := Verify(context.Background(), chain, sealed)
		if err == nil || !strings.Contains(err.Error(), "row 4") {
			t.Fatalf("err = %v, want a chain break at row 4", err)
		}
	})
	t.Run("seal row deleted", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		delete(chain.rows, 4)
		_, err := Verify(context.Background(), chain, sealed)
		if err == nil || errors.Is(err, ErrSealPurged) || !strings.Contains(err.Error(), "row 4") {
			t.Fatalf("err = %v, want a missing (not purged) seal row 4", err)
		}
	})
	t.Run("seal row detail no longer matches", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		row := chain.rows[4]
		row.Detail = strings.Replace(row.Detail, sealed.Seal.Parts[0].Sha256, strings.Repeat("0", 64), 1)
		chain.rows[4] = row
		_, err := Verify(context.Background(), chain, sealed)
		var tp *TamperedPart
		if !errors.As(err, &tp) || tp.Step != 0 {
			t.Fatalf("err = %v, want step 0 named", err)
		}
	})
	t.Run("audit_row_id points at another row", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		sealed.Seal.AuditRowId = 2
		if _, err := Verify(context.Background(), chain, sealed); err == nil || !strings.Contains(err.Error(), "not the seal") {
			t.Fatalf("err = %v, want the row to be rejected as not this pack's seal", err)
		}
	})
	t.Run("pack_sha256 in the file edited", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		sealed.Seal.PackSha256 = strings.Repeat("a", 64)
		if _, err := Verify(context.Background(), chain, sealed); err == nil {
			t.Fatal("Verify passed with an edited pack_sha256")
		}
	})
	t.Run("no seal", func(t *testing.T) {
		if _, err := Verify(context.Background(), newFakeChain(), &pb.SealedProofPack{Pack: samplePack()}); err == nil {
			t.Fatal("Verify passed an unsealed pack")
		}
	})
}

// The audit chain is one global chain whose prefix retention may purge. A seal
// whose row is retained still verifies; one whose row was purged reports that
// precisely instead of looking like tampering.
func TestVerify_AfterRetentionPurge(t *testing.T) {
	t.Run("prefix below the seal purged", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		for id := int64(1); id <= 3; id++ {
			delete(chain.rows, id)
		}
		chain.base, chain.purged = audit.ChainBase{ID: 3, Hash: "h3", RowsPurged: 3}, true
		if _, err := Verify(context.Background(), chain, sealed); err != nil {
			t.Fatalf("Verify after purging rows below the seal: %v", err)
		}
	})
	t.Run("seal row itself purged", func(t *testing.T) {
		chain := newFakeChain()
		sealed := sealSample(t, chain)
		_, _ = chain.Append(context.Background(), &audit.AuditEntry{Action: "container_create"})
		for id := int64(1); id <= 4; id++ {
			delete(chain.rows, id)
		}
		chain.base, chain.purged = audit.ChainBase{ID: 4, Hash: "h4", RowsPurged: 4}, true
		_, err := Verify(context.Background(), chain, sealed)
		if !errors.Is(err, ErrSealPurged) {
			t.Fatalf("err = %v, want ErrSealPurged", err)
		}
	})
}

func TestVerify_ChainWalkReachesTip(t *testing.T) {
	chain := newFakeChain()
	sealed := sealSample(t, chain)
	for i := 0; i < 2500; i++ {
		_, _ = chain.Append(context.Background(), &audit.AuditEntry{Action: "container_create"})
	}
	if _, err := Verify(context.Background(), chain, sealed); err != nil {
		t.Fatal(err)
	}
	last := chain.verifyFrom[len(chain.verifyFrom)-1]
	if last+verifyBatch < chain.next {
		t.Errorf("chain walk stopped at %d (batches %v), tip is %d", last, chain.verifyFrom, chain.next)
	}
}
