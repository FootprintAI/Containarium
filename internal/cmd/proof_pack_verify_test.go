//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/proofpack"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// memSealChain is an in-memory chain whose rows are always intact; the real
// chain is covered by internal/proofpack's integration tests.
type memSealChain struct{ rows []audit.ChainEntry }

func (m *memSealChain) Append(_ context.Context, e *audit.AuditEntry) (int64, error) {
	row := audit.ChainEntry{AuditEntry: *e}
	row.ID = int64(len(m.rows) + 1)
	m.rows = append(m.rows, row)
	return row.ID, nil
}
func (m *memSealChain) ChainEntryAt(_ context.Context, id int64) (audit.ChainEntry, bool, error) {
	if id < 1 || id > int64(len(m.rows)) {
		return audit.ChainEntry{}, false, nil
	}
	return m.rows[id-1], true, nil
}
func (m *memSealChain) ChainBase(context.Context) (audit.ChainBase, bool, error) {
	return audit.ChainBase{}, false, nil
}
func (m *memSealChain) MaxRowID(context.Context) (int64, error) { return int64(len(m.rows)), nil }
func (m *memSealChain) VerifyChainSinceID(context.Context, int64, int) (int64, error) {
	return 0, nil
}

func writeSealedPack(t *testing.T, chain *memSealChain, edit func(*pb.SealedProofPack)) string {
	t.Helper()
	log := []byte("PASS\n")
	pack := &pb.ProofPack{
		SchemaVersion: 1,
		Producer:      "tenant-container",
		Steps:         []*pb.ProofStep{{Name: "unit", Kind: pb.ProofPartKind_PROOF_PART_KIND_UNIT, Log: log, LogSha256: proofpack.LogDigest(log)}},
		Status:        pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED,
	}
	sealed, err := proofpack.Seal(context.Background(), chain, "tenant", "run-1", pack)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(sealed)
	}
	b, err := protojson.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proof-pack-2798.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runVerifyAgainst(t *testing.T, chain *memSealChain, path string) (string, error) {
	t.Helper()
	old := proofPackVerifyChain
	proofPackVerifyChain = func(context.Context) (proofpack.SealChain, func(), error) { return chain, func() {}, nil }
	t.Cleanup(func() { proofPackVerifyChain = old })
	var out bytes.Buffer
	cmd := proofPackVerifyCmd
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	err := runProofPackVerify(cmd, []string{path})
	return out.String(), err
}

func TestProofPackVerifyCmd(t *testing.T) {
	t.Run("sealed pack passes", func(t *testing.T) {
		chain := &memSealChain{}
		out, err := runVerifyAgainst(t, chain, writeSealedPack(t, chain, nil))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !strings.Contains(out, "audit row 1") || !strings.Contains(out, "1 step") {
			t.Errorf("output %q does not report the seal row and steps", out)
		}
	})
	t.Run("edited log byte fails naming the step", func(t *testing.T) {
		chain := &memSealChain{}
		path := writeSealedPack(t, chain, func(s *pb.SealedProofPack) { s.Pack.Steps[0].Log[0] ^= 1 })
		_, err := runVerifyAgainst(t, chain, path)
		if err == nil || !strings.Contains(err.Error(), `"unit"`) {
			t.Fatalf("err = %v, want it to name step \"unit\"", err)
		}
	})
	t.Run("not a sealed pack file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "junk-2798.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runVerifyAgainst(t, &memSealChain{}, path); err == nil {
			t.Fatal("verify accepted a file that is not a sealed pack")
		}
	})
}
