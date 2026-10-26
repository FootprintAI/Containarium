package proofpack

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/audit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Sealing (#2798): the pack's digests are written as one row of the existing
// audit hash chain (internal/audit), through the same append path as every
// other audit row. No new hashing scheme: the part, header and pack digests
// are SHA-256 over deterministic proto encodings, exactly as PackDigest, and
// the row itself is hashed by the chain's own computeRowHash.

const (
	// SealAction is the audit_logs action of a seal row.
	SealAction = "proof_pack.seal"
	// SealResourceType is its resource_type; resource_id is the pack digest.
	SealResourceType = "proof_pack"
	// HeaderPart is TamperedPart.Step for the pack's non-step fields.
	HeaderPart = -1

	// AttachPath is where the sealed pack is committed in an agent-opened
	// PR's branch.
	AttachPath = ".containarium/proof-pack.json"

	// verifyBatch is the rows per VerifyChainSinceID call, as `audit verify`.
	verifyBatch = 1000
)

// ErrSealPurged is returned by Verify when retention has purged the seal's
// audit row: the pack can no longer be checked against the chain.
var ErrSealPurged = errors.New("proofpack: the seal's audit row was purged by retention")

// ErrSealNotFound is returned by Verify when the seal's audit row does not
// exist (and was not purged), or is not the seal of the pack.
var ErrSealNotFound = errors.New("proofpack: seal audit row not found")

// ErrChainBroken is returned by Verify when the audit chain from the seal
// row to the tip does not verify.
var ErrChainBroken = errors.New("proofpack: audit chain broken")

// TamperedPart names the part of a pack that does not match its seal.
type TamperedPart struct {
	// Step is the step's index, or HeaderPart.
	Step int
	// Name is the step's name as sealed (as the pack has it for a step the
	// seal does not have); empty for the header.
	Name   string
	Reason string
}

func (e *TamperedPart) Error() string {
	if e.Step == HeaderPart {
		return "proofpack: pack header: " + e.Reason
	}
	return fmt.Sprintf("proofpack: step %d (%q): %s", e.Step, e.Name, e.Reason)
}

// ChainAppender appends one row to the audit chain and returns its id.
// *audit.Store satisfies it.
type ChainAppender interface {
	Append(ctx context.Context, e *audit.AuditEntry) (int64, error)
}

// SealChain is the read side Verify needs. *audit.Store satisfies it.
type SealChain interface {
	ChainEntryAt(ctx context.Context, id int64) (audit.ChainEntry, bool, error)
	ChainBase(ctx context.Context) (audit.ChainBase, bool, error)
	MaxRowID(ctx context.Context) (int64, error)
	VerifyChainSinceID(ctx context.Context, fromID int64, limit int) (int64, error)
}

// NewSeal computes a pack's seal digests. AuditRowId is left 0.
func NewSeal(pack *pb.ProofPack) (*pb.ProofPackSeal, error) {
	packDigest, err := PackDigest(pack)
	if err != nil {
		return nil, err
	}
	header := proto.Clone(pack).(*pb.ProofPack)
	header.Steps = nil
	headerDigest, err := PackDigest(header)
	if err != nil {
		return nil, err
	}
	seal := &pb.ProofPackSeal{PackSha256: packDigest, HeaderSha256: headerDigest}
	for _, s := range pack.GetSteps() {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(s)
		if err != nil {
			return nil, err
		}
		seal.Parts = append(seal.Parts, &pb.ProofPartDigest{Name: s.GetName(), Sha256: LogDigest(b)})
	}
	return seal, nil
}

// Seal appends pack's seal to the audit chain, attributed to username and
// runID, and returns the pack with the seal that points at its row. A pack
// whose stored log digests are already wrong is refused.
func Seal(ctx context.Context, chain ChainAppender, username, runID string, pack *pb.ProofPack) (*pb.SealedProofPack, error) {
	if err := CheckPartDigests(pack); err != nil {
		return nil, err
	}
	seal, err := NewSeal(pack)
	if err != nil {
		return nil, err
	}
	detail, err := protojson.Marshal(seal)
	if err != nil {
		return nil, err
	}
	id, err := chain.Append(ctx, &audit.AuditEntry{
		Username:     username,
		Action:       SealAction,
		ResourceType: SealResourceType,
		ResourceID:   seal.GetPackSha256(),
		Detail:       string(detail),
		RunID:        runID,
		StatusCode:   200,
	})
	if err != nil {
		return nil, fmt.Errorf("proofpack: seal into audit chain: %w", err)
	}
	seal.AuditRowId = id
	return &pb.SealedProofPack{Pack: proto.Clone(pack).(*pb.ProofPack), Seal: seal}, nil
}

// VerifyResult is what a passing Verify checked.
type VerifyResult struct {
	PackSHA256 string
	AuditRowID int64
	Steps      int
	// ChainCheckedThrough is the highest row id the chain walk covered.
	ChainCheckedThrough int64
	// ChainTipHash is the row_hash of that row, for comparison with the
	// external anchor; empty when the tip row could not be read back.
	ChainTipHash string
}

// Verify recomputes a sealed pack's digests and checks them against its seal
// row in the audit chain, and the chain from that row to the tip. A part
// that does not match is reported as a *TamperedPart naming it.
//
// The seal row stays verifiable after retention purges rows below it: the
// chain walk starts from the stored chain base. Once the seal row itself is
// purged, Verify returns ErrSealPurged.
func Verify(ctx context.Context, chain SealChain, sealed *pb.SealedProofPack) (VerifyResult, error) {
	pack, fileSeal := sealed.GetPack(), sealed.GetSeal()
	if pack == nil || fileSeal == nil || fileSeal.GetAuditRowId() <= 0 {
		return VerifyResult{}, errors.New("proofpack: not a sealed pack (no pack, seal or audit row id)")
	}
	if err := CheckPartDigests(pack); err != nil {
		return VerifyResult{}, err
	}

	id := fileSeal.GetAuditRowId()
	row, found, err := chain.ChainEntryAt(ctx, id)
	if err != nil {
		return VerifyResult{}, err
	}
	if !found {
		base, purged, err := chain.ChainBase(ctx)
		if err != nil {
			return VerifyResult{}, err
		}
		if purged && id <= base.ID {
			return VerifyResult{}, fmt.Errorf("%w: row %d is at or below the chain base id %d (purged %s)",
				ErrSealPurged, id, base.ID, base.PurgedAt.UTC().Format("2006-01-02"))
		}
		return VerifyResult{}, fmt.Errorf("%w: row %d does not exist and was not purged by retention", ErrSealNotFound, id)
	}
	if row.Action != SealAction || row.ResourceType != SealResourceType || row.ResourceID != fileSeal.GetPackSha256() {
		return VerifyResult{}, fmt.Errorf("%w: audit row %d is not the seal of pack %s", ErrSealNotFound, id, fileSeal.GetPackSha256())
	}

	maxID, err := chain.MaxRowID(ctx)
	if err != nil {
		return VerifyResult{}, err
	}
	for from := id - 1; from < maxID; from += verifyBatch {
		// A break comes back as its row id, usually with an error saying why.
		bad, err := chain.VerifyChainSinceID(ctx, from, verifyBatch)
		if bad > 0 {
			return VerifyResult{}, fmt.Errorf("%w at row %d (seal row %d): %v", ErrChainBroken, bad, id, err)
		}
		if err != nil {
			return VerifyResult{}, fmt.Errorf("proofpack: verify audit chain from row %d: %w", id, err)
		}
	}

	var recorded pb.ProofPackSeal
	if err := protojson.Unmarshal([]byte(row.Detail), &recorded); err != nil {
		return VerifyResult{}, fmt.Errorf("proofpack: seal audit row %d detail: %w", id, err)
	}
	if err := compareSeal(pack, &recorded); err != nil {
		return VerifyResult{}, err
	}
	res := VerifyResult{PackSHA256: recorded.GetPackSha256(), AuditRowID: id, Steps: len(pack.GetSteps()), ChainCheckedThrough: maxID}
	if tip, ok, err := chain.ChainEntryAt(ctx, maxID); err == nil && ok {
		res.ChainTipHash = tip.RowHash
	}
	return res, nil
}

// compareSeal recomputes pack's seal and names the first part that differs
// from recorded, the seal held in the audit chain.
func compareSeal(pack *pb.ProofPack, recorded *pb.ProofPackSeal) error {
	got, err := NewSeal(pack)
	if err != nil {
		return err
	}
	want := recorded.GetParts()
	for i := 0; i < len(want) || i < len(got.Parts); i++ {
		switch {
		case i >= len(got.Parts):
			return &TamperedPart{Step: i, Name: want[i].GetName(), Reason: "sealed step is missing from the pack"}
		case i >= len(want):
			return &TamperedPart{Step: i, Name: got.Parts[i].GetName(), Reason: "step is not in the seal"}
		case got.Parts[i].GetSha256() != want[i].GetSha256():
			return &TamperedPart{Step: i, Name: want[i].GetName(),
				Reason: fmt.Sprintf("digest %s does not match sealed %s", got.Parts[i].GetSha256(), want[i].GetSha256())}
		}
	}
	if got.GetHeaderSha256() != recorded.GetHeaderSha256() {
		return &TamperedPart{Step: HeaderPart,
			Reason: fmt.Sprintf("digest %s does not match sealed %s", got.GetHeaderSha256(), recorded.GetHeaderSha256())}
	}
	if got.GetPackSha256() != recorded.GetPackSha256() {
		return fmt.Errorf("proofpack: pack digest %s does not match sealed %s", got.GetPackSha256(), recorded.GetPackSha256())
	}
	return nil
}
