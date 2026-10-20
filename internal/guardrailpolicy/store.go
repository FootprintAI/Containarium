// Package guardrailpolicy stores the cluster-wide, admin-owned guardrail
// policy (#2368; docs/architecture/guardrail-inbound-and-server-policy.md,
// "Policy service"). The daemon's GuardrailPolicyService writes it; the
// deploy gate and the model gateway read it through PolicyProvider.
package guardrailpolicy

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ErrNotConfigured is the explicit "no policy was ever set" state. It is the
// ONLY error a consumer may read as "no policy"; any other error from Get
// (database down, timeout) means the policy is unknown, and a consumer must
// not fall back to ungated behaviour on it.
var ErrNotConfigured = errors.New("guardrail policy not configured")

// PolicyProvider is the read side the gateway and the deploy gate consume.
type PolicyProvider interface {
	// Get returns the stored policy, ErrNotConfigured, or a read error.
	Get(ctx context.Context) (*pb.ServerGuardrailPolicy, error)
}

// SetResult is what one Set replaced and what it stored, read in the same
// critical section so an audit entry names the revision that was actually
// overwritten.
type SetResult struct {
	Previous *pb.ServerGuardrailPolicy // nil when nothing was configured
	Current  *pb.ServerGuardrailPolicy
}

// Store is the read/write store. Set assigns revision = previous + 1 (1 for
// the first Set), stamps updated_at/updated_by, and stores the policy and
// signers as given; validation is the caller's job (see Validate).
type Store interface {
	PolicyProvider
	BaselineModeProvider
	Set(ctx context.Context, policy *pb.GuardrailPolicy, signers []*pb.GuardrailTrustedSigner, updatedBy string) (*SetResult, error)
	// SetBaselineMode stores the baseline mode (LOG or BLOCK; anything else
	// is ErrInvalidBaselineMode), revision = previous + 1. It never touches
	// the policy, so it cannot turn the baseline off. beforeCommit (nil =
	// none) runs with the new setting while the change is still pending:
	// an error from it discards the change and is returned, so a caller
	// can make the change conditional on its audit entry being written.
	SetBaselineMode(ctx context.Context, mode pb.GuardrailBaselineMode, updatedBy string, beforeCommit BaselineBeforeCommit) (*BaselineSetResult, error)
}

// BaselineModeProvider is the read side of the baseline mode (#2738), kept
// next to the policy but separate from it. A mode never set reads as
// DefaultBaseline (LOG, revision 0); any error is a read error.
type BaselineModeProvider interface {
	GetBaselineMode(ctx context.Context) (*pb.GuardrailBaselineSetting, error)
}

// BaselineSetResult is what one SetBaselineMode replaced and stored.
// Previous is DefaultBaseline when the mode was never set.
type BaselineSetResult struct {
	Previous *pb.GuardrailBaselineSetting
	Current  *pb.GuardrailBaselineSetting
}

// BaselineBeforeCommit is SetBaselineMode's hook; see Store.
type BaselineBeforeCommit func(*BaselineSetResult) error

// ErrInvalidBaselineMode is SetBaselineMode's answer to a mode other than
// LOG or BLOCK.
var ErrInvalidBaselineMode = errors.New("baseline mode must be LOG or BLOCK")

// DefaultBaseline is the setting of a daemon whose baseline mode was never
// set: log-only (#2575, Q3 on #2727).
func DefaultBaseline() *pb.GuardrailBaselineSetting {
	return &pb.GuardrailBaselineSetting{Mode: pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG}
}

// ValidBaselineMode reports whether mode may be stored.
func ValidBaselineMode(mode pb.GuardrailBaselineMode) bool {
	return mode == pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG ||
		mode == pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK
}

// NextBaseline builds the setting a SetBaselineMode stores on top of prev.
// Exported for the Postgres store in pgstore.
func NextBaseline(prev *pb.GuardrailBaselineSetting, mode pb.GuardrailBaselineMode, updatedBy string, now time.Time) *pb.GuardrailBaselineSetting {
	return &pb.GuardrailBaselineSetting{
		Mode:      mode,
		Revision:  prev.GetRevision() + 1,
		UpdatedAt: timestamppb.New(now.UTC().Truncate(time.Microsecond)),
		UpdatedBy: updatedBy,
	}
}

// Hash is the policy hash a GuardrailAttestation records for this policy:
// the inner GuardrailPolicy only, so rotating a signer leaves it unchanged.
func Hash(p *pb.ServerGuardrailPolicy) (string, error) {
	return guardrail.PolicyHash(p.GetPolicy())
}

// Next builds the record a Set stores on top of prev (nil = not configured):
// revision prev+1, the given rules and signers (copied), now and updatedBy.
// Exported for the Postgres store in pgstore.
func Next(prev *pb.ServerGuardrailPolicy, policy *pb.GuardrailPolicy, signers []*pb.GuardrailTrustedSigner, updatedBy string, now time.Time) *pb.ServerGuardrailPolicy {
	out := &pb.ServerGuardrailPolicy{
		Policy:    proto.Clone(policy).(*pb.GuardrailPolicy),
		Revision:  prev.GetRevision() + 1,
		UpdatedAt: timestamppb.New(now.UTC().Truncate(time.Microsecond)),
		UpdatedBy: updatedBy,
	}
	for _, s := range signers {
		out.TrustedSigners = append(out.TrustedSigners, proto.Clone(s).(*pb.GuardrailTrustedSigner))
	}
	return out
}

// Clone deep-copies p; nil stays nil.
func Clone(p *pb.ServerGuardrailPolicy) *pb.ServerGuardrailPolicy {
	if p == nil {
		return nil
	}
	return proto.Clone(p).(*pb.ServerGuardrailPolicy)
}

// MemoryStore is the in-process store for daemons without a database and
// for tests. It does not survive a restart.
type MemoryStore struct {
	mu       sync.Mutex
	cur      *pb.ServerGuardrailPolicy
	baseline *pb.GuardrailBaselineSetting
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{baseline: DefaultBaseline()} }

func (m *MemoryStore) GetBaselineMode(context.Context) (*pb.GuardrailBaselineSetting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return proto.Clone(m.baseline).(*pb.GuardrailBaselineSetting), nil
}

func (m *MemoryStore) SetBaselineMode(_ context.Context, mode pb.GuardrailBaselineMode, updatedBy string, beforeCommit BaselineBeforeCommit) (*BaselineSetResult, error) {
	if !ValidBaselineMode(mode) {
		return nil, ErrInvalidBaselineMode
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := NextBaseline(m.baseline, mode, updatedBy, time.Now())
	res := &BaselineSetResult{
		Previous: proto.Clone(m.baseline).(*pb.GuardrailBaselineSetting),
		Current:  proto.Clone(cur).(*pb.GuardrailBaselineSetting),
	}
	if beforeCommit != nil {
		if err := beforeCommit(res); err != nil {
			return nil, err
		}
	}
	m.baseline = cur
	return res, nil
}

func (m *MemoryStore) Get(context.Context) (*pb.ServerGuardrailPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return nil, ErrNotConfigured
	}
	return Clone(m.cur), nil
}

func (m *MemoryStore) Set(_ context.Context, policy *pb.GuardrailPolicy, signers []*pb.GuardrailTrustedSigner, updatedBy string) (*SetResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.cur
	m.cur = Next(prev, policy, signers, updatedBy, time.Now())
	return &SetResult{Previous: Clone(prev), Current: Clone(m.cur)}, nil
}
