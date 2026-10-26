// Package storetest is the behavioural contract every guardrailpolicy.Store
// must meet. The in-memory store runs it in the unit suite; the Postgres
// store runs it in the store-integration lane against a real database.
package storetest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Signer builds a valid trusted signer from a deterministic seed, so
// fixtures are synthetic and stable.
func Signer(t *testing.T, seed byte, label string) *pb.GuardrailTrustedSigner {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	return &pb.GuardrailTrustedSigner{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: label}
}

// Policy is a two-rule fixture policy.
func Policy(maxResidual int32) *pb.GuardrailPolicy {
	return &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT, MaxResidual: maxResidual},
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
	}}
}

// Req is a SetGuardrailPolicyRequest with the given rules and signers.
func Req(policy *pb.GuardrailPolicy, signers ...*pb.GuardrailTrustedSigner) *pb.SetGuardrailPolicyRequest {
	return &pb.SetGuardrailPolicyRequest{Policy: policy, TrustedSigners: signers}
}

// RunStoreContract runs the shared behaviour against stores built by newStore
// (each subtest gets a fresh, empty store).
func RunStoreContract(t *testing.T, newStore func(t *testing.T) guardrailpolicy.Store) {
	ctx := context.Background()

	t.Run("not configured is the typed ErrNotConfigured", func(t *testing.T) {
		s := newStore(t)
		got, err := s.Get(ctx)
		if !errors.Is(err, guardrailpolicy.ErrNotConfigured) {
			t.Fatalf("Get on an empty store = (%v, %v), want ErrNotConfigured", got, err)
		}
	})

	t.Run("set then get round-trips", func(t *testing.T) {
		s := newStore(t)
		signer := Signer(t, 1, "release key")
		res, err := s.Set(ctx, Req(Policy(2), signer), "admin-a")
		if err != nil {
			t.Fatalf("Set: %v", err)
		}
		if res.Previous != nil {
			t.Fatalf("first Set reported a previous policy: %v", res.Previous)
		}
		if res.Current.GetRevision() != 1 {
			t.Fatalf("first revision = %d, want 1", res.Current.GetRevision())
		}
		got, err := s.Get(ctx)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !proto.Equal(got.GetPolicy(), Policy(2)) {
			t.Fatalf("policy = %v, want %v", got.GetPolicy(), Policy(2))
		}
		if len(got.GetTrustedSigners()) != 1 || !proto.Equal(got.GetTrustedSigners()[0], signer) {
			t.Fatalf("signers = %v, want [%v]", got.GetTrustedSigners(), signer)
		}
		if got.GetRevision() != 1 || got.GetUpdatedBy() != "admin-a" || got.GetUpdatedAt() == nil {
			t.Fatalf("bookkeeping = rev %d by %q at %v, want rev 1 by admin-a with a time",
				got.GetRevision(), got.GetUpdatedBy(), got.GetUpdatedAt())
		}
		if !proto.Equal(got, res.Current) {
			t.Fatalf("Get = %v, want what Set returned %v", got, res.Current)
		}
	})

	t.Run("revision is monotonic and previous is reported", func(t *testing.T) {
		s := newStore(t)
		var prev *pb.ServerGuardrailPolicy
		for want := int64(1); want <= 3; want++ {
			res, err := s.Set(ctx, Req(Policy(int32(want))), "admin-a")
			if err != nil {
				t.Fatalf("Set #%d: %v", want, err)
			}
			if res.Current.GetRevision() != want {
				t.Fatalf("revision after Set #%d = %d, want %d", want, res.Current.GetRevision(), want)
			}
			if !proto.Equal(res.Previous, prev) {
				t.Fatalf("Set #%d previous = %v, want %v", want, res.Previous, prev)
			}
			prev = res.Current
		}
	})

	t.Run("an empty rule list is stored as configured", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Set(ctx, Req(&pb.GuardrailPolicy{}), "admin-a"); err != nil {
			t.Fatalf("Set empty: %v", err)
		}
		got, err := s.Get(ctx)
		if err != nil {
			t.Fatalf("Get after an empty Set = %v, want a configured (empty) policy", err)
		}
		if len(got.GetPolicy().GetRules()) != 0 || got.GetRevision() != 1 {
			t.Fatalf("got %v, want empty rules at revision 1", got)
		}
	})

	t.Run("returned values do not alias the store", func(t *testing.T) {
		s := newStore(t)
		res, err := s.Set(ctx, Req(Policy(0)), "admin-a")
		if err != nil {
			t.Fatalf("Set: %v", err)
		}
		res.Current.Policy.Rules[0].MaxResidual = 99
		got, err := s.Get(ctx)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.GetPolicy().GetRules()[0].GetMaxResidual() != 0 {
			t.Fatalf("mutating Set's result changed the stored policy")
		}
	})

	runRevocationContract(t, newStore)
	runBaselineModeContract(t, newStore)
}

// runRevocationContract is the read-edit-write and revocation part of the
// contract (#2729): expected_revision is checked under the store's lock, a
// revoked key's revoked_at is stamped by the store, and no Set can drop or
// change a stored revoked key.
func runRevocationContract(t *testing.T, newStore func(t *testing.T) guardrailpolicy.Store) {
	ctx := context.Background()
	rev := func(r int64) *int64 { return &r }

	t.Run("expected_revision must equal the stored revision", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Set(ctx, &pb.SetGuardrailPolicyRequest{Policy: Policy(0), ExpectedRevision: rev(1)}, "admin-a"); !errors.Is(err, guardrailpolicy.ErrRevisionConflict) {
			t.Fatalf("Set expecting revision 1 on an empty store = %v, want ErrRevisionConflict", err)
		}
		if _, err := s.Get(ctx); !errors.Is(err, guardrailpolicy.ErrNotConfigured) {
			t.Fatalf("a refused Set stored something: %v", err)
		}
		if _, err := s.Set(ctx, &pb.SetGuardrailPolicyRequest{Policy: Policy(0), ExpectedRevision: rev(0)}, "admin-a"); err != nil {
			t.Fatalf("Set expecting revision 0 on an empty store: %v", err)
		}
		if _, err := s.Set(ctx, Req(Policy(1)), "admin-b"); err != nil { // no precondition: applies
			t.Fatalf("Set without expected_revision: %v", err)
		}
		if _, err := s.Set(ctx, &pb.SetGuardrailPolicyRequest{Policy: Policy(3), ExpectedRevision: rev(1)}, "admin-a"); !errors.Is(err, guardrailpolicy.ErrRevisionConflict) {
			t.Fatalf("stale expected_revision = %v, want ErrRevisionConflict", err)
		}
		got, err := s.Get(ctx)
		if err != nil || got.GetRevision() != 2 || !proto.Equal(got.GetPolicy(), Policy(1)) {
			t.Fatalf("after a stale Set = (%v, %v), want admin-b's revision 2", got, err)
		}
	})

	t.Run("a revoked key is stamped by the store and permanent", func(t *testing.T) {
		s := newStore(t)
		gone := Signer(t, 9, "old key")
		clientTime := timestamppb.New(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC))
		revoked := []*pb.GuardrailRevokedKey{{KeyId: gone.GetKeyId(), Reason: "leaked", RevokedAt: clientTime}}
		res, err := s.Set(ctx, &pb.SetGuardrailPolicyRequest{Policy: Policy(0), RevokedSigners: revoked}, "admin-a")
		if err != nil {
			t.Fatalf("Set with a revoked key: %v", err)
		}
		stored := res.Current.GetRevokedSigners()
		if len(stored) != 1 || stored[0].GetKeyId() != gone.GetKeyId() || stored[0].GetReason() != "leaked" {
			t.Fatalf("stored revoked = %v", stored)
		}
		if at := stored[0].GetRevokedAt(); at == nil || at.AsTime().Year() == 2001 {
			t.Fatalf("revoked_at = %v, want the store's time, not the request's", at)
		}
		for name, keep := range map[string][]*pb.GuardrailRevokedKey{
			"dropped":        nil,
			"reason changed": {{KeyId: gone.GetKeyId(), Reason: "never mind"}},
		} {
			if _, err := s.Set(ctx, &pb.SetGuardrailPolicyRequest{Policy: Policy(0), RevokedSigners: keep}, "admin-b"); !errors.Is(err, guardrailpolicy.ErrRevocationPermanent) {
				t.Fatalf("Set with the revoked key %s = %v, want ErrRevocationPermanent", name, err)
			}
		}
		res2, err := s.Set(ctx, &pb.SetGuardrailPolicyRequest{Policy: Policy(1), RevokedSigners: []*pb.GuardrailRevokedKey{{KeyId: gone.GetKeyId(), Reason: "leaked"}}}, "admin-b")
		if err != nil {
			t.Fatalf("Set keeping the revoked key: %v", err)
		}
		if !proto.Equal(res2.Current.GetRevokedSigners()[0], stored[0]) {
			t.Fatalf("revoked entry changed across a Set: %v -> %v", stored[0], res2.Current.GetRevokedSigners()[0])
		}
		if got, err := s.Get(ctx); err != nil || got.GetRevision() != 2 {
			t.Fatalf("Get = (%v, %v), want revision 2", got, err)
		}
	})
}

// runBaselineModeContract is the baseline mode's part of the contract
// (#2738): LOG at revision 0 until set, a monotonic revision, and no effect
// on the stored policy (setting it must not turn the baseline off).
func runBaselineModeContract(t *testing.T, newStore func(t *testing.T) guardrailpolicy.Store) {
	ctx := context.Background()
	const (
		logMode   = pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG
		blockMode = pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK
	)

	t.Run("baseline mode is LOG at revision 0 until set", func(t *testing.T) {
		got, err := newStore(t).GetBaselineMode(ctx)
		if err != nil {
			t.Fatalf("GetBaselineMode on an empty store: %v", err)
		}
		if got.GetMode() != logMode || got.GetRevision() != 0 || got.GetUpdatedBy() != "" {
			t.Fatalf("default = %v, want LOG at revision 0 by nobody", got)
		}
	})

	t.Run("baseline mode set round-trips with a monotonic revision", func(t *testing.T) {
		s := newStore(t)
		prev, _ := s.GetBaselineMode(ctx)
		for i, mode := range []pb.GuardrailBaselineMode{blockMode, logMode, blockMode} {
			res, err := s.SetBaselineMode(ctx, mode, "admin-a", nil)
			if err != nil {
				t.Fatalf("SetBaselineMode #%d: %v", i+1, err)
			}
			if !proto.Equal(res.Previous, prev) {
				t.Fatalf("set #%d previous = %v, want %v", i+1, res.Previous, prev)
			}
			if res.Current.GetMode() != mode || res.Current.GetRevision() != int64(i+1) ||
				res.Current.GetUpdatedBy() != "admin-a" || res.Current.GetUpdatedAt() == nil {
				t.Fatalf("set #%d current = %v, want %v at revision %d by admin-a with a time", i+1, res.Current, mode, i+1)
			}
			got, err := s.GetBaselineMode(ctx)
			if err != nil || !proto.Equal(got, res.Current) {
				t.Fatalf("GetBaselineMode after set #%d = (%v, %v), want %v", i+1, got, err, res.Current)
			}
			prev = res.Current
		}
	})

	t.Run("baseline mode rejects UNSPECIFIED and leaves the setting", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.SetBaselineMode(ctx, pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_UNSPECIFIED, "admin-a", nil); err == nil {
			t.Fatal("SetBaselineMode(UNSPECIFIED) succeeded, want an error")
		}
		if got, err := s.GetBaselineMode(ctx); err != nil || got.GetRevision() != 0 {
			t.Fatalf("after a rejected set = (%v, %v), want the untouched default", got, err)
		}
	})

	t.Run("baseline mode beforeCommit sees the change and a failure discards it", func(t *testing.T) {
		s := newStore(t)
		var seen *guardrailpolicy.BaselineSetResult
		_, err := s.SetBaselineMode(ctx, blockMode, "admin-a", func(r *guardrailpolicy.BaselineSetResult) error {
			seen = r
			return errors.New("audit store down")
		})
		if err == nil {
			t.Fatal("SetBaselineMode with a failing beforeCommit succeeded, want its error")
		}
		if seen == nil || seen.Current.GetMode() != blockMode || seen.Current.GetRevision() != 1 || seen.Previous.GetRevision() != 0 {
			t.Fatalf("beforeCommit saw %+v, want LOG rev 0 -> BLOCK rev 1", seen)
		}
		if got, err := s.GetBaselineMode(ctx); err != nil || got.GetMode() != logMode || got.GetRevision() != 0 {
			t.Fatalf("after a failed beforeCommit = (%v, %v), want the untouched default", got, err)
		}
		// The next set reuses revision 1: nothing of the discarded one remains.
		res, err := s.SetBaselineMode(ctx, blockMode, "admin-a", func(*guardrailpolicy.BaselineSetResult) error { return nil })
		if err != nil || res.Current.GetRevision() != 1 {
			t.Fatalf("set after a discarded one = (%v, %v), want revision 1", res, err)
		}
	})

	t.Run("baseline mode is independent of the policy", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.SetBaselineMode(ctx, blockMode, "admin-a", nil); err != nil {
			t.Fatalf("SetBaselineMode: %v", err)
		}
		if got, err := s.Get(ctx); !errors.Is(err, guardrailpolicy.ErrNotConfigured) {
			t.Fatalf("Get after setting the baseline mode = (%v, %v), want ErrNotConfigured", got, err)
		}
		if _, err := s.Set(ctx, Req(Policy(0)), "admin-b"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if got, err := s.GetBaselineMode(ctx); err != nil || got.GetMode() != blockMode || got.GetRevision() != 1 {
			t.Fatalf("baseline mode after a policy Set = (%v, %v), want BLOCK at revision 1", got, err)
		}
	})
}
