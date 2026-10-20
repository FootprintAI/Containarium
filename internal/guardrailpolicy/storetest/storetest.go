// Package storetest is the behavioural contract every guardrailpolicy.Store
// must meet. The in-memory store runs it in the unit suite; the Postgres
// store runs it in the store-integration lane against a real database.
package storetest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

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
		res, err := s.Set(ctx, Policy(2), []*pb.GuardrailTrustedSigner{signer}, "admin-a")
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
			res, err := s.Set(ctx, Policy(int32(want)), nil, "admin-a")
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
		if _, err := s.Set(ctx, &pb.GuardrailPolicy{}, nil, "admin-a"); err != nil {
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
		res, err := s.Set(ctx, Policy(0), nil, "admin-a")
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

	runBaselineModeContract(t, newStore)
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
			res, err := s.SetBaselineMode(ctx, mode, "admin-a")
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
		if _, err := s.SetBaselineMode(ctx, pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_UNSPECIFIED, "admin-a"); err == nil {
			t.Fatal("SetBaselineMode(UNSPECIFIED) succeeded, want an error")
		}
		if got, err := s.GetBaselineMode(ctx); err != nil || got.GetRevision() != 0 {
			t.Fatalf("after a rejected set = (%v, %v), want the untouched default", got, err)
		}
	})

	t.Run("baseline mode is independent of the policy", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.SetBaselineMode(ctx, blockMode, "admin-a"); err != nil {
			t.Fatalf("SetBaselineMode: %v", err)
		}
		if got, err := s.Get(ctx); !errors.Is(err, guardrailpolicy.ErrNotConfigured) {
			t.Fatalf("Get after setting the baseline mode = (%v, %v), want ErrNotConfigured", got, err)
		}
		if _, err := s.Set(ctx, Policy(0), nil, "admin-b"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if got, err := s.GetBaselineMode(ctx); err != nil || got.GetMode() != blockMode || got.GetRevision() != 1 {
			t.Fatalf("baseline mode after a policy Set = (%v, %v), want BLOCK at revision 1", got, err)
		}
	})
}
