package guardrailpolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// testSigner builds a valid trusted signer from a deterministic seed, so
// fixtures are synthetic and stable.
func testSigner(t *testing.T, seed byte, label string) *pb.GuardrailTrustedSigner {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	return &pb.GuardrailTrustedSigner{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: label}
}

func testPolicy(maxResidual int32) *pb.GuardrailPolicy {
	return &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT, MaxResidual: maxResidual},
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
	}}
}

// runStoreContract is the behaviour both implementations must share. The
// in-memory store runs it in the unit suite; the Postgres store runs it in
// the store-integration lane against a real database.
func runStoreContract(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()

	t.Run("not configured is the typed ErrNotConfigured", func(t *testing.T) {
		s := newStore(t)
		got, err := s.Get(ctx)
		if !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("Get on an empty store = (%v, %v), want ErrNotConfigured", got, err)
		}
	})

	t.Run("set then get round-trips", func(t *testing.T) {
		s := newStore(t)
		signer := testSigner(t, 1, "release key")
		res, err := s.Set(ctx, testPolicy(2), []*pb.GuardrailTrustedSigner{signer}, "admin-a")
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
		if !proto.Equal(got.GetPolicy(), testPolicy(2)) {
			t.Fatalf("policy = %v, want %v", got.GetPolicy(), testPolicy(2))
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
			res, err := s.Set(ctx, testPolicy(int32(want)), nil, "admin-a")
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
		res, err := s.Set(ctx, testPolicy(0), nil, "admin-a")
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
}

func TestMemoryStore_Contract(t *testing.T) {
	runStoreContract(t, func(*testing.T) Store { return NewMemoryStore() })
}
