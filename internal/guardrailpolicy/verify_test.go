package guardrailpolicy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// verifyFixture is a dataset directory, a server policy that trusts one
// signer, and an attestation that signer made over the directory under the
// server's policy: everything VerifyAttestation accepts. Each test case
// breaks exactly one part of it.
type verifyFixture struct {
	dir    string
	server *pb.ServerGuardrailPolicy
	priv   ed25519.PrivateKey
	att    *pb.GuardrailAttestation
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("clean text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT},
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_ALLOW},
	}}
	server := &pb.ServerGuardrailPolicy{
		Policy:         policy,
		TrustedSigners: []*pb.GuardrailTrustedSigner{{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: "release key"}},
		Revision:       3,
	}
	f := &verifyFixture{dir: dir, server: server, priv: priv}
	f.att = f.attest(t, policy, guardrail.KindsFor(policy), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, priv)
	return f
}

func (f *verifyFixture) attest(t *testing.T, policy *pb.GuardrailPolicy, kinds []pb.GuardrailKind, verdict pb.GuardrailVerdict, priv ed25519.PrivateKey) *pb.GuardrailAttestation {
	t.Helper()
	digest, err := guardrail.SubjectDigest(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := guardrail.PolicyHash(policy)
	if err != nil {
		t.Fatal(err)
	}
	att := &pb.GuardrailAttestation{SubjectSha256: digest, PolicyHash: hash, Verdict: verdict, KindsScanned: kinds}
	if err := guardrail.Sign(att, priv); err != nil {
		t.Fatal(err)
	}
	return att
}

func TestVerifyAttestation(t *testing.T) {
	pii := pb.GuardrailKind_GUARDRAIL_KIND_PII
	secret := pb.GuardrailKind_GUARDRAIL_KIND_SECRET
	cases := []struct {
		name    string
		mutate  func(t *testing.T, f *verifyFixture) []pb.GuardrailKind // returns require_kinds
		wantErr error
	}{
		{name: "pass", mutate: func(*testing.T, *verifyFixture) []pb.GuardrailKind { return nil }},
		{name: "pass with a require kind the policy covers", mutate: func(*testing.T, *verifyFixture) []pb.GuardrailKind { return []pb.GuardrailKind{pii} }},
		{name: "no server policy", wantErr: guardrailpolicy.ErrNoServerPolicy, mutate: func(_ *testing.T, f *verifyFixture) []pb.GuardrailKind {
			f.server = nil
			return nil
		}},
		{name: "no trusted signer", wantErr: guardrailpolicy.ErrNoTrustedSigner, mutate: func(_ *testing.T, f *verifyFixture) []pb.GuardrailKind {
			f.server.TrustedSigners = nil
			return nil
		}},
		{name: "untrusted signer", wantErr: guardrailpolicy.ErrUntrustedSigner, mutate: func(t *testing.T, f *verifyFixture) []pb.GuardrailKind {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.att = f.attest(t, f.server.GetPolicy(), f.att.GetKindsScanned(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, other)
			return nil
		}},
		{name: "signature does not verify", wantErr: guardrail.ErrBadSignature, mutate: func(_ *testing.T, f *verifyFixture) []pb.GuardrailKind {
			f.att.Residual = []*pb.GuardrailKindCount{{Kind: pii, Findings: 9}} // changed after signing
			return nil
		}},
		{name: "wrong policy hash", wantErr: guardrailpolicy.ErrPolicyMismatch, mutate: func(t *testing.T, f *verifyFixture) []pb.GuardrailKind {
			f.att = f.attest(t, guardrail.DefaultPolicy(), []pb.GuardrailKind{pii, secret}, pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, f.priv)
			return nil
		}},
		{name: "FAIL verdict", wantErr: guardrailpolicy.ErrVerdictNotPass, mutate: func(t *testing.T, f *verifyFixture) []pb.GuardrailKind {
			f.att = f.attest(t, f.server.GetPolicy(), f.att.GetKindsScanned(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL, f.priv)
			return nil
		}},
		{name: "policy kind not scanned", wantErr: guardrailpolicy.ErrKindNotCovered, mutate: func(t *testing.T, f *verifyFixture) []pb.GuardrailKind {
			f.att = f.attest(t, f.server.GetPolicy(), nil, pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, f.priv)
			return nil
		}},
		{name: "require kind not scanned", wantErr: guardrailpolicy.ErrKindNotCovered, mutate: func(*testing.T, *verifyFixture) []pb.GuardrailKind {
			return []pb.GuardrailKind{secret} // the policy ALLOWs secrets, so they were never scanned
		}},
		{name: "tampered byte", wantErr: guardrailpolicy.ErrDigestMismatch, mutate: func(t *testing.T, f *verifyFixture) []pb.GuardrailKind {
			if err := os.WriteFile(filepath.Join(f.dir, "a.txt"), []byte("clean tExt\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerifyFixture(t)
			require := tc.mutate(t, f)
			signer, err := guardrailpolicy.VerifyAttestation(f.att, f.server, f.dir, require)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want pass, got %v", err)
				}
				if signer.GetLabel() != "release key" {
					t.Errorf("signer = %v, want the trusted release key", signer)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// The server policy and attestation are inputs, never outputs: a verify
// must not change either.
func TestVerifyAttestation_DoesNotMutateInputs(t *testing.T) {
	f := newVerifyFixture(t)
	att, server := proto.Clone(f.att), proto.Clone(f.server)
	if _, err := guardrailpolicy.VerifyAttestation(f.att, f.server, f.dir, nil); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(att, f.att) || !proto.Equal(server, f.server) {
		t.Fatal("VerifyAttestation changed its inputs")
	}
}
