package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func keygenPrefix(t *testing.T) (prefix, keyID string) {
	t.Helper()
	prefix = filepath.Join(t.TempDir(), "k")
	if o, err := runGuardrail(t, "keygen", "--out", prefix); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}
	pub, err := guardrail.LoadPublicKey(prefix + ".pub")
	must(t, err)
	return prefix, guardrail.KeyID(pub)
}

func TestGuardrailSigner_RotateRevokeBundle(t *testing.T) {
	fake := withFakeGuardrailPolicyAPI(t)
	oldP, oldID := keygenPrefix(t)
	newP, newID := keygenPrefix(t)
	setServerPolicy(t, fake, piiOnlyPolicy(), oldP)

	// not configured is an error, not a silent no-op
	t.Run("rotate adds the new key and keeps the old", func(t *testing.T) {
		o, err := runGuardrailAt(t, "signer", "rotate", "--add", newP+".pub", "--label", "2026-q4")
		if err != nil {
			t.Fatalf("rotate: %v\n%s", err, o)
		}
		last := fake.sets[len(fake.sets)-1]
		if last.ExpectedRevision == nil || *last.ExpectedRevision != 1 {
			t.Errorf("expected_revision = %v, want 1", last.ExpectedRevision)
		}
		if len(last.GetTrustedSigners()) != 2 || !strings.Contains(o, "revision 2") {
			t.Errorf("signers=%d out=%q", len(last.GetTrustedSigners()), o)
		}
	})
	t.Run("revoke is permanent and drops the trusted entry", func(t *testing.T) {
		o, err := runGuardrailAt(t, "signer", "revoke", oldID, "--reason", "laptop lost")
		if err != nil {
			t.Fatalf("revoke: %v\n%s", err, o)
		}
		cur, _ := fake.GetGuardrailPolicy()
		p := cur.GetPolicy()
		if len(p.GetTrustedSigners()) != 1 || p.GetTrustedSigners()[0].GetKeyId() != newID {
			t.Errorf("trusted = %v, want only the new key", p.GetTrustedSigners())
		}
		if len(p.GetRevokedSigners()) != 1 || p.GetRevokedSigners()[0].GetKeyId() != oldID || p.GetRevokedSigners()[0].GetRevokedAt() == nil {
			t.Errorf("revoked = %v", p.GetRevokedSigners())
		}
		if _, err := runGuardrailAt(t, "signer", "revoke", oldID, "--reason", "again"); err == nil {
			t.Error("revoking twice succeeded")
		}
	})
	t.Run("revoke without a reason is refused before any call", func(t *testing.T) {
		n := len(fake.sets)
		if _, err := runGuardrailAt(t, "signer", "revoke", newID); err == nil || len(fake.sets) != n {
			t.Errorf("err=%v sets %d->%d", err, n, len(fake.sets))
		}
	})
	t.Run("bundle prints protojson of signers and revoked", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "bundle.json")
		if o, err := runGuardrailAt(t, "signer", "bundle", "--out", out); err != nil {
			t.Fatalf("bundle: %v\n%s", err, o)
		}
		b, err := os.ReadFile(out)
		must(t, err)
		var bundle pb.GuardrailTrustBundle
		must(t, protojson.Unmarshal(b, &bundle))
		if len(bundle.GetSigners()) != 1 || len(bundle.GetRevoked()) != 1 {
			t.Errorf("bundle = %v", &bundle)
		}
	})
}

func TestGuardrailSigner_StaleRevisionIsNotOverwritten(t *testing.T) {
	fake := withFakeGuardrailPolicyAPI(t)
	oldP, _ := keygenPrefix(t)
	newP, _ := keygenPrefix(t)
	setServerPolicy(t, fake, piiOnlyPolicy(), oldP)
	racing := &racingPolicyAPI{fakeGuardrailPolicyAPI: fake}
	newGuardrailPolicyAPI = func() (guardrailPolicyAPI, func(), error) { return racing, func() {}, nil }
	_, err := runGuardrailAt(t, "signer", "rotate", "--add", newP+".pub")
	if err == nil {
		t.Fatal("rotate over a concurrent Set succeeded")
	}
	cur, _ := fake.GetGuardrailPolicy()
	if len(cur.GetPolicy().GetTrustedSigners()) != 1 {
		t.Error("the concurrent change was overwritten")
	}
}

// racingPolicyAPI lets another admin Set land between the CLI's read and write.
type racingPolicyAPI struct{ *fakeGuardrailPolicyAPI }

func (r *racingPolicyAPI) SetGuardrailPolicy(req *pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error) {
	cur, _ := r.GetGuardrailPolicy()
	other := guardrailpolicy.Clone(cur.GetPolicy())
	_, _ = r.store.Set(context.Background(), &pb.SetGuardrailPolicyRequest{Policy: other.GetPolicy(), TrustedSigners: other.GetTrustedSigners()}, "other-admin")
	return r.fakeGuardrailPolicyAPI.SetGuardrailPolicy(req)
}

func TestGuardrailVerify_TrustBundle(t *testing.T) {
	forbidGuardrailPolicyAPI(t)
	w := newGuardrailWork(t)
	if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
		t.Fatalf("apply: %v\n%s", err, o)
	}
	pub, err := guardrail.LoadPublicKey(w.keys + ".pub")
	must(t, err)
	trusted := &pb.GuardrailTrustedSigner{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: "k"}
	revoked := &pb.GuardrailRevokedKey{KeyId: guardrail.KeyID(pub), Reason: "laptop lost"}
	other := &pb.GuardrailTrustedSigner{KeyId: strings.Repeat("c", 64), PublicKey: make([]byte, 32), Label: "o"}

	tests := []struct {
		name    string
		bundle  *pb.GuardrailTrustBundle
		extra   []string
		wantErr string
	}{
		{"trusted key verifies", &pb.GuardrailTrustBundle{Signers: []*pb.GuardrailTrustedSigner{trusted}}, nil, ""},
		{"revoked key fails with key and reason", &pb.GuardrailTrustBundle{Signers: []*pb.GuardrailTrustedSigner{trusted}, Revoked: []*pb.GuardrailRevokedKey{revoked}}, nil, "laptop lost"},
		{"signer not in the bundle fails", &pb.GuardrailTrustBundle{Signers: []*pb.GuardrailTrustedSigner{other}}, nil, "trusted signer"},
		{"--public-key together is refused", &pb.GuardrailTrustBundle{Signers: []*pb.GuardrailTrustedSigner{trusted}}, []string{"--public-key", w.keys + ".pub"}, "mutually exclusive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := protojson.Marshal(tc.bundle)
			must(t, err)
			f := writePolicyFile(t, string(b))
			args := append([]string{"verify", w.out, "--attestation", w.attestationFile(), "--trust-bundle", f}, tc.extra...)
			o, err := runGuardrail(t, args...)
			if tc.wantErr == "" {
				if err != nil || !strings.Contains(o, "trust bundle") {
					t.Fatalf("verify = %v\n%s", err, o)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verify = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
