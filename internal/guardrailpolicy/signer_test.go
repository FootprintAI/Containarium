package guardrailpolicy

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var aaID = strings.Repeat("a", 64)

func testKey(seed byte) ed25519.PublicKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
}

func signerOf(pub ed25519.PublicKey, label string) *pb.GuardrailTrustedSigner {
	return &pb.GuardrailTrustedSigner{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: label}
}

func configured(rev int64, signers []*pb.GuardrailTrustedSigner, revoked []*pb.GuardrailRevokedKey) *pb.GetGuardrailPolicyResponse {
	return &pb.GetGuardrailPolicyResponse{Configured: true, Policy: &pb.ServerGuardrailPolicy{
		Policy:         guardrail.DefaultPolicy(),
		TrustedSigners: signers,
		RevokedSigners: revoked,
		Revision:       rev,
	}}
}

func TestRotateRequest(t *testing.T) {
	oldK, newK := testKey(1), testKey(2)
	tests := []struct {
		name    string
		cur     *pb.GetGuardrailPolicyResponse
		add     ed25519.PublicKey
		wantIDs []string
		wantErr string
	}{
		{"adds beside the old key", configured(3, []*pb.GuardrailTrustedSigner{signerOf(oldK, "old")}, nil), newK,
			[]string{guardrail.KeyID(oldK), guardrail.KeyID(newK)}, ""},
		{"adding an already trusted key is refused", configured(3, []*pb.GuardrailTrustedSigner{signerOf(oldK, "old")}, nil), oldK, nil, "already trusted"},
		{"adding a revoked key is refused", configured(3, nil, []*pb.GuardrailRevokedKey{{KeyId: guardrail.KeyID(newK), Reason: "stolen"}}), newK, nil, "revoked"},
		{"no policy configured", &pb.GetGuardrailPolicyResponse{}, newK, nil, "no guardrail policy"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := RotateRequest(tc.cur, tc.add, "new")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, s := range req.GetTrustedSigners() {
				got = append(got, s.GetKeyId())
			}
			if strings.Join(got, ",") != strings.Join(tc.wantIDs, ",") {
				t.Errorf("signers = %v, want %v", got, tc.wantIDs)
			}
			if req.ExpectedRevision == nil || *req.ExpectedRevision != tc.cur.GetPolicy().GetRevision() {
				t.Errorf("expected_revision = %v, want %d", req.ExpectedRevision, tc.cur.GetPolicy().GetRevision())
			}
			if !proto.Equal(req.GetPolicy(), tc.cur.GetPolicy().GetPolicy()) {
				t.Error("rules changed by a signer rotation")
			}
			if err := ValidateSetRequest(req); err != nil {
				t.Errorf("request does not validate: %v", err)
			}
		})
	}
}

func TestRevokeRequest(t *testing.T) {
	oldK, newK := testKey(1), testKey(2)
	oldID := guardrail.KeyID(oldK)
	cur := configured(5, []*pb.GuardrailTrustedSigner{signerOf(oldK, "old"), signerOf(newK, "new")},
		[]*pb.GuardrailRevokedKey{{KeyId: aaID, Reason: "earlier"}})
	tests := []struct {
		name, keyID, reason, wantErr string
		wantTrusted                  int
	}{
		{"trusted key is revoked and dropped from signers", oldID, "laptop lost", "", 1},
		{"untrusted key can still be revoked", guardrail.KeyID(testKey(9)), "seen leaked", "", 2},
		{"reason is required", oldID, " ", "reason", 0},
		{"key id must be sha256 hex", "nothex", "x", "key id", 0},
		{"already revoked", aaID, "again", "already revoked", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "already revoked" {
				cur2 := configured(5, nil, []*pb.GuardrailRevokedKey{{KeyId: oldID, Reason: "earlier"}})
				_, err := RevokeRequest(cur2, oldID, "again")
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			req, err := RevokeRequest(cur, tc.keyID, tc.reason)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(req.GetTrustedSigners()) != tc.wantTrusted {
				t.Errorf("trusted = %d, want %d", len(req.GetTrustedSigners()), tc.wantTrusted)
			}
			if len(req.GetRevokedSigners()) != 2 || req.GetRevokedSigners()[0].GetKeyId() != aaID {
				t.Errorf("revoked = %v, want the stored entry kept plus the new one", req.GetRevokedSigners())
			}
			if *req.ExpectedRevision != 5 {
				t.Errorf("expected_revision = %d, want 5", *req.ExpectedRevision)
			}
			if err := ValidateSetRequest(req); err != nil {
				t.Errorf("request does not validate: %v", err)
			}
		})
	}
}

func TestBundleOf(t *testing.T) {
	k := testKey(1)
	p := configured(2, []*pb.GuardrailTrustedSigner{signerOf(k, "a")}, []*pb.GuardrailRevokedKey{{KeyId: "bb", Reason: "r"}}).GetPolicy()
	b := BundleOf(p)
	if len(b.GetSigners()) != 1 || len(b.GetRevoked()) != 1 || b.GetRevoked()[0].GetKeyId() != "bb" {
		t.Fatalf("bundle = %v", b)
	}
	b.Signers[0].Label = "mutated"
	if p.GetTrustedSigners()[0].GetLabel() != "a" {
		t.Error("bundle aliases the policy")
	}
}
