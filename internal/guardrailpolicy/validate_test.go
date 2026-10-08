package guardrailpolicy_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailpolicy/storetest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestValidate(t *testing.T) {
	good := storetest.Signer(t, 1, "release key")
	other := storetest.Signer(t, 2, "other key")
	mismatched := &pb.GuardrailTrustedSigner{KeyId: other.GetKeyId(), PublicKey: good.GetPublicKey(), Label: "mismatch"}
	shortKey := &pb.GuardrailTrustedSigner{KeyId: good.GetKeyId(), PublicKey: good.GetPublicKey()[:16]}

	rule := func(k pb.GuardrailKind, a pb.GuardrailAction, max int32) *pb.GuardrailRule {
		return &pb.GuardrailRule{Kind: k, Action: a, MaxResidual: max}
	}
	const (
		pii    = pb.GuardrailKind_GUARDRAIL_KIND_PII
		secret = pb.GuardrailKind_GUARDRAIL_KIND_SECRET
		redact = pb.GuardrailAction_GUARDRAIL_ACTION_REDACT
		block  = pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK
	)

	cases := []struct {
		name    string
		policy  *pb.GuardrailPolicy
		signers []*pb.GuardrailTrustedSigner
		wantErr string // substring; empty = valid
	}{
		{name: "valid policy with signers", policy: storetest.Policy(1), signers: []*pb.GuardrailTrustedSigner{good, other}},
		{name: "empty rule list is valid", policy: &pb.GuardrailPolicy{}},
		{name: "missing policy", policy: nil, wantErr: "policy is required"},
		{name: "unspecified kind", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pb.GuardrailKind_GUARDRAIL_KIND_UNSPECIFIED, redact, 0)}}, wantErr: "kind"},
		{name: "unknown kind value", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pb.GuardrailKind(99), redact, 0)}}, wantErr: "kind"},
		{name: "unspecified action", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, pb.GuardrailAction_GUARDRAIL_ACTION_UNSPECIFIED, 0)}}, wantErr: "action"},
		{name: "unknown action value", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, pb.GuardrailAction(42), 0)}}, wantErr: "action"},
		{name: "duplicate kind", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, redact, 0), rule(secret, block, 0), rule(pii, block, 0)}}, wantErr: "duplicate"},
		{name: "negative residual", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, redact, -1)}}, wantErr: "max_residual"},
		{name: "nil rule", policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{nil}}, wantErr: "kind"},
		{name: "signer key_id does not match its key", policy: storetest.Policy(0), signers: []*pb.GuardrailTrustedSigner{good, mismatched}, wantErr: "key_id"},
		{name: "signer key is not ed25519-sized", policy: storetest.Policy(0), signers: []*pb.GuardrailTrustedSigner{shortKey}, wantErr: "public_key"},
		{name: "nil signer", policy: storetest.Policy(0), signers: []*pb.GuardrailTrustedSigner{nil}, wantErr: "public_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := guardrailpolicy.Validate(tc.policy, tc.signers)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestParseSetRequest: the CLI's --file format is the protojson of
// SetGuardrailPolicyRequest, with enum names, and an unknown field is an
// error rather than silently dropped (a typo must not weaken a policy).
func TestParseSetRequest(t *testing.T) {
	good := storetest.Signer(t, 1, "release key")
	ok := `{"policy":{"rules":[{"kind":"GUARDRAIL_KIND_PII","action":"GUARDRAIL_ACTION_REDACT","maxResidual":1}]},` +
		`"trustedSigners":[{"keyId":"` + good.GetKeyId() + `","publicKey":"` + b64(good.GetPublicKey()) + `","label":"release key"}]}`
	req, err := guardrailpolicy.ParseSetRequest([]byte(ok))
	if err != nil {
		t.Fatalf("ParseSetRequest(valid) = %v", err)
	}
	if got := req.GetPolicy().GetRules()[0].GetKind(); got != pb.GuardrailKind_GUARDRAIL_KIND_PII {
		t.Fatalf("kind = %v, want PII", got)
	}
	if req.GetTrustedSigners()[0].GetKeyId() != good.GetKeyId() {
		t.Fatalf("signer key_id not decoded")
	}

	for name, in := range map[string]string{
		"unknown field": `{"policy":{"rules":[]},"policyy":{}}`,
		"not json":      `rules: []`,
	} {
		if _, err := guardrailpolicy.ParseSetRequest([]byte(in)); err == nil {
			t.Errorf("ParseSetRequest(%s) = nil, want an error", name)
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
