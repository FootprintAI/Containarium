package guardrailpolicy

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Validate is the check Set runs before storing: every rule has a defined,
// non-UNSPECIFIED kind and action, no kind appears twice, max_residual is not
// negative, and every signer carries a 32-byte Ed25519 key whose SHA-256 is
// its key_id. A nil policy is refused so a malformed request cannot clear
// the rules by omission; an empty rule list is a valid, deliberate policy.
func Validate(policy *pb.GuardrailPolicy, signers []*pb.GuardrailTrustedSigner) error {
	if policy == nil {
		return fmt.Errorf("policy is required (an empty rule list clears the rules)")
	}
	seen := make(map[pb.GuardrailKind]bool, len(policy.GetRules()))
	for i, r := range policy.GetRules() {
		k, a := r.GetKind(), r.GetAction()
		if k == pb.GuardrailKind_GUARDRAIL_KIND_UNSPECIFIED || !definedKind(k) {
			return fmt.Errorf("rule %d: kind %v is not a valid guardrail kind", i, k)
		}
		if a == pb.GuardrailAction_GUARDRAIL_ACTION_UNSPECIFIED || !definedAction(a) {
			return fmt.Errorf("rule %d (%v): action %v is not a valid guardrail action", i, k, a)
		}
		if seen[k] {
			return fmt.Errorf("rule %d: duplicate kind %v", i, k)
		}
		seen[k] = true
		if r.GetMaxResidual() < 0 {
			return fmt.Errorf("rule %d (%v): max_residual %d is negative", i, k, r.GetMaxResidual())
		}
	}
	for i, s := range signers {
		pub := s.GetPublicKey()
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted signer %d: public_key is %d bytes, want an Ed25519 key of %d", i, len(pub), ed25519.PublicKeySize)
		}
		if want := guardrail.KeyID(ed25519.PublicKey(pub)); s.GetKeyId() != want {
			return fmt.Errorf("trusted signer %d (%q): key_id is not the SHA-256 of its public_key", i, s.GetLabel())
		}
	}
	return nil
}

// ValidateSetRequest is Validate plus the revoked keys (#2729): each has a
// key_id of 64 lowercase hex characters and a reason, appears once, and is
// not also a trusted signer. Whether the request keeps every stored
// revocation is CheckTransition's job, under the store's lock.
func ValidateSetRequest(req *pb.SetGuardrailPolicyRequest) error {
	if err := Validate(req.GetPolicy(), req.GetTrustedSigners()); err != nil {
		return err
	}
	revoked := make(map[string]bool, len(req.GetRevokedSigners()))
	for i, r := range req.GetRevokedSigners() {
		if !keyIDPattern.MatchString(r.GetKeyId()) {
			return fmt.Errorf("revoked key %d: key_id %q is not 64 lowercase hex characters (a SHA-256)", i, r.GetKeyId())
		}
		if strings.TrimSpace(r.GetReason()) == "" {
			return fmt.Errorf("revoked key %d (%s): a reason is required", i, r.GetKeyId())
		}
		if revoked[r.GetKeyId()] {
			return fmt.Errorf("revoked key %d: %s is revoked twice", i, r.GetKeyId())
		}
		revoked[r.GetKeyId()] = true
	}
	for i, s := range req.GetTrustedSigners() {
		if revoked[s.GetKeyId()] {
			return fmt.Errorf("trusted signer %d (%q): key %s is revoked and cannot be trusted again", i, s.GetLabel(), s.GetKeyId())
		}
	}
	return nil
}

var keyIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func definedKind(k pb.GuardrailKind) bool {
	return k.Descriptor().Values().ByNumber(k.Number()) != nil
}

func definedAction(a pb.GuardrailAction) bool {
	return a.Descriptor().Values().ByNumber(a.Number()) != nil
}

// ParseSetRequest decodes the `guardrail policy set --file` format: the
// protojson encoding of SetGuardrailPolicyRequest. Unknown fields are an
// error, so a misspelt field cannot silently drop part of a policy.
func ParseSetRequest(data []byte) (*pb.SetGuardrailPolicyRequest, error) {
	req := &pb.SetGuardrailPolicyRequest{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, req); err != nil {
		return nil, fmt.Errorf("parse guardrail policy file: %w", err)
	}
	return req, nil
}
