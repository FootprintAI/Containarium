package guardrailpolicy

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Describe renders a GetGuardrailPolicyResponse for a person: the text the
// `guardrail policy get` CLI prints and the MCP tool returns. Signers are
// shown by key id and label, never by key bytes.
func Describe(resp *pb.GetGuardrailPolicyResponse) string {
	if !resp.GetConfigured() {
		return "Guardrail policy: not configured (no server policy has been set; ungated deploys are unaffected)\n"
	}
	p := resp.GetPolicy()
	var b strings.Builder
	fmt.Fprintf(&b, "Revision:     %d\n", p.GetRevision())
	fmt.Fprintf(&b, "Policy hash:  %s\n", resp.GetPolicyHash())
	if p.GetUpdatedAt() != nil {
		fmt.Fprintf(&b, "Updated:      %s by %s\n", p.GetUpdatedAt().AsTime().Format(time.RFC3339), p.GetUpdatedBy())
	}
	rules := p.GetPolicy().GetRules()
	fmt.Fprintf(&b, "Rules (%d):\n", len(rules))
	for _, r := range rules {
		fmt.Fprintf(&b, "  %-8s %-8s max_residual=%d\n",
			strings.TrimPrefix(r.GetKind().String(), "GUARDRAIL_KIND_"),
			strings.TrimPrefix(r.GetAction().String(), "GUARDRAIL_ACTION_"),
			r.GetMaxResidual())
	}
	signers := p.GetTrustedSigners()
	fmt.Fprintf(&b, "Trusted signers (%d):\n", len(signers))
	for _, s := range signers {
		fmt.Fprintf(&b, "  %s  %s\n", s.GetKeyId(), s.GetLabel())
	}
	if revoked := p.GetRevokedSigners(); len(revoked) > 0 {
		fmt.Fprintf(&b, "Revoked keys (%d):\n", len(revoked))
		for _, r := range revoked {
			fmt.Fprintf(&b, "  %s  revoked %s: %s\n", r.GetKeyId(), r.GetRevokedAt().AsTime().UTC().Format(time.RFC3339), r.GetReason())
		}
	}
	return b.String()
}
