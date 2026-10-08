package cmd

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `guardrail apply` and `guardrail verify` read the server-side guardrail
// policy (#2368; docs/architecture/guardrail-inbound-and-server-policy.md,
// "CLI").
//
// This deliberately reverses a stated property of the guardrail CLI: before
// #2368 every guardrail verb was local and none talked to the daemon. Now
// apply and verify contact the platform for ONE thing only, a read of the
// policy (GetGuardrailPolicy, carrying the caller's credentials). No dataset
// content, finding, vault entry, attestation or key ever leaves the machine;
// verify checks the attestation locally against the policy and signers it
// read. What changes is that the *policy* now originates on the platform.
//
// The rule for when they contact a server:
//
//   - Only when a server is named EXPLICITLY for this invocation: the
//     --server flag or CONTAINARIUM_SERVER. A login's default_server
//     (credentials.json) does not count: logging in does not make these two
//     commands contact the platform. With no explicit server they run in
//     local mode exactly as before #2368, labelled NOT server-attested /
//     NOT server-trusted.
//   - With an explicit server there is no silent fallback: unreachable, a
//     TLS or certificate failure, UNAVAILABLE, a 5xx, a timeout,
//     unauthenticated, a store read error are all errors (non-zero exit).
//     The one local outcome is an authenticated answer that the server has
//     no policy configured; that result is labelled NOT server-attested.

// guardrailServerView is what apply/verify learned from the daemon.
type guardrailServerView struct {
	// policy is the server's policy, or nil in local mode.
	policy *pb.ServerGuardrailPolicy
	// hash is policy_hash of policy.policy; "" in local mode.
	hash string
	// localReason says why this run is in local mode; "" when a server
	// policy is in force.
	localReason string
}

// fetchGuardrailServerView applies the rule above.
func fetchGuardrailServerView() (*guardrailServerView, error) {
	if explicitServerAddr == "" {
		return &guardrailServerView{localReason: "no server named (--server or CONTAINARIUM_SERVER; a login's default server does not count)"}, nil
	}
	api, done, err := newGuardrailPolicyAPI()
	if err != nil {
		return nil, fmt.Errorf("read server guardrail policy from %s: %w (an explicitly named server is never skipped; omit --server to run locally)", explicitServerAddr, err)
	}
	defer done()
	resp, err := api.GetGuardrailPolicy()
	if err != nil {
		return nil, fmt.Errorf("read server guardrail policy from %s: %w (an explicitly named server is never skipped; omit --server to run locally)", explicitServerAddr, err)
	}
	if !resp.GetConfigured() {
		return &guardrailServerView{localReason: "the server has no guardrail policy configured"}, nil
	}
	hash, err := guardrailpolicy.Hash(resp.GetPolicy())
	if err != nil {
		return nil, err
	}
	if resp.GetPolicyHash() != "" && resp.GetPolicyHash() != hash {
		return nil, fmt.Errorf("server guardrail policy: reported hash %s is not the hash of the policy it sent (%s)", resp.GetPolicyHash(), hash)
	}
	return &guardrailServerView{policy: resp.GetPolicy(), hash: hash}, nil
}

// warnIfNotTrustedSigner tells an apply under a server policy, on stderr,
// that its attestation will not be server-trusted: unsigned, or signed by a
// key the server does not trust. Key id prefixes only, never key bytes.
func warnIfNotTrustedSigner(cmd *cobra.Command, server *pb.ServerGuardrailPolicy, signKey ed25519.PrivateKey) {
	var trusted []string
	for _, s := range server.GetTrustedSigners() {
		trusted = append(trusted, shortGuardrailHash(s.GetKeyId()))
	}
	names := strings.Join(trusted, ", ")
	if names == "" {
		names = "none"
	}
	if signKey == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "guardrail: no --sign-key: the attestation is unsigned, so verify and a gated deploy will refuse it (server trusted signers: %s)\n", names)
		return
	}
	id := guardrail.KeyID(signKey.Public().(ed25519.PublicKey))
	for _, s := range server.GetTrustedSigners() {
		if s.GetKeyId() == id {
			return
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "guardrail: --sign-key %s is not one of the server's trusted signers (%s); verify and a gated deploy will refuse this attestation\n", shortGuardrailHash(id), names)
}

func shortGuardrailHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
