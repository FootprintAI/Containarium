package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `guardrail apply` and `guardrail verify` read the server-side guardrail
// policy (#2368; docs/architecture/guardrail-inbound-and-server-policy.md,
// "CLI").
//
// This deliberately reverses a stated property of the guardrail CLI: before
// #2368 every guardrail verb was local and none talked to the daemon. Now
// apply and verify contact the platform, for ONE thing only: a read of the
// policy (GetGuardrailPolicy). No dataset content, finding, vault entry or
// key ever leaves the machine; apply sends nothing but that read, and verify
// checks the attestation locally against the policy and signers it fetched.
// What changes is that the *policy* now originates on the platform. An owner
// who must stay fully offline still can (no --server, or no reachable
// daemon); the result is then labelled not server-attested / not
// server-trusted.

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

// fetchGuardrailServerView reads the server policy. Local mode is chosen
// only when there is no daemon to ask (no --server) or the daemon cannot be
// reached at all, or it answers that no policy is configured. A daemon that
// answers with an error (its store unreadable, the caller unauthenticated)
// is an error: a read error is never treated as "no policy".
func fetchGuardrailServerView() (*guardrailServerView, error) {
	api, done, err := newGuardrailPolicyAPI()
	if errors.Is(err, errNoGuardrailServer) {
		return &guardrailServerView{localReason: "no --server configured"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read server guardrail policy: %w", err)
	}
	defer done()
	resp, err := api.GetGuardrailPolicy()
	if err != nil {
		if guardrailDaemonUnreachable(err) {
			return &guardrailServerView{localReason: fmt.Sprintf("daemon unreachable (%v)", err)}, nil
		}
		return nil, fmt.Errorf("read server guardrail policy: %w", err)
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

func shortGuardrailHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// guardrailDaemonUnreachable is true only for transport failures: gRPC
// UNAVAILABLE (connection refused, DNS failure) or an HTTP request that never
// got a response. Every status the daemon itself returns is not "unreachable".
func guardrailDaemonUnreachable(err error) bool {
	var st interface{ GRPCStatus() *status.Status }
	if errors.As(err, &st) {
		return st.GRPCStatus().Code() == codes.Unavailable
	}
	var uerr *url.Error
	var nerr *net.OpError
	return errors.As(err, &uerr) || errors.As(err, &nerr)
}
