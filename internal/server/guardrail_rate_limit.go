package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrailrate"
)

// Rate limits on the guardrail APIs (#2404). Each is per authenticated
// subject; a nil limiter is disabled.

// GuardrailRateLimits is the daemon's configuration for them (flags
// --guardrail-*-rate-per-minute / --guardrail-*-burst). A zero Limit is
// disabled.
type GuardrailRateLimits struct {
	Deploy    guardrailrate.Limit // gated DeployRecipe
	PolicySet guardrailrate.Limit // GuardrailPolicyService.Set
	PolicyGet guardrailrate.Limit // GuardrailPolicyService.Get (incl. guardrail apply/verify's read)
}

// SetGuardrailDeployRateLimit limits gated deploys per subject. Startup only.
func (s *RecipeServer) SetGuardrailDeployRateLimit(l *guardrailrate.Limiter) {
	s.guardrailDeployLimit = l
}

// SetRateLimits limits Set and Get per subject. Startup only.
func (s *GuardrailPolicyServer) SetRateLimits(set, get *guardrailrate.Limiter) {
	s.setLimit, s.getLimit = set, get
}

// checkGuardrailRate charges the caller's subject one token on l. Callers
// run it after authentication and before any work.
func checkGuardrailRate(ctx context.Context, l *guardrailrate.Limiter) error {
	if !l.Enabled() {
		return nil
	}
	subject, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	return l.Check(subject)
}
