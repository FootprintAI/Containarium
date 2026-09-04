package auth

import (
	"fmt"
	"strings"
)

// Actor is the RFC 8693 "act" (actor) claim: the principal that actually
// dispatched a token's mint, distinct from the token's own subject, when the
// token was minted on that principal's behalf rather than issued to them
// directly (#1677). An agent-box token's Username is the synthetic
// agent-<skill-id> subject; Act records the human/service that dispatched
// it, so an auditor asking "who authorized this?" doesn't get the name of a
// robot.
//
// Nested — not a flat on_behalf_of — so a token derived from an
// already-derived token wraps the chain instead of overwriting it: Act.Act
// is the actor that delegated to Act, and so on down to the root human
// principal at the base of the chain. See MaxActDepth for the bound on how
// deep that chain may go.
type Actor struct {
	Subject string `json:"sub"`
	Act     *Actor `json:"act,omitempty"`
}

// MaxActDepth bounds delegation-chain nesting. A chain exceeding it is
// rejected outright — at mint by GenerateDelegatedToken, and again at
// validation by ValidateToken as defense in depth against a token minted by
// a future/other code path that skips the mint-time check — never silently
// truncated. Truncation would drop exactly the human principal furthest
// from the leaf, which is the one an auditor most needs.
const MaxActDepth = 8

// actDepth counts a's chain length: a itself counts as 1, each nested Act
// adds 1, nil is 0.
func actDepth(a *Actor) int {
	d := 0
	for a != nil {
		d++
		a = a.Act
	}
	return d
}

// validateActDepth returns an error if a's chain exceeds MaxActDepth. A nil
// a (no delegation claim at all) always passes — absence is the
// backward-compatible, "unattributed" case, not a violation.
func validateActDepth(a *Actor) error {
	if d := actDepth(a); d > MaxActDepth {
		return fmt.Errorf("delegation chain depth %d exceeds max %d", d, MaxActDepth)
	}
	return nil
}

// RootActor walks a's chain to its base and returns that Subject — the
// human/service principal furthest from the leaf, which is the one an
// auditor most needs (#1678: this is how the audit package's `actor` column
// is resolved from a request's delegation claim). Returns "" for a nil
// chain, matching Actor's own "absence is valid, not an error" contract.
func RootActor(a *Actor) string {
	if a == nil {
		return ""
	}
	for a.Act != nil {
		a = a.Act
	}
	return a.Subject
}

// IntersectRoles returns the roles common to caller and requested.
//
// Deliberately NOT IntersectScopes with a different argument name. That
// function treats a nil caller as "no ceiling" and passes the requested set
// through unchanged, which is right for scopes — an absent scopes claim means
// unrestricted — and catastrophically wrong for roles, where it would let a
// caller holding no roles at all mint an admin token.
//
// Roles fail closed at every step here: no wildcard, and an empty result is a
// normal outcome rather than something to widen. HasRole finds nothing in an
// empty list, so a token minted with no roles simply cannot reach anything
// gated on one.
//
// Returns a non-nil empty slice rather than nil so callers can range over it
// without a check.
func IntersectRoles(caller, requested []string) []string {
	out := make([]string, 0, len(requested))
	if len(caller) == 0 || len(requested) == 0 {
		return out
	}
	held := make(map[string]struct{}, len(caller))
	for _, r := range caller {
		held[strings.TrimSpace(r)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(requested))
	for _, r := range requested {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		if _, ok := held[r]; ok {
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	return out
}
