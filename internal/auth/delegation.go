package auth

import "fmt"

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
