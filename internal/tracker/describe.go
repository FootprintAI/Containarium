package tracker

import (
	"context"
	"errors"
	"time"
)

// Conn carries what a provider adapter needs to reach the tracker: base
// URL, project, and the resolved credential. Built per call and never
// stored or logged — see docs/architecture/agent-tracker-broker.md.
type Conn struct {
	// BaseURL is empty for the provider's SaaS endpoint (github.com /
	// gitlab.com), or set for GitHub Enterprise Server / self-managed
	// GitLab.
	BaseURL string
	// Project is "owner/repo" (GitHub) or "group/subgroup/project"
	// (GitLab). Unused by DescribeCredential today but carried here
	// since every other adapter verb (#1922) needs it and Conn is the
	// one seam constructed at every call site.
	Project string
	// Credential is the plaintext broker-only secret value, resolved via
	// CredentialSource immediately before the call.
	Credential string
}

// CredentialBreadth classifies a credential against the provider's
// preferred (narrowest) type — see the design note's "Preferred
// credential types" table. It bounds what a DAEMON compromise can do,
// as distinct from the broker's verb set, which bounds what a BOX can
// do.
type CredentialBreadth int

const (
	// BreadthUnspecified means breadth could not be determined — the
	// probe that would determine it failed (e.g. the tracker was
	// unreachable) before classification was possible.
	BreadthUnspecified CredentialBreadth = iota
	// BreadthPreferred is the narrowest type for the provider: a GitLab
	// project access token, or a GitHub App installation token /
	// single-repository fine-grained PAT.
	BreadthPreferred
	// BreadthBroad is anything wider: a GitLab group or personal access
	// token, or a GitHub classic PAT.
	BreadthBroad
)

func (b CredentialBreadth) String() string {
	switch b {
	case BreadthPreferred:
		return "preferred"
	case BreadthBroad:
		return "broad"
	default:
		return "unspecified"
	}
}

// CredentialInfo is what DescribeCredential reports about a tracker
// credential, asked of the upstream rather than the operator (both
// providers let a token describe itself).
type CredentialInfo struct {
	// Scopes are the provider-native scope/permission strings the
	// credential was granted. May be empty when the provider doesn't
	// expose them for this credential type (best-effort, not a
	// validity signal on its own).
	Scopes []string
	// ExpiresAt is when the credential expires. Zero means "no expiry,
	// or the provider doesn't report one for this credential type" —
	// callers must not treat zero as "never expires" for alerting
	// purposes without checking which case applies.
	ExpiresAt time.Time
	// Breadth classifies the credential against the provider's
	// preferred type. BreadthUnspecified if classification itself
	// requires a probe that failed.
	Breadth CredentialBreadth
}

// ErrCredentialInvalid is returned by DescribeCredential when the
// upstream is reachable but rejects the credential (401/403) — as
// distinct from a network-level failure (ErrUnreachable). Callers use
// this split to report "reachable" and "credential_valid" as the two
// separate booleans the design note's tracker status asks for.
var ErrCredentialInvalid = errors.New("tracker: credential rejected by provider")

// ErrUnreachable is returned by DescribeCredential when the upstream
// could not be reached at all (DNS, connect, TLS, timeout) — before any
// credential was ever presented, so nothing can be said about its
// validity.
var ErrUnreachable = errors.New("tracker: upstream unreachable")

// CredentialDescriber is satisfied by each provider adapter
// (internal/tracker/github, internal/tracker/gitlab). Split out from the
// full Provider interface (#1922 — GetIssue, Comment, OpenChange, …)
// because #1921 needs only this one verb: it backs `tracker connect`'s
// best-effort expiry population and `tracker status`'s live check.
type CredentialDescriber interface {
	DescribeCredential(ctx context.Context, conn Conn) (CredentialInfo, error)
}
