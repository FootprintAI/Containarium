package runner

import (
	"fmt"
	"regexp"
	"strings"
)

// Runner registration targets: a single repository, or a whole organization
// (#1217).
//
// A repo-scoped runner serves exactly one repository, so an org with N repos
// wanting shared CI capacity had to provision N separate pools — N times the
// boxes for the same throughput, each idle whenever its own repo is idle,
// which is the opposite of why a shared runner pool exists.
//
// The target's SHAPE selects the endpoint family, the way GitHub itself
// disambiguates: "owner/repo" is a repository, a bare "owner" is an
// organization. That keeps the CLI surface unchanged for every existing
// caller — no new flag to learn, and no flag to get wrong.

// Scope is what a runner is registered against.
type Scope int

const (
	// ScopeRepo registers against a single repository.
	ScopeRepo Scope = iota
	// ScopeOrg registers against an organization, so every repo in it can
	// use the runner.
	ScopeOrg
)

func (s Scope) String() string {
	if s == ScopeOrg {
		return "organization"
	}
	return "repository"
}

// Target is a parsed runner registration target.
type Target struct {
	Scope Scope
	Owner string // the org, or the repository's owner
	Name  string // the repository name; empty for ScopeOrg
}

var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	// repoPattern is kept as the two-segment form for the messages that
	// still speak in owner/repo terms.
	targetRepoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// ParseTarget reads "owner/repo" or a bare "owner".
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return Target{}, fmt.Errorf("target is required: either owner/repo for a single repository, or a bare owner for an organization")
	case targetRepoPattern.MatchString(s):
		owner, name, _ := strings.Cut(s, "/")
		return Target{Scope: ScopeRepo, Owner: owner, Name: name}, nil
	case ownerPattern.MatchString(s):
		return Target{Scope: ScopeOrg, Owner: s}, nil
	default:
		return Target{}, fmt.Errorf("target %q is neither owner/repo nor a bare organization name", s)
	}
}

// APIPath is the api.github.com path segment for this target's runner
// endpoints: "repos/<owner>/<repo>" or "orgs/<org>".
//
// Every runner endpoint differs only by this segment, so selecting it in one
// place is what keeps the two scopes from drifting apart.
func (t Target) APIPath() string {
	if t.Scope == ScopeOrg {
		return "orgs/" + t.Owner
	}
	return "repos/" + t.Owner + "/" + t.Name
}

// ConfigURL is the --url the runner registers itself against.
func (t Target) ConfigURL() string {
	if t.Scope == ScopeOrg {
		return "https://github.com/" + t.Owner
	}
	return "https://github.com/" + t.Owner + "/" + t.Name
}

// RequiredPATScope names the GitHub token scope this target needs.
//
// The scopes genuinely differ — an org target needs admin:org, not repo — and
// a repo-scoped token used against an org endpoint returns a bare 403 that
// says nothing about which scope is missing. Naming it is the difference
// between a one-line fix and an afternoon.
func (t Target) RequiredPATScope() string {
	if t.Scope == ScopeOrg {
		return "admin:org"
	}
	return "repo"
}

// String renders the target the way the user typed it.
func (t Target) String() string {
	if t.Scope == ScopeOrg {
		return t.Owner
	}
	return t.Owner + "/" + t.Name
}

// scopeHint turns an authorization failure into one that names the scope the
// target actually needs.
func (t Target) scopeHint(status int) string {
	if status != 403 && status != 401 {
		return ""
	}
	return fmt.Sprintf(" — this is an %s target, which needs a token with the %q scope (a %q-scoped token returns exactly this)",
		t.Scope, t.RequiredPATScope(), "repo")
}
