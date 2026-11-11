// Package naming holds the one rule for tenant, owner and collaborator names.
//
// A collaborator's jump account is built as "<owner>-container-<collaborator>"
// and an owner's box is "<owner>-container". A name containing "-container-"
// or ending in "-container" can therefore make two different (owner,
// collaborator) pairs, or an owner and a collaborator account, produce the same
// string (#3630). The rule applies to NEW names only; existing names are
// reported by AuditNames and never renamed.
package naming

import (
	"fmt"
	"sort"
	"strings"
)

const (
	reservedInfix  = "-container-"
	reservedSuffix = "-container"
)

// CollaboratorPair is one (owner, collaborator) grant.
type CollaboratorPair struct {
	Owner        string
	Collaborator string
}

// Finding is one audit result.
type Finding struct {
	// Name is the offending name (or the colliding derived account name).
	Name string
	// Kind is "owner", "collaborator" or "account-collision".
	Kind   string
	Reason string
}

// ValidateTenantName rejects a name that contains the "-container-" infix or
// ends in "-container". It checks only this rule; character-set and length
// checks stay with the callers.
func ValidateTenantName(name string) error {
	if strings.Contains(name, reservedInfix) {
		return fmt.Errorf("name %q must not contain %q: it is the separator in collaborator account names", name, reservedInfix)
	}
	if strings.HasSuffix(name, reservedSuffix) {
		return fmt.Errorf("name %q must not end in %q: it would collide with the derived box name", name, reservedSuffix)
	}
	return nil
}

// AuditNames reports existing names that break the rule, plus collaborator
// account names that more than one (owner, collaborator) pair derives. It is
// pure: it reads its arguments and changes nothing.
func AuditNames(owners []string, collaborators []CollaboratorPair) []Finding {
	var out []Finding
	for _, o := range owners {
		if err := ValidateTenantName(o); err != nil {
			out = append(out, Finding{Name: o, Kind: "owner", Reason: err.Error()})
		}
	}
	derived := map[string][]CollaboratorPair{}
	for _, c := range collaborators {
		if err := ValidateTenantName(c.Collaborator); err != nil {
			out = append(out, Finding{Name: c.Collaborator, Kind: "collaborator", Reason: err.Error()})
		}
		acct := c.Owner + reservedSuffix + "-" + c.Collaborator
		derived[acct] = append(derived[acct], c)
	}
	accts := make([]string, 0, len(derived))
	for a, pairs := range derived {
		if len(pairs) > 1 {
			accts = append(accts, a)
		}
	}
	sort.Strings(accts)
	for _, a := range accts {
		out = append(out, Finding{Name: a, Kind: "account-collision",
			Reason: fmt.Sprintf("derived by %d different owner/collaborator pairs", len(derived[a]))})
	}
	return out
}
