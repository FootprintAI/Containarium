package sdlcskills

import (
	"fmt"
	"sort"
	"strings"
)

// The skill-set contract between this binary and a skills release
// (docs/design/sdlc-skills-option-b.md).
//
// A skills release is built, signed and published outside this repository.
// What stays here is the part a daemon has to agree on with every release it
// may be handed: the manifest format it can read (ContractVersion) and the
// set ids a caller may ask for by name (KnownSetIDs). Which namespaces a set
// covers is the release's business and is read from its signed manifest.

// ContractVersion is the manifest contract this binary reads. A release may
// add manifest keys and skill sets without changing it; a change an older
// reader cannot safely ignore bumps it, and a reader refuses a manifest whose
// contract is higher than its own.
const ContractVersion = 1

// contractSetIDs are the set ids of ContractVersion, sorted.
var contractSetIDs = []string{"qa", "sdlc", "security"}

// KnownSetIDs returns the set ids a caller may select by name, sorted.
func KnownSetIDs() []string { return append([]string(nil), contractSetIDs...) }

// UnknownSetError is a requested set id outside the contract.
type UnknownSetError struct {
	ID    string
	Known []string
}

func (e *UnknownSetError) Error() string {
	return fmt.Sprintf("unknown skill set %q; known skill sets: %s", e.ID, strings.Join(e.Known, ", "))
}

// ValidateSetIDs checks every id against the contract. The first id outside
// it is an *UnknownSetError naming the known ids. The installer's "all" and
// "none" literals are not set ids.
func ValidateSetIDs(ids []string) error {
	for _, id := range ids {
		i := sort.SearchStrings(contractSetIDs, id)
		if i >= len(contractSetIDs) || contractSetIDs[i] != id {
			return &UnknownSetError{ID: id, Known: KnownSetIDs()}
		}
	}
	return nil
}

// ContractTooNewError is a manifest written for a later contract.
type ContractTooNewError struct {
	Got, Supported int
}

func (e *ContractTooNewError) Error() string {
	return fmt.Sprintf("sdlcskills: the skills release uses contract %d; this version supports contract %d (upgrade it, or use an earlier skills release)", e.Got, e.Supported)
}

// CheckContract reports whether a manifest of contract n can be read.
func CheckContract(n int) error {
	switch {
	case n < 1:
		return fmt.Errorf("sdlcskills: contract %d is not a contract version", n)
	case n > ContractVersion:
		return &ContractTooNewError{Got: n, Supported: ContractVersion}
	}
	return nil
}
