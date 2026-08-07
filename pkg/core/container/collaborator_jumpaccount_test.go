package container

import "testing"

// TestCollaboratorJumpAccountContainer pins the #1140 mapping: a collaborator
// jump account "<owner>-container-<collab>" resolves to the owner container
// "<owner>-container", while a bare owner account (or any non-collaborator
// name) reports false so the caller falls back to "<name>-container".
func TestCollaboratorJumpAccountContainer(t *testing.T) {
	tests := []struct {
		name   string
		jump   string
		wantC  string
		wantOK bool
	}{
		{"machine principal", "cld-9c675c0e-container-mb42419a2", "cld-9c675c0e-container", true},
		{"human collaborator", "cld-abc12345-container-ubob", "cld-abc12345-container", true},
		{"bare owner account is not a collaborator", "cld-9c675c0e", "", false},
		{"plain username, no infix", "randomuser", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := CollaboratorJumpAccountContainer(tt.jump)
			if ok != tt.wantOK || c != tt.wantC {
				t.Errorf("CollaboratorJumpAccountContainer(%q) = (%q, %v), want (%q, %v)", tt.jump, c, ok, tt.wantC, tt.wantOK)
			}
		})
	}
}

// TestCollaboratorJumpAccountContainer_MatchesAddCollaboratorNaming guards the
// invariant against the naming in AddCollaborator: accountName =
// (ownerUsername + "-container") + "-" + collaboratorUsername must map back to
// (ownerUsername + "-container").
func TestCollaboratorJumpAccountContainer_MatchesAddCollaboratorNaming(t *testing.T) {
	owner := "cld-9c675c0e"
	collab := "mb42419a2"
	containerName := owner + "-container"
	accountName := containerName + "-" + collab

	got, ok := CollaboratorJumpAccountContainer(accountName)
	if !ok || got != containerName {
		t.Fatalf("mapping = (%q,%v), want (%q,true)", got, ok, containerName)
	}
}
