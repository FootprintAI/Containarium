package container

import "testing"

// The collaborator creation validator shares pkg/core/naming's rule (#3630).
func TestCreationValidatorsRejectContainerNaming(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid", "owner-a", true},
		{"infix", "a-container-b", false},
		{"suffix", "a-container", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidCollaboratorUsername(tt.in); got != tt.want {
				t.Errorf("isValidCollaboratorUsername(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// Cleanup and lookup paths keep accepting existing colliding names, so they
// stay deletable.
func TestIsValidUsernameStillAcceptsExistingNames(t *testing.T) {
	if !isValidUsername("a-container-b") || !isValidUsername("a-container") {
		t.Fatal("isValidUsername must keep accepting existing names for cleanup")
	}
}
