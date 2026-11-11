package naming

import "testing"

func TestValidateTenantName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid simple", "owner-a", false},
		{"valid with underscore", "owner_a", false},
		{"infix", "a-container-b", true},
		{"infix with longer owner", "owner-container-x", true},
		{"suffix", "a-container", true},
		{"exactly the word", "container", false},
		{"container as prefix word", "container-a", false},
		{"container inside word", "mycontainer", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTenantName(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTenantName(%q) err=%v, wantErr=%v", tt.in, err, tt.wantErr)
			}
		})
	}
}

// The suffix case from the issue: owner "a-container" + collaborator "b" would
// build the same jump account as owner "a" + collaborator "container-b".
func TestSuffixCaseOwnerRejectedCollaboratorAccepted(t *testing.T) {
	if err := ValidateTenantName("a-container"); err == nil {
		t.Fatal("owner a-container must be rejected")
	}
	if err := ValidateTenantName("b"); err != nil {
		t.Fatalf("collaborator b must be accepted: %v", err)
	}
}

func TestAuditNames(t *testing.T) {
	owners := []string{"owner-a", "a-container", "x-container-y"}
	collabs := []CollaboratorPair{
		{Owner: "owner-a", Collaborator: "bob"},
		{Owner: "a-container", Collaborator: "b"},
		{Owner: "a", Collaborator: "container-b"},
	}
	got := AuditNames(owners, collabs)
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.Name+"|"+f.Kind] = true
	}
	for _, want := range []string{
		"a-container|owner",
		"x-container-y|owner",
		"a-container-container-b|account-collision",
	} {
		if !seen[want] {
			t.Errorf("missing finding %q in %+v", want, got)
		}
	}
	if seen["owner-a|owner"] {
		t.Errorf("valid owner flagged: %+v", got)
	}
}
