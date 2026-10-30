package stacks

import (
	"strings"
	"testing"
)

func TestValidateStackID(t *testing.T) {
	m := GetDefault()
	for id, want := range map[string]bool{"": true, "nodejs": true, "no-such-stack": false} {
		if got := m.ValidateStackID(id); got != want {
			t.Errorf("ValidateStackID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestCheckStackID(t *testing.T) {
	m := GetDefault()
	if err := m.CheckStackID("nodejs"); err != nil {
		t.Errorf("CheckStackID(nodejs) = %v", err)
	}
	err := m.CheckStackID("typo")
	if err == nil {
		t.Fatal("CheckStackID(typo) = nil, want an error")
	}
	for _, want := range []string{`"typo"`, "nodejs", "python"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err, want)
		}
	}
}
