package server

import (
	"os"
	"strings"
	"testing"
)

// A validator nothing calls is a validator that does not run. Both write
// paths have to use it: Create defaults an empty severity and then checks,
// Update checks only when the caller supplied one.
//
// Checked against the source because reaching these RPCs needs a wired store,
// and what is being asserted is the wiring itself — the same reason the
// dual_server guards in this package read source rather than standing the
// daemon up.
func TestAlertSeverityIsValidatedOnEveryWritePath(t *testing.T) {
	b, err := os.ReadFile("alert_server.go")
	if err != nil {
		t.Fatalf("read alert_server.go: %v", err)
	}
	src := string(b)

	// Every place the stored severity is assigned from a request.
	writes := strings.Count(src, "Severity:    severity,") +
		strings.Count(src, "existing.Severity = req.Severity")
	if writes == 0 {
		t.Fatal("found no severity write sites — the pattern changed, so this guard is blind")
	}

	checks := strings.Count(src, "alert.ValidateSeverity(")
	if checks < 2 {
		t.Errorf("severity is validated on %d write path(s), want both Create and Update — an "+
			"unvalidated path stores a value that routes nowhere and never errors", checks)
	}
}
