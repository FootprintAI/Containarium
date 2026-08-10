package alert

import (
	"strings"
	"testing"
)

// The severity is written into the generated Prometheus rule as a label, and
// Alertmanager routes on that label. An unrecognised value produces a rule
// that fires and matches no route — the alert reaches nobody, and nothing
// reports an error. Silence is the same observable outcome as "nothing is
// wrong", which is why this is worth refusing at the API rather than
// discovering during an incident.
func TestValidateSeverity(t *testing.T) {
	for _, ok := range []string{SeverityCritical, SeverityWarning, SeverityInfo} {
		if err := ValidateSeverity(ok); err != nil {
			t.Errorf("ValidateSeverity(%q) rejected a documented severity: %v", ok, err)
		}
	}

	for _, bad := range []string{
		"",          // an explicitly empty severity is not the same as unset
		"warnning",  // the typo this exists for
		"Warning",   // case matters to Alertmanager's matcher
		" warning",  // as does whitespace
		"page",      // a plausible-sounding severity from another system
		"emergency", // syslog's vocabulary, not Prometheus's
	} {
		if err := ValidateSeverity(bad); err == nil {
			t.Errorf("ValidateSeverity(%q) was accepted — it would be written into the rule and "+
				"route nowhere", bad)
		}
	}
}

// The error has to tell the caller what to send instead. "invalid severity"
// leaves them guessing at a closed set they cannot see.
func TestValidateSeverity_ErrorNamesTheValidValues(t *testing.T) {
	err := ValidateSeverity("warnning")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"critical", "warning", "info", "warnning"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so the caller cannot act on it: %v", want, err)
		}
	}
}
