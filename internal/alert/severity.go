package alert

import "fmt"

// The severities an alert rule may carry.
//
// These are not decoration. The manager writes the value straight into the
// generated Prometheus rule as a `severity` label, and Alertmanager routes on
// that label. A rule stored with "warnning" is therefore a rule that fires and
// matches no route — it reaches nobody, and nothing anywhere reports an error.
// That is the failure this set exists to make impossible.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// ValidateSeverity rejects a severity that is not one of the known set.
//
// Deliberately strict rather than normalising: "Warning" and " warning" are
// refused instead of being coerced, because a caller that sent either is
// working from a different idea of the contract, and silently repairing it
// hides that until the routing they expect does not happen.
func ValidateSeverity(severity string) error {
	switch severity {
	case SeverityCritical, SeverityWarning, SeverityInfo:
		return nil
	default:
		return fmt.Errorf(
			"severity %q is not one of %q, %q, %q — Alertmanager routes on this label, so an "+
				"unrecognised value produces a rule that fires and reaches nobody",
			severity, SeverityCritical, SeverityWarning, SeverityInfo)
	}
}
