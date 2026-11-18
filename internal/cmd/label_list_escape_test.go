package cmd

import (
	"strings"
	"testing"
)

// `label list` prints label keys and values the tenant set on its box.
// Printed raw, a value can clear the operator's screen or forge a row of
// the table (#3343); both columns go through escapeControl.
func TestPrintLabelsTable_EscapesTenantKeysAndValues(t *testing.T) {
	for name, labels := range map[string]map[string]string{
		"value": {"team": hostile},
		"key":   {hostile: "ml"},
	} {
		t.Run(name, func(t *testing.T) {
			out := captureStdout(t, func() { printLabelsTable("alice", labels) })
			assertNoRawControl(t, out)
		})
	}
}

// Clean labels keep the existing layout.
func TestPrintLabelsTable_PlainOutputUnchanged(t *testing.T) {
	out := captureStdout(t, func() {
		printLabelsTable("alice", map[string]string{"team": "ml", "env": "prod"})
	})
	for _, want := range []string{
		"  KEY   VALUE\n",
		"  env   prod\n",
		"  team  ml\n",
		"Total: 2 label(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
