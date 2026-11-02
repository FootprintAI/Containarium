//go:build !windows && !containarium_client

package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
)

// Operator-side tables that only exist in the daemon build (the SSH session
// log and the audit query) escape tenant-supplied cells too (#3343). The SSH
// login is chosen by an unauthenticated client, so it is the least trusted
// value any table prints.
func TestOperatorTables_EscapeTenantSuppliedCells(t *testing.T) {
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		out  string
	}{
		{"ssh sessions: login and target", strings.Join(sshSessionRowFields(sshsession.Record{OccurredAt: ts, Login: hostile, Target: hostile}), "\t")},
		{"audit detail column", sanitizeDetailForCLI(hostile)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertNoRawControl(t, tc.out) })
	}
}

// The audit detail column keeps its existing contract — whitespace controls
// fold to a space so a row stays on one line — while every other control
// (ESC, DEL, C1) is now escaped instead of passing through.
func TestSanitizeDetailForCLI_FoldsWhitespaceAndEscapesTheRest(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain detail", "plain detail"},
		{"a\nb\rc\td", "a b c d"},
		{"x\x1b[31my", `x\x1b[31my`},
		{"del\x7f", `del\x7f`},
		{"café ok", "café ok"},
	} {
		if got := sanitizeDetailForCLI(tc.in); got != tc.want {
			t.Errorf("sanitizeDetailForCLI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
