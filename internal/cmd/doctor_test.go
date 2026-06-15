//go:build !windows

package cmd

import (
	"testing"

	"github.com/footprintai/containarium/internal/hostcheck"
)

func TestPrintDoctor_CountsRequiredFailures(t *testing.T) {
	checks := []hostcheck.Check{
		{Name: "ok-required", OK: true, Required: true},
		{Name: "fail-required", OK: false, Required: true, Detail: "x"}, // counts
		{Name: "warn-optional", OK: false, Required: false},             // not counted
		{Name: "fail-required-2", OK: false, Required: true},            // counts
	}
	if got := printDoctor(checks); got != 2 {
		t.Fatalf("printDoctor required-failure count = %d, want 2", got)
	}
}
