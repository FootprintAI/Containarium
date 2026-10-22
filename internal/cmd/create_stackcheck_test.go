package cmd

import (
	"strings"
	"testing"
)

// #2860: `create --force --stack typo` must fail BEFORE --force deletes the
// existing box. In local mode the stack catalog on this host is the one the
// create uses, so it is checked up front. With a server address the daemon's
// catalog (possibly an operator stacks.yaml) is authoritative and the daemon
// rejects it; the client does not second-guess it.
func TestValidateStackLocal(t *testing.T) {
	err := validateStackLocal("", "typo")
	if err == nil || !strings.Contains(err.Error(), "typo") || !strings.Contains(err.Error(), "nodejs") {
		t.Fatalf("local unknown stack = %v, want an error naming it and listing valid IDs", err)
	}
	for _, tc := range []struct{ addr, stack string }{
		{"", ""}, {"", "nodejs"}, {"daemon.example.com:50051", "typo"},
	} {
		if err := validateStackLocal(tc.addr, tc.stack); err != nil {
			t.Errorf("validateStackLocal(%q, %q) = %v, want nil", tc.addr, tc.stack, err)
		}
	}
}
