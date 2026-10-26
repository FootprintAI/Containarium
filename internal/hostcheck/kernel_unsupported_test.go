package hostcheck

import (
	"errors"
	"testing"
)

// #2972: the status reports KERNEL_UNSUPPORTED only when the kernel is KNOWN to
// be too old for TCX attach. A release that cannot be read or parsed is
// "unknown", which must not be reported as unsupported (that would tell an
// operator a capable host cannot enforce).
func TestKernelUnsupportedFrom(t *testing.T) {
	for _, tc := range []struct {
		name    string
		release func() (string, error)
		want    bool
	}{
		{"too old", func() (string, error) { return "5.15.0-1050-gcp", nil }, true},
		{"just below the floor", func() (string, error) { return "6.5.13", nil }, true},
		{"at the floor", func() (string, error) { return "6.6.0", nil }, false},
		{"newer", func() (string, error) { return "6.8.0-137-generic", nil }, false},
		{"suffix after the version", func() (string, error) { return "6.6.12+", nil }, false},
		{"unparseable is unknown, not unsupported", func() (string, error) { return "weird", nil }, false},
		{"a read error is unknown, not unsupported", func() (string, error) { return "", errors.New("boom") }, false},
		{"no probe is unknown, not unsupported", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelUnsupportedFrom(tc.release); got != tc.want {
				t.Errorf("kernelUnsupportedFrom = %v, want %v", got, tc.want)
			}
		})
	}
}
