//go:build !windows

package hostcheck

import (
	"errors"
	"strings"
	"testing"
)

// KernelSupportsTCX is the pure helper behind the egress TCX check (#2972).
// "known" false means the release could not be parsed; a caller must never
// read that as supported.
func TestKernelSupportsTCX(t *testing.T) {
	cases := []struct {
		release       string
		wantSupported bool
		wantKnown     bool
	}{
		{"6.8.0-45-generic", true, true},
		{"6.6.12+", true, true},
		{"6.6.0", true, true},
		{"6.6", true, true},
		{"6.6-rc1", true, true},
		{"7.0.1-custom", true, true},
		{"10.1.0", true, true},
		{"6.10.3-arch1-1", true, true},
		{"  6.8.0-generic\n", true, true},
		{"6.5.13-generic", false, true},
		{"6.5.99", false, true},
		{"5.15.0-1050-gcp", false, true},
		{"5.4.0", false, true},
		{"4.19.0-amd64", false, true},
		{"6.1.0-13-cloud-amd64", false, true},
		{"", false, false},
		{"garbage", false, false},
		{"6", false, false},
		{"6.", false, false},
		{"6.x.1", false, false},
		{".6.1", false, false},
		{"-1.6.0", false, false},
		{"10.0", true, true},
		{"6.6.0-rc1", true, true},
		{"v6.6", false, false},
		{" ", false, false},
		{"99999999999999999999.6", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.release, func(t *testing.T) {
			sup, known := KernelSupportsTCX(tc.release)
			if sup != tc.wantSupported || known != tc.wantKnown {
				t.Errorf("KernelSupportsTCX(%q) = (%v, %v), want (%v, %v)",
					tc.release, sup, known, tc.wantSupported, tc.wantKnown)
			}
		})
	}
}

// The advisory kernel check shows up in the posture output (doctor, pool
// join), never gates, and unknown is never a pass.
func TestKernelTCXCheck(t *testing.T) {
	cases := []struct {
		name       string
		probe      func() (string, error)
		wantOK     bool
		wantDetail string
	}{
		{"supported", func() (string, error) { return "6.8.0-45-generic", nil }, true, "kernel 6.8.0-45-generic"},
		{"too old", func() (string, error) { return "5.15.0-1050-gcp", nil }, false, string(ReasonKernelTooOld) + ":"},
		{"unparseable", func() (string, error) { return "garbage", nil }, false, string(ReasonKernelUnknown) + ":"},
		{"probe error", func() (string, error) { return "", errors.New("denied") }, false, string(ReasonKernelUnknown) + ":"},
		{"no probe", nil, false, string(ReasonKernelUnknown) + ":"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := kernelTCXCheck(tc.probe)
			if c.OK != tc.wantOK || c.Required {
				t.Errorf("OK=%v Required=%v, want OK=%v Required=false", c.OK, c.Required, tc.wantOK)
			}
			if !strings.Contains(c.Detail, tc.wantDetail) {
				t.Errorf("detail %q lacks %q", c.Detail, tc.wantDetail)
			}
		})
	}
}

func TestRunPosture_IncludesKernelTCX(t *testing.T) {
	p, _ := tempPaths(t)
	p.kernelRelease = func() (string, error) { return "6.8.0-45-generic", nil }
	for _, c := range runPosture(p) {
		if c.Name == egressCheckKernel {
			if !c.OK || c.Kind != KindPosture || c.Required {
				t.Errorf("kernel check = %+v, want OK posture non-required", c)
			}
			return
		}
	}
	t.Error("runPosture does not include the kernel TCX check")
}
