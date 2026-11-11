//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

var (
	toolchainInstalled = toolchain.Status{Installed: true, Release: "v0.123.0", Arch: "amd64"}
	toolchainMissing   = toolchain.Status{Err: fmt.Errorf("stat manifest: %w", fs.ErrNotExist)}
	toolchainBroken    = toolchain.Status{Err: errors.New("managed toolchain manifest is not a regular file")}
)

func TestPrintToolchainStatus(t *testing.T) {
	tests := []struct {
		name    string
		st      toolchain.Status
		want    []string
		notWant []string
	}{
		{
			name:    "installed release names its tag and arch",
			st:      toolchainInstalled,
			want:    []string{"✓", "v0.123.0", "amd64"},
			notWant: []string{toolchain.InstallDoc},
		},
		{
			name: "missing release says BUILD_TOOLS runs are refused and where to install",
			st:   toolchainMissing,
			want: []string{"!", "not installed", "BUILD_TOOLS", toolchain.InstallDoc},
		},
		{
			name: "unreadable release is reported with its reason",
			st:   toolchainBroken,
			want: []string{"!", "not a regular file", toolchain.InstallDoc},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printToolchainStatus(&buf, tt.st)
			out := buf.String()
			if !strings.Contains(out, "advisory") {
				t.Fatalf("section must say it does not affect the exit code:\n%s", out)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(out, w) {
					t.Errorf("output unexpectedly contains %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestLogStartupToolchainCheck(t *testing.T) {
	tests := []struct {
		name     string
		st       toolchain.Status
		wantWarn bool
		want     []string
	}{
		{name: "installed release logs one info line", st: toolchainInstalled, want: []string{"v0.123.0"}},
		{name: "missing release warns loudly", st: toolchainMissing, wantWarn: true,
			want: []string{"WARNING", "BUILD_TOOLS", toolchain.HostRoot, toolchain.InstallDoc}},
		{name: "unreadable release warns with the reason", st: toolchainBroken, wantWarn: true,
			want: []string{"WARNING", "not a regular file", toolchain.InstallDoc}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lines []string
			logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
			if got := logStartupToolchainCheck(logf, tt.st); got != tt.wantWarn {
				t.Fatalf("warned = %v, want %v", got, tt.wantWarn)
			}
			out := strings.Join(lines, "\n")
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("log missing %q:\n%s", w, out)
				}
			}
		})
	}
}
