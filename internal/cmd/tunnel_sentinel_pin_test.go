//go:build !windows && !containarium_client

package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/sentinel"
)

const (
	testPinA = "sha256:" + "aa00000000000000000000000000000000000000000000000000000000000000"
	testPinB = "sha256:" + "bb00000000000000000000000000000000000000000000000000000000000000"
)

func TestResolveSentinelPins(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		env     string
		want    []sentinel.TunnelPin
		wantErr string
	}{
		{name: "flag list normalised", flag: testPinA + ", sha256:" + strings.ToUpper(testPinB[len("sha256:"):]), want: []sentinel.TunnelPin{testPinA, testPinB}},
		{name: "unprefixed entry", flag: testPinB[len("sha256:"):], wantErr: "must start with"},
		{name: "flag single", flag: testPinA, want: []sentinel.TunnelPin{testPinA}},
		{name: "flag list with rotation overlap", flag: testPinA + "," + testPinB, want: []sentinel.TunnelPin{testPinA, testPinB}},
		{name: "env used when flag empty", env: testPinB, want: []sentinel.TunnelPin{testPinB}},
		{name: "flag wins over env", flag: testPinA, env: testPinB, want: []sentinel.TunnelPin{testPinA}},
		{name: "missing", wantErr: "--sentinel-pin or " + sentinelPinEnv + " is required"},
		{name: "malformed", flag: "sha256:zz", wantErr: "invalid --sentinel-pin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(sentinelPinEnv, tt.env)
			got, err := resolveSentinelPins(tt.flag)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveSentinelPins(%q) error = %v, want containing %q", tt.flag, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSentinelPins(%q): %v", tt.flag, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestRunTunnelRefusesWithoutPin: `containarium tunnel` exits with a clear
// error before connecting anywhere when no sentinel pin is configured.
func TestRunTunnelRefusesWithoutPin(t *testing.T) {
	t.Setenv(sentinelPinEnv, "")
	t.Setenv("CONTAINARIUM_TUNNEL_TOKEN", "")
	saved := []string{tunnelSentinelAddr, tunnelToken, tunnelSpotID, tunnelSentinelPin}
	t.Cleanup(func() {
		tunnelSentinelAddr, tunnelToken, tunnelSpotID, tunnelSentinelPin = saved[0], saved[1], saved[2], saved[3]
	})
	tunnelSentinelAddr = "127.0.0.1:1"
	tunnelToken = "tok"
	tunnelSpotID = "spot"
	tunnelSentinelPin = ""

	err := runTunnel(tunnelCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--sentinel-pin") {
		t.Fatalf("runTunnel without a pin: err = %v, want a --sentinel-pin error", err)
	}
}

// TestRunHypervisorAgentRefusesWithoutPin: hypervisor-agent also requires
// the sentinel pin, and checks it before opening its console listener.
func TestRunHypervisorAgentRefusesWithoutPin(t *testing.T) {
	t.Setenv(sentinelPinEnv, "")
	saved := []string{hvSentinelAddr, hvTunnelToken, hvSpotID, hvVBoxDir, hvConsoleToken, hvSentinelPin}
	t.Cleanup(func() {
		hvSentinelAddr, hvTunnelToken, hvSpotID, hvVBoxDir, hvConsoleToken, hvSentinelPin = saved[0], saved[1], saved[2], saved[3], saved[4], saved[5]
	})
	hvSentinelAddr = "127.0.0.1:1"
	hvTunnelToken = "tok"
	hvSpotID = "host"
	hvVBoxDir = t.TempDir()
	hvConsoleToken = "console"
	hvSentinelPin = ""

	err := runHypervisorAgent(hypervisorAgentCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--sentinel-pin") {
		t.Fatalf("runHypervisorAgent without a pin: err = %v, want a --sentinel-pin error", err)
	}
}

func TestSentinelPinFlagsRegistered(t *testing.T) {
	if f := tunnelCmd.Flags().Lookup("sentinel-pin"); f == nil {
		t.Error("tunnel: --sentinel-pin flag not registered")
	}
	if f := hypervisorAgentCmd.Flags().Lookup("sentinel-pin"); f == nil {
		t.Error("hypervisor-agent: --sentinel-pin flag not registered")
	}
}
