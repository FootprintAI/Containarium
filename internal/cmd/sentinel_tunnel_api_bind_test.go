//go:build !windows && !containarium_client

package cmd

import (
	"testing"

	"github.com/footprintai/containarium/internal/sentinel"
)

func TestApplyTunnelAPIBindAddr(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "127.0.0.1", want: "127.0.0.1"},
		{in: "10.0.0.5", want: "10.0.0.5"},
		{in: "::1", want: "::1"},
		{in: "", wantErr: true},
		{in: "not-an-ip", wantErr: true},
		{in: "127.0.0.1:18001", wantErr: true},
	} {
		ts := sentinel.NewTunnelServer("", sentinel.NewTokenPolicy(), sentinel.NewTunnelRegistry(), 0)
		err := applyTunnelAPIBindAddr(ts, tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("applyTunnelAPIBindAddr(%q) = nil, want error", tc.in)
			}
			if ts.APIBindAddr != sentinel.DefaultTunnelAPIBindAddr {
				t.Errorf("applyTunnelAPIBindAddr(%q) changed APIBindAddr to %q on error", tc.in, ts.APIBindAddr)
			}
			continue
		}
		if err != nil {
			t.Errorf("applyTunnelAPIBindAddr(%q): %v", tc.in, err)
		}
		if ts.APIBindAddr != tc.want {
			t.Errorf("applyTunnelAPIBindAddr(%q): APIBindAddr = %q, want %q", tc.in, ts.APIBindAddr, tc.want)
		}
	}
}

func TestSentinelFlag_TunnelAPIBindAddrDefaultsToLoopback(t *testing.T) {
	f := sentinelCmd.Flags().Lookup("tunnel-api-bind-addr")
	if f == nil {
		t.Fatal("sentinel has no --tunnel-api-bind-addr flag")
	}
	if f.DefValue != "127.0.0.1" {
		t.Errorf("--tunnel-api-bind-addr default = %q, want 127.0.0.1", f.DefValue)
	}
}
