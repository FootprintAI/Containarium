//go:build !windows

package cmd

import (
	"strings"
	"testing"
)

func TestRenderTunnelUnit_RequiredFlags(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr: "sentinel.example.com:443",
		Token:        "tok-123",
		SpotID:       "node1",
		Ports:        "22,8080,443",
		Pool:         "prod",
	})
	for _, want := range []string{
		"--sentinel-addr sentinel.example.com:443",
		"--token tok-123",
		"--spot-id node1",
		"--ports 22,8080,443",
		"--pool prod",
		"WantedBy=multi-user.target",
		"Restart=always",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("tunnel unit missing %q\n---\n%s", want, u)
		}
	}
	// No public hostname requested → no public flags rendered.
	if strings.Contains(u, "--public-hostname") || strings.Contains(u, "--public-port") {
		t.Errorf("tunnel unit should not carry public-* flags when unset:\n%s", u)
	}
}

func TestRenderTunnelUnit_PublicPrimary(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr:   "s:443",
		Token:          "t",
		SpotID:         "n",
		Ports:          "443",
		Pool:           "prod",
		PublicHostname: "node1.example.com",
		PublicPort:     443,
	})
	if !strings.Contains(u, "--public-hostname node1.example.com") {
		t.Errorf("missing --public-hostname:\n%s", u)
	}
	if !strings.Contains(u, "--public-port 443") {
		t.Errorf("missing --public-port:\n%s", u)
	}
}

func TestRenderPoolDropIn(t *testing.T) {
	// ExecStart must be cleared then re-set (systemd override semantics) and
	// carry --pool; empty base-domain is omitted.
	d := renderPoolDropIn("prod", "")
	if !strings.Contains(d, "ExecStart=\nExecStart=/usr/local/bin/containarium daemon") {
		t.Errorf("drop-in must clear+reset ExecStart:\n%s", d)
	}
	if !strings.Contains(d, "--pool prod") {
		t.Errorf("drop-in missing --pool:\n%s", d)
	}
	if strings.Contains(d, "--base-domain") {
		t.Errorf("drop-in should omit --base-domain when empty:\n%s", d)
	}
	// With a base domain it's included.
	d2 := renderPoolDropIn("prod", "boxes.example.com")
	if !strings.Contains(d2, "--base-domain boxes.example.com") {
		t.Errorf("drop-in missing --base-domain when set:\n%s", d2)
	}
}
