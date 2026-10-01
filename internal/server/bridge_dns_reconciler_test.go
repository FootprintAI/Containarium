package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/bridgedns"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeBridgeDNSBackend is an in-memory Incus: optionally one core-caddy
// container, and the bridge's raw.dnsmasq value.
type fakeBridgeDNSBackend struct {
	present bool
	ip, raw string
}

func (f *fakeBridgeDNSBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	if !f.present || name != CoreCaddyContainer {
		return nil, errors.New("not found: " + name)
	}
	return &incus.ContainerInfo{Name: name, State: "Running", IPAddress: f.ip}, nil
}
func (f *fakeBridgeDNSBackend) GetNetworkConfigValue(string, string) (string, error) {
	return f.raw, nil
}
func (f *fakeBridgeDNSBackend) SetNetworkConfigValue(_, _, v string) error { f.raw = v; return nil }

var _ bridgedns.Backend = (*fakeBridgeDNSBackend)(nil)

func hostedConfig() *DualServerConfig {
	return &DualServerConfig{
		EnableAppHosting:    true,
		BaseDomain:          "example.com",
		SSHHost:             "ssh.example.com",
		DNSPassthroughHosts: []string{"api.example.com"},
	}
}

// The reconciler renders exactly what the daemon's own record would be, SSH
// carve-out and passthrough hosts included, from core-caddy's live address.
func TestNewBridgeDNSReconciler_RendersTheDaemonsRecord(t *testing.T) {
	be := &fakeBridgeDNSBackend{present: true, ip: "10.0.3.5"}
	r := newBridgeDNSReconciler(hostedConfig(), be)
	if r == nil {
		t.Fatal("want a reconciler when app hosting is on, a base domain is set and core-caddy exists")
	}
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	want := bridgeDNSRaw("example.com", "10.0.3.5", "ssh.example.com", "api.example.com")
	if be.raw != want {
		t.Fatalf("record = %q; want %q", be.raw, want)
	}
}

// #2188 root cause: on every daemon start after core-caddy first exists, the
// daemon auto-detects the Caddy admin URL, so CaddyAdminURL is already set when
// the server is built and the core-services block that used to write (and, in
// the first version of this fix, construct) the record is skipped. The record
// must still be reconciled in that case — it is the normal case after the first
// start, and the one that left a dead address in place for months.
func TestNewBridgeDNSReconciler_RunsWhenTheCaddyAdminURLWasAutoDetected(t *testing.T) {
	cfg := hostedConfig()
	cfg.CaddyAdminURL = "http://10.0.3.5:2019" // what cmd/daemon.go sets from the running core-caddy

	be := &fakeBridgeDNSBackend{present: true, ip: "10.0.3.5", raw: "address=/example.com/10.0.3.9"} // stale
	r := newBridgeDNSReconciler(cfg, be)
	if r == nil {
		t.Fatal("reconciler must not depend on CaddyAdminURL being empty")
	}
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if want := bridgeDNSRaw("example.com", "10.0.3.5", "ssh.example.com", "api.example.com"); be.raw != want {
		t.Fatalf("stale record not repaired: %q; want %q", be.raw, want)
	}
}

func TestNewBridgeDNSReconciler_NilWhenNotManaged(t *testing.T) {
	cases := []struct {
		name string
		edit func(*DualServerConfig)
		be   *fakeBridgeDNSBackend
	}{
		{"no core-caddy container on this host", func(*DualServerConfig) {}, &fakeBridgeDNSBackend{present: false}},
		{"app hosting off", func(c *DualServerConfig) { c.EnableAppHosting = false }, &fakeBridgeDNSBackend{present: true, ip: "10.0.3.5"}},
		{"no base domain", func(c *DualServerConfig) { c.BaseDomain = "" }, &fakeBridgeDNSBackend{present: true, ip: "10.0.3.5"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostedConfig()
			tc.edit(cfg)
			if r := newBridgeDNSReconciler(cfg, tc.be); r != nil {
				t.Fatalf("want nil (this daemon does not manage the record), got a reconciler")
			}
		})
	}
}
