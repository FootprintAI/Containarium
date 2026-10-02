package server

import "github.com/footprintai/containarium/internal/bridgedns"

// newBridgeDNSReconciler builds the reconciler that keeps the bridge DNS record
// on core-caddy's live address (#2188), or nil when this daemon should not
// manage it: app hosting off, no base domain, or no core-caddy container on this
// host (an operator-run external Caddy has none, and then there is nothing for
// the record to point at).
//
// It deliberately does not look at CaddyAdminURL. On every start after
// core-caddy first exists the daemon auto-detects that URL from the running
// container, so it is already set by the time the server is built and the
// core-services block that writes the record at first install is skipped. Tying
// the reconciler to that block — as the first version of this fix did — meant it
// never ran in exactly the case that left a dead address in place.
// createIfAbsent is true when this daemon run installed core-caddy itself
// (the first-install case) or the operator passed --bridge-dns-create; only
// then may a pass write a record onto a bridge that has none (#2232).
func newBridgeDNSReconciler(config *DualServerConfig, be bridgedns.Backend, createIfAbsent bool) *bridgedns.Reconciler {
	if !config.EnableAppHosting || config.BaseDomain == "" || config.BridgeDNSReconcileDisabled {
		return nil
	}
	if _, err := be.GetContainer(CoreCaddyContainer); err != nil {
		return nil
	}
	baseDomain, sshHost := config.BaseDomain, config.SSHHost
	passthrough := append([]string(nil), config.DNSPassthroughHosts...)
	carveouts := append([]string(nil), passthrough...)
	if sshHost != "" {
		carveouts = append([]string{sshHost}, carveouts...)
	}
	return bridgedns.NewReconciler(be, bridgedns.Config{
		Bridge:         "incusbr0",
		CaddyContainer: CoreCaddyContainer,
		Render: func(ip string) string {
			return bridgeDNSRaw(baseDomain, ip, sshHost, passthrough...)
		},
		CreateIfAbsent: createIfAbsent || config.BridgeDNSCreate,
		BaseDomain:     baseDomain,
		Carveouts:      carveouts,
	})
}
