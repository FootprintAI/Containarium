// Package hostharden applies narrow, single-purpose host mitigations that
// don't require the daemon's full eBPF network-policy engine.
//
// #1103 fix 3 asked to "arm the network policy (hence IMDS deny) as part of
// BYOC enrollment rather than leaving it opt-in". The daemon's actual IMDS
// deny is a PER-TENANT field (network_policies.allow_metadata, default
// false) enforced by the eBPF engine on a tenant's veth — but that engine is
// gated behind CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT/_ENFORCE, host-wide
// systemd config, and has documented incident history (OSS #654) wedging
// incusd's reconcile loop on a resource-constrained host. Auto-arming that
// whole stack at BYOC enrollment time, on an arbitrary customer machine,
// trades one risk for another.
//
// This package is the narrower alternative the team chose instead: a single
// static firewall rule, applied once at enrollment, that blocks the one
// thing #1103 actually cared about — a workload that escapes its container
// pivoting through the bridge to instance credentials. It does NOT touch the
// host's own OUTPUT chain, so cloud-provider tooling running ON the host
// (guest agent, gcloud, disk-resize scripts) keeps working; only traffic
// FORWARDED from the container bridge's subnet is blocked.
package hostharden

import (
	"fmt"
	"os/exec"
	"strings"
)

// MetadataIP is the link-local cloud-metadata address common to GCP, AWS,
// and Azure's IMDS implementations.
const MetadataIP = "169.254.169.254"

// runner abstracts exec.Command so tests can substitute a fake without
// actually invoking iptables/incus. Mirrors hostcheck/posture.go's
// dependency-injection shape for the same reason: a check/mutation that can
// only be exercised on a correctly-configured real host is one nobody runs
// in CI.
type runner func(name string, args ...string) ([]byte, error)

func defaultRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() // #nosec G204 -- name/args are package-internal constants ("incus", "iptables") with a caller-supplied bridge name, never raw user input
}

// BridgeSubnet resolves bridge's configured IPv4 CIDR via the incus CLI
// (not the Go client library) — this is a narrow, CLI-only feature and
// deliberately doesn't need an authenticated incus API connection at
// enrollment time the way the daemon's own network setup does.
func BridgeSubnet(bridge string) (string, error) {
	return bridgeSubnet(defaultRunner, bridge)
}

func bridgeSubnet(run runner, bridge string) (string, error) {
	out, err := run("incus", "network", "get", bridge, "ipv4.address")
	if err != nil {
		return "", fmt.Errorf("incus network get %s ipv4.address: %w: %s", bridge, err, strings.TrimSpace(string(out)))
	}
	subnet := strings.TrimSpace(string(out))
	if subnet == "" || subnet == "none" {
		return "", fmt.Errorf("bridge %s has no ipv4.address configured", bridge)
	}
	return subnet, nil
}

// BlockMetadataFromBridge inserts an idempotent iptables FORWARD rule
// dropping traffic from bridge's subnet to MetadataIP. Safe to call on
// every enrollment: it checks for the exact rule first (`iptables -C`)
// and only inserts when absent, so re-running `cloud enroll` never
// duplicates the rule.
//
// Scope, precisely: this blocks the container bridge's FORWARDED traffic
// to the metadata endpoint. It does not block the host's own
// OUTPUT-originated requests — a deliberate choice (see package doc) — and
// it does not require or interact with the eBPF network-policy engine.
//
// Known gap: this targets `iptables` (works whether the host's real backend
// is legacy iptables or the nft-via-iptables-shim most modern distros ship),
// not raw `nft`. A host with nftables ONLY and no iptables shim will fail
// this step; that failure is surfaced to the caller as an error, not
// silently swallowed, but it is deliberately non-fatal to enrollment (see
// cmd/cloud.go) — the fallback is the same "opt-in, documented" state
// #1103 started from, not a regression.
func BlockMetadataFromBridge(bridge string) (applied bool, detail string, err error) {
	return blockMetadataFromBridge(defaultRunner, bridge)
}

func blockMetadataFromBridge(run runner, bridge string) (bool, string, error) {
	subnet, err := bridgeSubnet(run, bridge)
	if err != nil {
		return false, "", fmt.Errorf("resolve bridge subnet: %w", err)
	}

	rule := []string{"FORWARD", "-s", subnet, "-d", MetadataIP, "-j", "DROP"}

	if _, err := run("iptables", append([]string{"-C"}, rule...)...); err == nil {
		return false, fmt.Sprintf("already present: iptables -A %s", strings.Join(rule, " ")), nil
	}

	insertArgs := append([]string{"-I"}, rule...)
	if out, err := run("iptables", insertArgs...); err != nil {
		return false, "", fmt.Errorf("iptables %s: %w: %s", strings.Join(insertArgs, " "), err, strings.TrimSpace(string(out)))
	}
	return true, fmt.Sprintf("inserted: iptables -I %s", strings.Join(rule, " ")), nil
}
