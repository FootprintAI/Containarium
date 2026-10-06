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
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// MetadataIP is the link-local cloud-metadata address common to GCP, AWS,
// and Azure's IMDS implementations.
const MetadataIP = "169.254.169.254"

// DefaultBridge is the incus bridge `cloud enroll` and `pool join` block, and
// the one the host posture check (internal/hostcheck) inspects.
const DefaultBridge = "incusbr0"

// runner abstracts exec.Command so tests can substitute a fake without
// actually invoking iptables/incus. Mirrors hostcheck/posture.go's
// dependency-injection shape for the same reason: a check/mutation that can
// only be exercised on a correctly-configured real host is one nobody runs
// in CI.
type runner func(name string, args ...string) ([]byte, error)

func defaultRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() // #nosec G204 -- name/args are package-internal constants ("incus", "iptables") with a caller-supplied bridge name, never raw user input
}

// probeTimeout bounds each command MetadataBlockPresent runs. The posture
// check runs in `doctor` and in the daemon's cloud status probe every
// heartbeat; a hung incusd must not hang either of them (#2325 was that
// failure for the hardware scan).
const probeTimeout = 5 * time.Second

// probeWaitDelay bounds how long a timed-out command's output pipes may stay
// open after it is killed: a child it spawned can hold them, and
// CombinedOutput would otherwise wait for that child too.
const probeWaitDelay = time.Second

// timeoutRunner is defaultRunner with a deadline. A command that overruns it
// is killed and reported as an error with no exit code, which
// metadataBlockPresent treats as "could not tell", never as "absent".
func timeoutRunner(timeout time.Duration) runner {
	return func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- same callers and arguments as defaultRunner
		cmd.WaitDelay = probeWaitDelay
		out, err := cmd.CombinedOutput()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("%s did not finish within %s", name, timeout)
		}
		return out, err
	}
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

	rule := metadataRule(subnet)

	if _, err := run("iptables", append([]string{"-C"}, rule...)...); err == nil {
		return false, fmt.Sprintf("already present: iptables -A %s", strings.Join(rule, " ")), nil
	}

	insertArgs := append([]string{"-I"}, rule...)
	if out, err := run("iptables", insertArgs...); err != nil {
		return false, "", fmt.Errorf("iptables %s: %w: %s", strings.Join(insertArgs, " "), err, strings.TrimSpace(string(out)))
	}
	return true, fmt.Sprintf("inserted: iptables -I %s", strings.Join(rule, " ")), nil
}

// metadataRule is the FORWARD rule BlockMetadataFromBridge inserts and
// MetadataBlockPresent looks for — one definition, so the posture check can
// never look for a different rule than the one enrollment applies.
func metadataRule(subnet string) []string {
	return []string{"FORWARD", "-s", subnet, "-d", MetadataIP, "-j", "DROP"}
}

// MetadataBlockPresent reports whether BlockMetadataFromBridge's rule is in
// the kernel right now, changing nothing (#2298). It backs the host posture
// check, so it keeps "absent" and "could not tell" apart: present=false with
// a nil error means `iptables -C` ran and found no such rule; a non-nil error
// means the answer is unknown (bridge has no subnet, iptables missing, not
// root, nftables-only host, or a command that did not finish within
// probeTimeout).
func MetadataBlockPresent(bridge string) (present bool, detail string, err error) {
	return metadataBlockPresent(timeoutRunner(probeTimeout), bridge)
}

func metadataBlockPresent(run runner, bridge string) (bool, string, error) {
	subnet, err := bridgeSubnet(run, bridge)
	if err != nil {
		return false, "", fmt.Errorf("resolve bridge subnet: %w", err)
	}
	rule := metadataRule(subnet)
	checkArgs := append([]string{"-C"}, rule...)
	out, err := run("iptables", checkArgs...)
	if err == nil {
		return true, fmt.Sprintf("present: iptables -A %s", strings.Join(rule, " ")), nil
	}
	// `iptables -C` exits 1 for "no such rule"; any other failure (exit 4
	// for permission denied, a missing binary with no exit code at all) says
	// nothing about the rule.
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, fmt.Sprintf("absent: iptables -A %s", strings.Join(rule, " ")), nil
	}
	return false, "", fmt.Errorf("iptables %s: %w: %s", strings.Join(checkArgs, " "), err, strings.TrimSpace(string(out)))
}
