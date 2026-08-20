// Package clustere2e is the gated KVM end-to-end lane for managed
// Kubernetes clusters (#1418) — the definition-of-done check for the
// managed-clusters MVP (design: docs/architecture/managed-k8s-clusters.md,
// "End-to-end" section).
//
// This file carries no build tag on purpose, mirroring
// internal/testsupport/incusenv: the pure decision logic the lane leans
// on — which kubeconfig endpoint counts as "outside", which nodes count
// as "new and Ready", what a sabotage value means — is testable, and
// provably able to fail, in the ordinary unit suite on any machine. The
// code that needs a real Incus + KVM host lives behind the
// `incus && cluster_e2e` tags in e2e_test.go.
package clustere2e

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
)

// KubeconfigServerHost returns the host:port of the server URL the
// kubeconfig's current context points at.
func KubeconfigServerHost(kubeconfig []byte) (string, error) {
	cfg, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("parse kubeconfig: %w", err)
	}
	ctx, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return "", fmt.Errorf("kubeconfig has no context %q", cfg.CurrentContext)
	}
	cluster, ok := cfg.Clusters[ctx.Cluster]
	if !ok {
		return "", fmt.Errorf("kubeconfig context %q names missing cluster %q", cfg.CurrentContext, ctx.Cluster)
	}
	u, err := url.Parse(cluster.Server)
	if err != nil {
		return "", fmt.Errorf("kubeconfig server %q: %w", cluster.Server, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("kubeconfig server %q has no host", cluster.Server)
	}
	return u.Host, nil
}

// NewReadyNodes returns the names in current that are Ready and were
// not present in baseline, sorted.
func NewReadyNodes(baseline []string, current map[string]bool) []string {
	known := make(map[string]bool, len(baseline))
	for _, n := range baseline {
		known[n] = true
	}
	var out []string
	for name, ready := range current {
		if ready && !known[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// SabotageMode is a deliberate breakage the lane injects to prove it
// can fail (#1418 guardrail: a green lane is not evidence the test ran).
type SabotageMode int

const (
	// SabotageNone runs the lane normally.
	SabotageNone SabotageMode = iota
	// SabotageJoinToken corrupts worker join tokens so nodes can never
	// register; the lane must go red.
	SabotageJoinToken
)

// ParseSabotage maps CONTAINARIUM_E2E_SABOTAGE onto a mode. Unknown
// values are an error, not SabotageNone: a typo'd proof run silently
// taking the normal green path would "prove" the lane can fail without
// ever sabotaging anything.
func ParseSabotage(value string) (SabotageMode, error) {
	switch strings.TrimSpace(value) {
	case "":
		return SabotageNone, nil
	case "join-token":
		return SabotageJoinToken, nil
	default:
		return SabotageNone, fmt.Errorf("unknown CONTAINARIUM_E2E_SABOTAGE value %q (want empty or join-token)", value)
	}
}

// MaxRestartDelta returns the largest restart-count increase across
// containers between two observations keyed by pod/container name. A
// container unseen before counts from zero; one gone in after (its pod
// replaced) contributes nothing — a fresh pod is not a restart loop.
func MaxRestartDelta(before, after map[string]int32) int32 {
	var max int32
	for key, count := range after {
		if d := count - before[key]; d > max {
			max = d
		}
	}
	return max
}
