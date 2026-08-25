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
	"strconv"
	"strings"
	"time"

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
	// SabotageDropPrerouting deletes the published endpoint's
	// PREROUTING DNAT rule once the cluster is up, leaving the OUTPUT
	// rule intact. The daemon host can still reach the endpoint;
	// nothing else can.
	//
	// This is the acceptance evidence #1468 asks for. Before the
	// off-host probe existed the lane stayed GREEN under exactly this
	// breakage — every dial it made was locally generated and took the
	// OUTPUT path — while no tenant could reach any cluster. A lane
	// that survives this is a lane whose "from outside" step is
	// decorative.
	SabotageDropPrerouting
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
	case "drop-prerouting":
		return SabotageDropPrerouting, nil
	default:
		return SabotageNone, fmt.Errorf("unknown CONTAINARIUM_E2E_SABOTAGE value %q (want empty, join-token or drop-prerouting)", value)
	}
}

// IsolationMode is the node isolation class the lane exercises
// (#1430). The same six-step journey runs in both classes; what
// changes is the `cluster create` call and what the runner must be
// able to do (KVM for VMs, container-node preconditions otherwise).
type IsolationMode int

const (
	// IsolationVM is the default: cluster nodes are Incus VMs, the
	// class the self-hosted KVM lane gates (#1418).
	IsolationVM IsolationMode = iota
	// IsolationContainer: cluster nodes are Incus system containers
	// (#1429), the class the GitHub-hosted lane runs without KVM.
	IsolationContainer
)

func (m IsolationMode) String() string {
	if m == IsolationContainer {
		return "container"
	}
	return "vm"
}

// ParseIsolation maps CONTAINARIUM_E2E_ISOLATION onto a mode. Unset is
// VM so the KVM lane's environment keeps meaning exactly what it meant
// before this knob existed. Unknown values are an error, for
// ParseSabotage's reason: a typo'd container run that silently took the
// VM path would report "container mode works" having never asked for a
// container node.
func ParseIsolation(value string) (IsolationMode, error) {
	switch strings.TrimSpace(value) {
	case "", "vm":
		return IsolationVM, nil
	case "container":
		return IsolationContainer, nil
	default:
		return IsolationVM, fmt.Errorf("unknown CONTAINARIUM_E2E_ISOLATION value %q (want empty, vm or container)", value)
	}
}

// CreateArgs returns the extra `containarium cluster create` arguments
// for the mode. VM mode adds none — the KVM lane invokes the CLI
// byte-identically to its pre-#1430 self, and the daemon's own default
// (never the weaker class) decides.
func (m IsolationMode) CreateArgs() []string {
	if m == IsolationContainer {
		return []string{"--isolation", "container"}
	}
	return nil
}

// ClusterInstance is one Incus instance as the lane observes it.
type ClusterInstance struct {
	Name string
	// Type is Incus's instance type ("container" or "virtual-machine").
	// Carried for logs only — see ClusterInstanceNames.
	Type string
}

// ClusterInstanceNames returns the names of the instances belonging to
// a cluster, matched on the cluster's name prefix and NOTHING else,
// sorted. The type is deliberately not a filter: a container-mode
// cluster's nodes are Incus containers and a VM-mode cluster's are VMs,
// so a type filter would make one of the two lanes observe an empty
// cluster and report "no leftover nodes" as a pass.
func ClusterInstanceNames(all []ClusterInstance, prefix string) []string {
	var out []string
	for _, inst := range all {
		if strings.HasPrefix(inst.Name, prefix) {
			out = append(out, inst.Name)
		}
	}
	sort.Strings(out)
	return out
}

// incusInstanceType is Incus's own name for the instance class the
// mode provisions ("container" / "virtual-machine" on the API).
func (m IsolationMode) incusInstanceType() string {
	if m == IsolationContainer {
		return "container"
	}
	return "virtual-machine"
}

// WrongClassInstances returns "name (type)" for every instance of the
// cluster whose Incus instance type is not the class the lane asked
// for, sorted. This is what makes the isolation knob provable: a
// container-mode run whose daemon quietly provisioned VMs (or the
// reverse) would otherwise run the entire journey and report the wrong
// class as green. A type Incus did not report counts as a mismatch —
// an unverified class is not a verified one.
func WrongClassInstances(all []ClusterInstance, prefix string, mode IsolationMode) []string {
	want := mode.incusInstanceType()
	var out []string
	for _, inst := range all {
		if !strings.HasPrefix(inst.Name, prefix) {
			continue
		}
		if inst.Type != want {
			out = append(out, fmt.Sprintf("%s (%s)", inst.Name, inst.Type))
		}
	}
	sort.Strings(out)
	return out
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

// PostgresReadyArgs is how the lane asks whether its throwaway
// postgres is actually up (#1514).
//
// `-h 127.0.0.1` is the entire point, and it is not a stylistic
// preference. The official postgres entrypoint starts TWO servers: a
// temporary one for the init phase, run with `listen_addresses=”` so
// it is reachable only over the Unix socket, and then — after
// CREATE DATABASE and any init scripts — it SHUTS THAT ONE DOWN and
// starts the real server, which is the first to listen on TCP.
//
// A default `pg_isready` talks to the Unix socket, so it answers "ready"
// about the temporary server. The lane's wait loop broke on that
// answer, the entrypoint then shut that server down, and the
// confirming probe landed in the shutdown window: a red build seven
// seconds into a bound of ninety, with nothing wrong with postgres or
// the product.
//
// Probing over TCP cannot see the init server at all, so it cannot
// break early. Raising the timeout — which is what was tried before —
// cannot help something that never reaches its timeout.
func PostgresReadyArgs(user string) []string {
	return []string{"pg_isready", "-h", "127.0.0.1", "-U", user}
}

// OffHostProbe is how the lane checks that the advertised cluster
// endpoint is reachable from somewhere that is NOT the daemon host
// (#1468).
//
// Why this needs a knob at all: the test process runs ON the daemon
// host, so every dial it makes is locally generated and skips
// PREROUTING entirely, taking the OUTPUT path instead. Those are two
// different kernel paths, and #1459 was exactly the difference — the
// lane could not reach its own cluster's endpoint until an OUTPUT rule
// with `-m addrtype --dst-type LOCAL` was added. So the step named
// "from outside" has been exercising the rule added for the lane's own
// benefit and never the PREROUTING rule every real tenant traverses.
// Delete the PREROUTING rule and the suite stays green while no tenant
// can reach any cluster.
type OffHostProbe int

const (
	// OffHostProbeNone: no off-host check. The step still verifies
	// that the kubeconfig POINTS at the advertised host, which is
	// real and valuable, but it does not verify that address is
	// reachable from off-host — and it says so out loud rather than
	// letting the step's name imply otherwise.
	OffHostProbeNone OffHostProbe = iota
	// OffHostProbeNetns dials from a network namespace joined to the
	// host by a veth, so the packet arrives from elsewhere and
	// traverses PREROUTING the way a tenant's does. Needs root and
	// iproute2; the cheap version of "a second machine".
	OffHostProbeNetns
)

func (p OffHostProbe) String() string {
	if p == OffHostProbeNetns {
		return "netns"
	}
	return "none"
}

// ParseOffHostProbe maps CONTAINARIUM_E2E_OFFHOST_PROBE onto a mode.
// Unset is none, so an environment that cannot create namespaces keeps
// working. Unknown values are an error, for ParseIsolation's reason: a
// typo'd probe that silently degraded to "none" would report that the
// tenant-facing path was verified having never left the host.
func ParseOffHostProbe(value string) (OffHostProbe, error) {
	switch strings.TrimSpace(value) {
	case "", "none":
		return OffHostProbeNone, nil
	case "netns":
		return OffHostProbeNetns, nil
	default:
		return OffHostProbeNone, fmt.Errorf("unknown CONTAINARIUM_E2E_OFFHOST_PROBE value %q (want empty, none or netns)", value)
	}
}

// OffHostNetns names the namespace and the veth pair the probe builds.
// Fixed names so a leaked namespace from a killed run is found and
// removed by the next one rather than accumulating.
const (
	OffHostNetns    = "ctnr-e2e-outside"
	OffHostVethHost = "ctnre2eh"
	OffHostVethPeer = "ctnre2ep"
	// A /30 that does not collide with Incus's default bridges
	// (10.0.3.0/24, 10.100.0.0/16) or the runner's own networks.
	OffHostHostAddr = "10.244.244.1"
	OffHostPeerAddr = "10.244.244.2"
)

// DropPreroutingCommand deletes the published endpoint's inbound DNAT
// rule for one port, leaving the OUTPUT rule alone. Mirrors the shape
// passthroughDeleteArgs installs, so the sabotage removes the same rule
// the product creates rather than a lookalike.
func DropPreroutingCommand(externalPort int) []string {
	return []string{
		"iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "tcp", "--dport", strconv.Itoa(externalPort),
	}
}

// OffHostSetupCommands builds the namespace and the veth into the
// host. Pure so the sequence is table-testable without root — the
// commands are the contract, and getting their ORDER wrong (addressing
// an interface before moving it into the namespace, routing before the
// link is up) is the whole failure mode.
func OffHostSetupCommands() [][]string {
	return [][]string{
		{"ip", "netns", "add", OffHostNetns},
		{"ip", "link", "add", OffHostVethHost, "type", "veth", "peer", "name", OffHostVethPeer},
		// Move the peer BEFORE addressing it: addressing it on the
		// host and then moving it loses the address.
		{"ip", "link", "set", OffHostVethPeer, "netns", OffHostNetns},
		{"ip", "addr", "add", OffHostHostAddr + "/30", "dev", OffHostVethHost},
		{"ip", "link", "set", OffHostVethHost, "up"},
		{"ip", "netns", "exec", OffHostNetns, "ip", "addr", "add", OffHostPeerAddr + "/30", "dev", OffHostVethPeer},
		{"ip", "netns", "exec", OffHostNetns, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", OffHostNetns, "ip", "link", "set", OffHostVethPeer, "up"},
		// Default route last: it needs the link up and addressed.
		{"ip", "netns", "exec", OffHostNetns, "ip", "route", "add", "default", "via", OffHostHostAddr},
	}
}

// OffHostTeardownCommands removes the namespace. Deleting the netns
// takes the peer with it; the host side goes with its pair.
func OffHostTeardownCommands() [][]string {
	return [][]string{
		{"ip", "netns", "del", OffHostNetns},
		{"ip", "link", "del", OffHostVethHost},
	}
}

// OffHostDialCommand dials hostPort from inside the namespace.
//
// Any TCP answer proves the packet reached the API server through
// PREROUTING — an HTTP 401 or 403 is a pass, because authentication is
// not what is under test. Only "could not connect" is a failure, which
// is why this asks for a connect-only probe rather than a successful
// request.
func OffHostDialCommand(hostPort string, timeout time.Duration) []string {
	return []string{
		"ip", "netns", "exec", OffHostNetns,
		"curl", "-sS", "-k", "-o", "/dev/null",
		"--connect-timeout", strconv.Itoa(int(timeout.Seconds())),
		"-w", "%{http_code}",
		"https://" + hostPort + "/version",
	}
}
