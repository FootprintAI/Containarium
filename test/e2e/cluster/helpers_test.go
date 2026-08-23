package clustere2e

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A minimal but real kubeconfig shape — two clusters, so the test can
// prove the helper follows current-context rather than "first cluster".
const twoClusterKubeconfig = `apiVersion: v1
kind: Config
current-context: outside
clusters:
- name: inside
  cluster:
    server: https://10.166.42.7:6443
- name: outside
  cluster:
    server: https://198.51.100.20:31843
contexts:
- name: inside
  context:
    cluster: inside
    user: admin
- name: outside
  context:
    cluster: outside
    user: admin
users:
- name: admin
  user:
    token: unused
`

func TestKubeconfigServerHost(t *testing.T) {
	tests := []struct {
		name       string
		kubeconfig string
		want       string
		wantErr    string
	}{
		{
			name:       "follows current-context, not first cluster",
			kubeconfig: twoClusterKubeconfig,
			want:       "198.51.100.20:31843",
		},
		{
			name: "no clusters is an error",
			kubeconfig: `apiVersion: v1
kind: Config
current-context: gone
`,
			wantErr: "gone",
		},
		{
			name:       "garbage is an error, not an empty host",
			kubeconfig: "{{not yaml",
			wantErr:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KubeconfigServerHost([]byte(tt.kubeconfig))
			if tt.wantErr != "" || tt.want == "" {
				if err == nil {
					t.Fatalf("want error, got host %q", got)
				}
				if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("host = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewReadyNodes(t *testing.T) {
	tests := []struct {
		name     string
		baseline []string
		current  map[string]bool
		want     []string
	}{
		{
			name:     "new ready node is reported",
			baseline: []string{"w-small-1"},
			current:  map[string]bool{"w-small-1": true, "w-small-2": true},
			want:     []string{"w-small-2"},
		},
		{
			name:     "new but NotReady node does not count",
			baseline: []string{"w-small-1"},
			current:  map[string]bool{"w-small-1": true, "w-small-2": false},
			want:     nil,
		},
		{
			name:     "baseline node flapping back to Ready is not new",
			baseline: []string{"w-small-1", "w-small-2"},
			current:  map[string]bool{"w-small-1": true, "w-small-2": true},
			want:     nil,
		},
		{
			name:     "output is sorted for stable logs",
			baseline: nil,
			current:  map[string]bool{"w-b": true, "w-a": true},
			want:     []string{"w-a", "w-b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewReadyNodes(tt.baseline, tt.current)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("NewReadyNodes = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSabotage(t *testing.T) {
	tests := []struct {
		value   string
		want    SabotageMode
		wantErr bool
	}{
		{value: "", want: SabotageNone},
		{value: "join-token", want: SabotageJoinToken},
		{value: "  join-token \n", want: SabotageJoinToken},
		// Fail closed: a typo'd sabotage value silently running the
		// normal green path would "prove" the lane can fail without
		// ever sabotaging anything.
		{value: "join_token", wantErr: true},
		{value: "none", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("value="+tt.value, func(t *testing.T) {
			got, err := ParseSabotage(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error for %q, got mode %v", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("mode = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaxRestartDelta(t *testing.T) {
	tests := []struct {
		name   string
		before map[string]int32
		after  map[string]int32
		want   int32
	}{
		{
			name:   "steady pods report zero",
			before: map[string]int32{"p1/app": 0},
			after:  map[string]int32{"p1/app": 0},
			want:   0,
		},
		{
			name:   "a restart-looping container dominates",
			before: map[string]int32{"p1/app": 1, "p2/app": 0},
			after:  map[string]int32{"p1/app": 1, "p2/app": 4},
			want:   4,
		},
		{
			name:   "a container unseen before counts from zero",
			before: map[string]int32{},
			after:  map[string]int32{"p3/app": 2},
			want:   2,
		},
		{
			name:   "a pod replaced by a fresh one is not a loop",
			before: map[string]int32{"p1/app": 3},
			after:  map[string]int32{"p9/app": 0},
			want:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaxRestartDelta(tt.before, tt.after); got != tt.want {
				t.Fatalf("MaxRestartDelta = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseIsolation(t *testing.T) {
	tests := []struct {
		value    string
		want     IsolationMode
		wantArgs []string
		wantErr  bool
	}{
		// Unset is VM: the KVM lane (#1418) sets nothing, and must keep
		// invoking `cluster create <name>` with no extra arguments.
		{value: "", want: IsolationVM, wantArgs: nil},
		{value: "vm", want: IsolationVM, wantArgs: nil},
		{value: "container", want: IsolationContainer, wantArgs: []string{"--isolation", "container"}},
		{value: "  container \n", want: IsolationContainer, wantArgs: []string{"--isolation", "container"}},
		// Fail closed, like ParseSabotage: a typo'd container run that
		// quietly took the VM path would report "container mode works"
		// having never asked for a container node.
		{value: "containers", wantErr: true},
		{value: "VM", wantErr: true},
		{value: "none", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("value="+tt.value, func(t *testing.T) {
			got, err := ParseIsolation(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error for %q, got mode %v", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("mode = %v, want %v", got, tt.want)
			}
			if args := got.CreateArgs(); !reflect.DeepEqual(args, tt.wantArgs) {
				t.Fatalf("CreateArgs = %v, want %v", args, tt.wantArgs)
			}
		})
	}
}

func TestWrongClassInstances(t *testing.T) {
	// The knob has to be provable: a container lane whose daemon quietly
	// provisioned VMs (or a VM lane that got containers) would run the
	// whole journey and report the wrong class as green. Incus's own
	// instance type is the observed state that settles it.
	tests := []struct {
		name   string
		all    []ClusterInstance
		mode   IsolationMode
		want   []string
		prefix string
	}{
		{
			name:   "container mode with container nodes is clean",
			all:    []ClusterInstance{{Name: "c-cp", Type: "container"}, {Name: "c-small-1", Type: "container"}},
			mode:   IsolationContainer,
			prefix: "c-",
			want:   nil,
		},
		{
			name:   "container mode that got a VM names it",
			all:    []ClusterInstance{{Name: "c-cp", Type: "container"}, {Name: "c-small-1", Type: "virtual-machine"}},
			mode:   IsolationContainer,
			prefix: "c-",
			want:   []string{"c-small-1 (virtual-machine)"},
		},
		{
			name:   "vm mode that got a container names it",
			all:    []ClusterInstance{{Name: "c-cp", Type: "container"}},
			mode:   IsolationVM,
			prefix: "c-",
			want:   []string{"c-cp (container)"},
		},
		{
			name:   "an unreported type is a mismatch, not a pass",
			all:    []ClusterInstance{{Name: "c-cp", Type: ""}},
			mode:   IsolationContainer,
			prefix: "c-",
			want:   []string{`c-cp ()`},
		},
		{
			name:   "instances outside the cluster are none of our business",
			all:    []ClusterInstance{{Name: "other-box", Type: "virtual-machine"}},
			mode:   IsolationContainer,
			prefix: "c-",
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrongClassInstances(tt.all, tt.prefix, tt.mode)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("WrongClassInstances = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClusterInstanceNames(t *testing.T) {
	// Container-mode nodes are Incus containers and VM-mode nodes are
	// Incus VMs, so the lane's instance-listing assertions match on the
	// cluster's name prefix and NEVER on the instance type — a type
	// filter would make the container lane observe an empty cluster and
	// call that "no leftover nodes".
	all := []ClusterInstance{
		{Name: "e2etenant-k8s-lane-cp", Type: "virtual-machine"},
		{Name: "e2etenant-k8s-lane-small-1", Type: "container"},
		{Name: "othertenant-k8s-lane-cp", Type: "container"},
		{Name: "e2etenant-k8s-other-cp", Type: "container"},
		{Name: "unrelated-box", Type: "container"},
	}
	tests := []struct {
		name   string
		all    []ClusterInstance
		prefix string
		want   []string
	}{
		{
			name:   "both instance types match on prefix alone",
			all:    all,
			prefix: "e2etenant-k8s-lane-",
			want:   []string{"e2etenant-k8s-lane-cp", "e2etenant-k8s-lane-small-1"},
		},
		{
			name:   "another tenant's or cluster's instances never match",
			all:    all,
			prefix: "nosuchtenant-k8s-lane-",
			want:   nil,
		},
		{
			name: "output is sorted for stable logs",
			all: []ClusterInstance{
				{Name: "p-b", Type: "container"},
				{Name: "p-a", Type: "virtual-machine"},
			},
			prefix: "p-",
			want:   []string{"p-a", "p-b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClusterInstanceNames(tt.all, tt.prefix)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ClusterInstanceNames = %v, want %v", got, tt.want)
			}
		})
	}
}

// #1514: the probe must not be answerable by the entrypoint's
// temporary init server, which listens on the Unix socket only.
//
// Asserted against the SCRIPT, not against a Go constant the script
// does not read. A helper checked only against itself is decorative:
// the bash could drift back to a socket probe and this would stay
// green, which is the same mistake — asserting on a representation
// instead of on what actually runs — that this sprint has now
// collected four times.
func TestLaneScriptProbesPostgresOverTCP(t *testing.T) {
	raw, err := os.ReadFile("../../../scripts/cluster-e2e.sh")
	if err != nil {
		t.Fatalf("read lane script: %v", err)
	}
	script := string(raw)

	var probes []string
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		// Comments talk ABOUT the probe; only what runs counts.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "pg_isready") {
			probes = append(probes, trimmed)
		}
	}
	if len(probes) == 0 {
		t.Fatal("the lane script has no pg_isready probe at all; this test is checking nothing")
	}

	want := strings.Join(PostgresReadyArgs("containarium"), " ")
	for _, p := range probes {
		if !strings.Contains(p, want) {
			t.Errorf("probe %q does not force TCP (want %q).\n"+
				"A default pg_isready uses the Unix socket, so it answers \"ready\" about the "+
				"entrypoint's TEMPORARY init server — which is then shut down, and the confirming "+
				"probe fails seven seconds into a ninety-second bound (#1514).", p, want)
		}
	}
}

// The knob: unset must not silently claim the tenant-facing path was
// verified, and a typo must not degrade to "none" — that is how a lane
// ends up reporting "reachable from outside" having never left the
// host (#1468).
func TestParseOffHostProbe(t *testing.T) {
	tests := []struct {
		value   string
		want    OffHostProbe
		wantErr bool
	}{
		{"", OffHostProbeNone, false},
		{"none", OffHostProbeNone, false},
		{"netns", OffHostProbeNetns, false},
		{" netns ", OffHostProbeNetns, false},
		{"netnss", OffHostProbeNone, true},
		{"true", OffHostProbeNone, true},
		{"1", OffHostProbeNone, true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ParseOffHostProbe(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseOffHostProbe(%q) = %v, want an error", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOffHostProbe(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("ParseOffHostProbe(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// The setup sequence is the contract, and its ORDER is the failure
// mode: address the peer before moving it into the namespace and the
// address is lost with the move; add the default route before the link
// is up and it is rejected. Asserted here so a reordering fails on any
// machine rather than only on a runner with root.
func TestOffHostSetupCommandOrder(t *testing.T) {
	cmds := OffHostSetupCommands()
	idx := func(match ...string) int {
		for i, c := range cmds {
			joined := strings.Join(c, " ")
			all := true
			for _, m := range match {
				if !strings.Contains(joined, m) {
					all = false
					break
				}
			}
			if all {
				return i
			}
		}
		return -1
	}

	addNetns := idx("netns", "add")
	createVeth := idx("link", "add", OffHostVethHost)
	movePeer := idx("link", "set", OffHostVethPeer, "netns")
	addrPeer := idx("netns", "exec", "addr", "add", OffHostPeerAddr)
	upPeer := idx("netns", "exec", "link", "set", OffHostVethPeer, "up")
	route := idx("netns", "exec", "route", "add", "default")

	for name, got := range map[string]int{
		"netns add": addNetns, "veth add": createVeth, "move peer": movePeer,
		"address peer": addrPeer, "peer up": upPeer, "default route": route,
	} {
		if got < 0 {
			t.Fatalf("setup sequence has no %q step: %v", name, cmds)
		}
	}
	if addNetns > createVeth {
		t.Error("the namespace must exist before a link can be moved into it")
	}
	if movePeer > addrPeer {
		t.Error("the peer must be moved into the namespace BEFORE it is addressed; moving it discards the address")
	}
	if upPeer > route {
		t.Error("the default route needs the peer link up first")
	}
	if addrPeer > route {
		t.Error("the default route's gateway is only reachable once the peer is addressed")
	}
}

// The probe must accept any TCP answer. An unauthenticated dial to the
// API server is expected to be refused at the AUTH layer — that is a
// pass, because reaching the auth layer means the packet traversed
// PREROUTING. Asserting on a 200 would make the probe fail for the one
// reason it must not care about.
func TestOffHostDialCommandProbesConnectivityNotAuth(t *testing.T) {
	got := strings.Join(OffHostDialCommand("203.0.113.7:36443", 10*time.Second), " ")
	for _, want := range []string{
		"ip netns exec " + OffHostNetns,
		"https://203.0.113.7:36443/version",
		"--connect-timeout 10",
		"-k",           // the cluster CA is not in the namespace's trust store
		"-o /dev/null", // the body is irrelevant; reachability is not
		"%{http_code}", // what the caller inspects
	} {
		if !strings.Contains(got, want) {
			t.Errorf("dial command %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "--fail") {
		t.Error("--fail would turn a 401 into a probe failure, but a 401 proves the packet arrived")
	}
}

// A leaked namespace from a killed run must not make the next run
// fail: teardown removes it by a fixed name, so the next setup can
// clear it first.
func TestOffHostTeardownRemovesTheNamespace(t *testing.T) {
	got := OffHostTeardownCommands()
	if len(got) == 0 {
		t.Fatal("teardown does nothing, so a killed run leaks a namespace and a veth forever")
	}
	joined := strings.Join(got[0], " ")
	if !strings.Contains(joined, "netns del "+OffHostNetns) {
		t.Errorf("teardown does not delete the namespace: %v", got)
	}
}

// The proof mode for #1468. A typo here is worse than elsewhere: a
// sabotage value that silently degrades to "none" produces a green
// suite, which the job then reports as "the lane cannot fail" — the
// exact inversion the guardrail exists to prevent.
func TestParseSabotageKnowsDropPrerouting(t *testing.T) {
	got, err := ParseSabotage("drop-prerouting")
	if err != nil {
		t.Fatalf("ParseSabotage(drop-prerouting): %v", err)
	}
	if got != SabotageDropPrerouting {
		t.Errorf("ParseSabotage(drop-prerouting) = %v, want SabotageDropPrerouting", got)
	}
	if _, err := ParseSabotage("drop-preroute"); err == nil {
		t.Error("a near-miss must be an error, not a silent SabotageNone")
	}
}

// The sabotage must delete the rule the PRODUCT installs, not a
// lookalike: it targets the nat table's PREROUTING chain by protocol
// and destination port, and must not touch OUTPUT — leaving OUTPUT in
// place is precisely what makes the host still able to connect while
// nothing else can.
func TestDropPreroutingCommandTargetsTheInboundRuleOnly(t *testing.T) {
	got := strings.Join(DropPreroutingCommand(36443), " ")
	for _, want := range []string{"-t nat", "-D PREROUTING", "-p tcp", "--dport 36443"} {
		if !strings.Contains(got, want) {
			t.Errorf("drop command %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "OUTPUT") {
		t.Error("the sabotage must leave the OUTPUT rule alone; removing both would break the host's own dial too, " +
			"and the suite would go red without proving anything about the tenant-facing path")
	}
}
