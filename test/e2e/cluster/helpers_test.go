package clustere2e

import (
	"os"
	"reflect"
	"strings"
	"testing"
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
