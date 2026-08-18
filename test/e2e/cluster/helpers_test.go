package clustere2e

import (
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
