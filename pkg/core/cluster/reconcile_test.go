package cluster

import (
	"reflect"
	"testing"
)

func TestDecide(t *testing.T) {
	desired := Desired{
		Tenant:  "alice",
		Cluster: "demo",
		Groups: []DesiredGroup{
			{Name: "small", Min: 2, Max: 3},
			{Name: "large", Min: 0, Max: 1},
		},
	}
	cp := func(running bool) *ObservedVM {
		return &ObservedVM{Name: "alice-k8s-demo-cp", Running: running}
	}

	cases := []struct {
		name     string
		desired  Desired
		observed Observed
		want     []Action
	}{
		{
			"fresh cluster creates the control plane first, no workers yet",
			desired,
			Observed{},
			[]Action{{Kind: ActionCreateCP, Name: "alice-k8s-demo-cp"}},
		},
		{
			"stopped control plane is started, not replaced",
			desired,
			Observed{CP: cp(false)},
			[]Action{{Kind: ActionStartVM, Name: "alice-k8s-demo-cp"}},
		},
		{
			"running control plane converges each group to its min",
			desired,
			Observed{CP: cp(true)},
			[]Action{
				{Kind: ActionCreateWorker, Group: "small", Name: "alice-k8s-demo-small-1"},
				{Kind: ActionCreateWorker, Group: "small", Name: "alice-k8s-demo-small-2"},
			},
		},
		{
			"lost worker is replaced under an unused index",
			desired,
			Observed{CP: cp(true), Workers: map[string][]ObservedVM{
				"small": {{Name: "alice-k8s-demo-small-2", Running: true}},
			}},
			[]Action{
				{Kind: ActionCreateWorker, Group: "small", Name: "alice-k8s-demo-small-1"},
			},
		},
		{
			"stopped worker is started, never started AND replaced in one pass",
			desired,
			Observed{CP: cp(true), Workers: map[string][]ObservedVM{
				"small": {
					{Name: "alice-k8s-demo-small-1", Running: false},
					{Name: "alice-k8s-demo-small-2", Running: true},
				},
			}},
			[]Action{
				{Kind: ActionStartVM, Group: "small", Name: "alice-k8s-demo-small-1"},
			},
		},
		{
			"between min and max is the autoscaler's territory — no scale-down",
			desired,
			Observed{CP: cp(true), Workers: map[string][]ObservedVM{
				"small": {
					{Name: "alice-k8s-demo-small-1", Running: true},
					{Name: "alice-k8s-demo-small-2", Running: true},
					{Name: "alice-k8s-demo-small-3", Running: true},
				},
			}},
			nil,
		},
		{
			"deleting tears down workers first, control plane last",
			Desired{Tenant: "alice", Cluster: "demo", Deleting: true},
			Observed{CP: cp(true), Workers: map[string][]ObservedVM{
				"small": {{Name: "alice-k8s-demo-small-1", Running: true}},
			}},
			[]Action{
				{Kind: ActionDeleteVM, Group: "small", Name: "alice-k8s-demo-small-1"},
				{Kind: ActionDeleteVM, Name: "alice-k8s-demo-cp"},
			},
		},
		{
			"deleting with nothing observed does nothing",
			Desired{Tenant: "alice", Cluster: "demo", Deleting: true},
			Observed{},
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.desired, tc.observed)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Decide() =\n  %+v\nwant\n  %+v", got, tc.want)
			}
		})
	}
}

func TestNamingAndLabels(t *testing.T) {
	if got := CPName("alice", "demo"); got != "alice-k8s-demo-cp" {
		t.Fatalf("CPName = %q", got)
	}
	if got := WorkerName("alice", "demo", "small", 3); got != "alice-k8s-demo-small-3" {
		t.Fatalf("WorkerName = %q", got)
	}
	l := VMLabels("alice", "demo", RoleWorker, "small")
	for k, want := range map[string]string{
		LabelCluster:       "demo",
		LabelClusterOwner:  "alice",
		LabelClusterRole:   "worker",
		LabelNodeGroup:     "small",
		LabelWorkloadClass: "k8s-node",
	} {
		if l[k] != want {
			t.Fatalf("label %s = %q, want %q", k, l[k], want)
		}
	}
	if _, ok := VMLabels("alice", "demo", RoleControlPlane, "")[LabelNodeGroup]; ok {
		t.Fatal("control-plane labels must not carry a node_group")
	}
}
