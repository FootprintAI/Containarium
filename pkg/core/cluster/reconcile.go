package cluster

import (
	"fmt"
	"sort"
)

// The reconcile decision function — pure, exhaustively table-tested
// (the autosleep decide.go house pattern). The daemon-side loop builds
// Desired from the store record and Observed from the host, and
// executes whatever Decide returns; all policy lives here.
//
// Deliberately NOT here: scale-down. Removing surplus workers is the
// cluster-autoscaler's job (it drains first); the reconciler only
// creates up to each group's Min, restarts stopped VMs, and tears down
// deleting clusters. See the design's "Who decides what".

// DesiredGroup is one node group's desired shape.
type DesiredGroup struct {
	Name     string
	Min, Max int
	CPU      string
	Memory   string
	Disk     string
}

// Desired is a cluster's desired state, derived from the store record.
type Desired struct {
	Tenant  string
	Cluster string
	// Deleting means the record is in state DELETING: every VM goes.
	Deleting bool
	Groups   []DesiredGroup
}

// ObservedVM is one cluster VM as the host reports it.
type ObservedVM struct {
	Name    string
	Running bool
}

// Observed is the host's view of a cluster's VMs.
type Observed struct {
	CP *ObservedVM
	// Workers by group name. Names follow WorkerName; the observer
	// buckets them by the node_group label, not by parsing names.
	Workers map[string][]ObservedVM
}

// ActionKind enumerates what the reconciler can do in one pass.
type ActionKind int

const (
	ActionCreateCP ActionKind = iota
	ActionStartVM
	ActionCreateWorker
	ActionDeleteVM
)

func (k ActionKind) String() string {
	switch k {
	case ActionCreateCP:
		return "create-cp"
	case ActionStartVM:
		return "start-vm"
	case ActionCreateWorker:
		return "create-worker"
	case ActionDeleteVM:
		return "delete-vm"
	default:
		return fmt.Sprintf("actionkind(%d)", int(k))
	}
}

// Action is one step the loop executes.
type Action struct {
	Kind  ActionKind
	Group string // worker actions only
	// Name is the VM the action targets (for creates, the name to
	// create under).
	Name string
}

// Decide computes the actions that move Observed toward Desired.
// Invariants:
//   - a deleting cluster tears down workers first, control plane last;
//   - no worker is created before the control plane exists and runs
//     (agents need a server to join);
//   - stopped VMs are started, missing ones created — never both for
//     the same name in one pass;
//   - creation converges to each group's Min; anything between Min and
//     Max is the autoscaler's territory and is left alone;
//   - scale-down never happens here.
func Decide(d Desired, o Observed) []Action {
	if d.Deleting {
		var acts []Action
		groups := sortedKeys(o.Workers)
		for _, g := range groups {
			for _, w := range o.Workers[g] {
				acts = append(acts, Action{Kind: ActionDeleteVM, Group: g, Name: w.Name})
			}
		}
		if o.CP != nil {
			acts = append(acts, Action{Kind: ActionDeleteVM, Name: o.CP.Name})
		}
		return acts
	}

	cpName := CPName(d.Tenant, d.Cluster)
	if o.CP == nil {
		return []Action{{Kind: ActionCreateCP, Name: cpName}}
	}
	if !o.CP.Running {
		return []Action{{Kind: ActionStartVM, Name: o.CP.Name}}
	}

	var acts []Action
	for _, g := range d.Groups {
		observed := o.Workers[g.Name]
		inUse := make(map[string]bool, len(observed))
		alive := 0
		for _, w := range observed {
			inUse[w.Name] = true
			if !w.Running {
				acts = append(acts, Action{Kind: ActionStartVM, Group: g.Name, Name: w.Name})
			}
			alive++ // stopped VMs are being started, not replaced
		}
		for n := 1; alive < g.Min; n++ {
			name := WorkerName(d.Tenant, d.Cluster, g.Name, n)
			if inUse[name] {
				continue
			}
			acts = append(acts, Action{Kind: ActionCreateWorker, Group: g.Name, Name: name})
			inUse[name] = true
			alive++
		}
	}
	return acts
}

func sortedKeys(m map[string][]ObservedVM) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
