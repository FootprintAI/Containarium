//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	clusterstore "github.com/footprintai/containarium/internal/cluster"
	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
)

// The re-mint pass moves ready clusters onto the id-bearing autoscaler
// credential (#3689 stage 3a). A failure is logged and retried; it never sets a
// cluster to ERROR, and a bound cluster is not deployed again.

func remintFixture(t *testing.T, clusters ...*clusterstore.Cluster) (*clusterstore.MemStore, *ClusterReconciler, *[]string) {
	t.Helper()
	store := clusterstore.NewMemStore()
	for _, c := range clusters {
		if err := store.Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	deployed := &[]string{}
	r := &ClusterReconciler{
		store:  store,
		caAddr: "10.0.0.1:36442",
		mintCACert: func(owner, name, id string) (clustercore.CACredentials, error) {
			return clustercore.CACredentials{}, nil
		},
		deployCA: func(owner, name string, _ clustercore.CADeploy, _ clustercore.CACredentials) error {
			*deployed = append(*deployed, owner+"/"+name)
			return nil
		},
	}
	return store, r, deployed
}

func ready(owner, name string, bound bool) *clusterstore.Cluster {
	return &clusterstore.Cluster{ID: owner + "-" + name + "-id", Owner: owner, Name: name, State: clusterstore.StateReady, CAIDBound: bound, CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func TestRemintMovesAReadyClusterOntoTheIdCredential(t *testing.T) {
	store, r, deployed := remintFixture(t, ready("alice", "demo", false))
	r.remintCAIdentities(context.Background(), mustList(t, store))
	if len(*deployed) != 1 || (*deployed)[0] != "alice/demo" {
		t.Fatalf("deployed = %v, want alice/demo", *deployed)
	}
	c, _ := store.Get(context.Background(), "alice", "demo")
	if !c.CAIDBound {
		t.Error("the re-minted cluster was not marked CA-id bound")
	}
	if c.State != clusterstore.StateReady {
		t.Errorf("state = %v, want READY", c.State)
	}
}

func TestRemintSkipsAnAlreadyBoundCluster(t *testing.T) {
	store, r, deployed := remintFixture(t, ready("alice", "demo", true))
	r.remintCAIdentities(context.Background(), mustList(t, store))
	if len(*deployed) != 0 {
		t.Errorf("a bound cluster was deployed again: %v", *deployed)
	}
}

func TestRemintFailureNeverSetsErrorAndRetries(t *testing.T) {
	store, r, _ := remintFixture(t, ready("alice", "demo", false))
	r.deployCA = func(string, string, clustercore.CADeploy, clustercore.CACredentials) error {
		return errors.New("host unreachable")
	}
	r.remintCAIdentities(context.Background(), mustList(t, store))
	c, _ := store.Get(context.Background(), "alice", "demo")
	if c.State != clusterstore.StateReady {
		t.Errorf("a failed re-mint changed the state to %v; it must stay READY", c.State)
	}
	if c.CAIDBound {
		t.Error("a failed re-mint was recorded as bound")
	}
}

func TestRemintLeavesAClusterThatIsNotReadyAlone(t *testing.T) {
	provisioning := ready("alice", "demo", false)
	provisioning.State = clusterstore.StateProvisioning
	store, r, deployed := remintFixture(t, provisioning)
	r.remintCAIdentities(context.Background(), mustList(t, store))
	if len(*deployed) != 0 {
		t.Errorf("a provisioning cluster was re-minted: %v", *deployed)
	}
}

func mustList(t *testing.T, store clusterstore.Store) []*clusterstore.Cluster {
	t.Helper()
	cs, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	return cs
}
