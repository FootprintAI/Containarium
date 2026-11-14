//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"testing"

	clusterstore "github.com/footprintai/containarium/internal/cluster"
	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
)

// Clusters re-minted before the restart fix are bound but deployed with an old
// generation, so the forced pass re-deploys each once (#3720).

func behindCluster(owner, name string, gen int) *clusterstore.Cluster {
	c := ready(owner, name, true)
	c.CADeployGen = gen
	return c
}

func TestForceDeployRedeploysAClusterBehindTheGeneration(t *testing.T) {
	store, r, deployed := remintFixture(t, behindCluster("alice", "demo", 0))
	r.forceCADeploys(context.Background(), mustList(t, store))
	if len(*deployed) != 1 || (*deployed)[0] != "alice/demo" {
		t.Fatalf("deployed = %v, want alice/demo", *deployed)
	}
	c, _ := store.Get(context.Background(), "alice", "demo")
	if c.CADeployGen != clusterstore.CADeployGeneration {
		t.Errorf("generation = %d, want %d after the forced deploy", c.CADeployGen, clusterstore.CADeployGeneration)
	}
}

func TestForceDeploySkipsACurrentCluster(t *testing.T) {
	store, r, deployed := remintFixture(t, behindCluster("alice", "demo", clusterstore.CADeployGeneration))
	r.forceCADeploys(context.Background(), mustList(t, store))
	if len(*deployed) != 0 {
		t.Errorf("a current cluster was re-deployed: %v", *deployed)
	}
}

func TestForceDeploySkipsAnUnboundOrNotReadyCluster(t *testing.T) {
	unbound := ready("alice", "unbound", false)
	provisioning := behindCluster("alice", "provisioning", 0)
	provisioning.State = clusterstore.StateProvisioning
	store, r, deployed := remintFixture(t, unbound, provisioning)
	r.forceCADeploys(context.Background(), mustList(t, store))
	if len(*deployed) != 0 {
		t.Errorf("a cluster the re-mint pass owns, or a non-ready one, was forced: %v", *deployed)
	}
}

func TestForceDeployFailureLeavesGenerationAndState(t *testing.T) {
	store, r, _ := remintFixture(t, behindCluster("alice", "demo", 0))
	r.deployCA = func(string, string, clustercore.CADeploy, clustercore.CACredentials) error {
		return errors.New("host unreachable")
	}
	r.forceCADeploys(context.Background(), mustList(t, store))
	c, _ := store.Get(context.Background(), "alice", "demo")
	if c.CADeployGen != 0 {
		t.Errorf("a failed forced deploy recorded generation %d", c.CADeployGen)
	}
	if c.State != clusterstore.StateReady {
		t.Errorf("a failed forced deploy changed the state to %v; it must stay READY", c.State)
	}
}
