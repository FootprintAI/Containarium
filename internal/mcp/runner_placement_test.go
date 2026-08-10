package mcp

import (
	"context"
	"testing"
)

// #1216: `runner provision` / `provision_runners` could not say WHERE the
// runner boxes should land, while the create primitive underneath them
// could. So the lower-level call expressed placement and the workflow built
// on top of it could not — runners always landed on the default backend.
//
// The acceptance criterion this covers is deliberately about the wire, not
// the flag: "a test asserts the placement argument reaches the create call
// rather than being silently dropped". A flag that parses and then goes
// nowhere is the failure mode, and it looks identical to a working one.

// capturingCreateAPI records the CreateContainerRequest the runner creator
// builds.
type capturingCreateAPI struct {
	API
	got CreateContainerRequest
}

func (c *capturingCreateAPI) CreateContainer(req CreateContainerRequest) (*CreateContainerResponse, error) {
	c.got = req
	return &CreateContainerResponse{
		Container: Container{Name: req.Username, Username: req.Username},
	}, nil
}

// buildCreator extracts the creator the runner deps are wired with, by
// building the deps and invoking the box manager's create path.
func createWithPlacement(t *testing.T, place placement) CreateContainerRequest {
	t.Helper()
	api := &capturingCreateAPI{}

	// withSSH=false skips the sentinel/SSH-key requirements; the creator is
	// wired identically either way, and the creator is what is under test.
	deps, _, err := buildMCPRunnerDeps(api, "", "", false, place)
	if err != nil {
		t.Fatalf("buildMCPRunnerDeps: %v", err)
	}
	if _, _, err := deps.Boxes.Create(context.Background(), "ci-runner-1", "ssh-ed25519 AAAA test"); err != nil {
		t.Fatalf("create: %v", err)
	}
	return api.got
}

func TestProvisionRunners_PlacementReachesTheCreateCall(t *testing.T) {
	got := createWithPlacement(t, placement{BackendID: "tunnel-gpu-node-a"})

	if got.BackendID != "tunnel-gpu-node-a" {
		t.Errorf("backendId = %q, want %q — the placement was accepted and then dropped, so the "+
			"runners land on the default backend while the caller believes otherwise (#1216)",
			got.BackendID, "tunnel-gpu-node-a")
	}
}

func TestProvisionRunners_PoolReachesTheCreateCall(t *testing.T) {
	got := createWithPlacement(t, placement{Pool: "gpu-pool"})

	if got.Pool != "gpu-pool" {
		t.Errorf("pool = %q, want %q (#1216)", got.Pool, "gpu-pool")
	}
}

// Omitting both must preserve today's placement exactly — this is an added
// capability, not a change to existing callers.
func TestProvisionRunners_NoPlacementLeavesTheRequestUnchanged(t *testing.T) {
	got := createWithPlacement(t, placement{})

	if got.Pool != "" || got.BackendID != "" {
		t.Errorf("pool=%q backendId=%q, want both empty so the daemon's default placement is "+
			"untouched for callers that never asked for one", got.Pool, got.BackendID)
	}
	// The rest of the runner box shape must be unaffected either way.
	if !got.EnablePodman || got.Image != "images:ubuntu/24.04" {
		t.Errorf("runner box shape changed: podman=%v image=%q", got.EnablePodman, got.Image)
	}
}

// Both set is a caller error the DAEMON validates (backend must belong to the
// pool). The tool must forward the pair rather than silently resolving it
// itself — otherwise the CLI and MCP would disagree about what is legal.
func TestProvisionRunners_ForwardsBothForDaemonValidation(t *testing.T) {
	got := createWithPlacement(t, placement{Pool: "gpu-pool", BackendID: "tunnel-gpu-node-a"})

	if got.Pool != "gpu-pool" || got.BackendID != "tunnel-gpu-node-a" {
		t.Errorf("pool=%q backendId=%q — both must reach the daemon so its existing "+
			"backend/pool consistency check is the single arbiter", got.Pool, got.BackendID)
	}
}
