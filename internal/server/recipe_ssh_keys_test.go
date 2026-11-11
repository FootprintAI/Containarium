package server

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3514: DeployRecipeRequest.ssh_keys is forwarded to the inner
// CreateContainer, so a recipe-deployed box is reachable over SSH by the
// person it was made for without a second AddSSHKey call. An invalid or
// over-bound key refuses the whole deploy before any box is created.

const sshKeysRecipeYAML = `recipes:
  - id: plain
    image: x
    post_start:
      - echo up
`

// createRecordingBoxes records every CreateContainerRequest the deploy hands
// the box backend, and can hold post_start until released (the async case).
type createRecordingBoxes struct {
	*fakeRecipeBoxes
	mu       sync.Mutex
	requests []*pb.CreateContainerRequest
	// holdPostStart, when set, blocks every post_start run until closed.
	holdPostStart chan struct{}
	postStartRan  chan struct{}
}

func (b *createRecordingBoxes) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	b.mu.Lock()
	b.requests = append(b.requests, proto.Clone(req).(*pb.CreateContainerRequest))
	b.mu.Unlock()
	return b.fakeRecipeBoxes.CreateContainer(ctx, req)
}

func (b *createRecordingBoxes) ExecWithExitCode(name string, command []string) (string, string, int, error) {
	if b.holdPostStart != nil {
		<-b.holdPostStart
	}
	defer func() {
		if b.postStartRan != nil {
			close(b.postStartRan)
		}
	}()
	return b.fakeRecipeBoxes.ExecWithExitCode(name, command)
}

func (b *createRecordingBoxes) createRequests() []*pb.CreateContainerRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*pb.CreateContainerRequest(nil), b.requests...)
}

func newSSHKeysRecipeServer(t *testing.T) (*RecipeServer, *createRecordingBoxes) {
	t.Helper()
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(sshKeysRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	boxes := &createRecordingBoxes{fakeRecipeBoxes: &fakeRecipeBoxes{}}
	return &RecipeServer{catalog: catalog, boxes: boxes}, boxes
}

func TestDeployRecipe_ForwardsSSHKeysToInnerCreate(t *testing.T) {
	srv, boxes := newSSHKeysRecipeServer(t)
	keys := []string{newTestPubKey(t), newTestPubKey(t)}
	labels := map[string]string{"org": "acme"}
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId: "plain", Name: "alice", SshKeys: keys, Labels: labels,
	}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got := boxes.createRequests()
	if len(got) != 1 {
		t.Fatalf("inner CreateContainer called %d times, want 1", len(got))
	}
	if strings.Join(got[0].GetSshKeys(), "|") != strings.Join(keys, "|") {
		t.Errorf("inner create ssh_keys = %q, want %q (same keys, same order)", got[0].GetSshKeys(), keys)
	}
	if got[0].GetLabels()["org"] != "acme" {
		t.Errorf("labels no longer forwarded alongside ssh_keys: %v", got[0].GetLabels())
	}
}

// An empty ssh_keys builds the same inner CreateContainerRequest as before
// the field existed: no keys, nothing else changed.
func TestDeployRecipe_NoSSHKeysInnerCreateUnchanged(t *testing.T) {
	srv, boxes := newSSHKeysRecipeServer(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "plain", Name: "alice"}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got := boxes.createRequests()
	if len(got) != 1 {
		t.Fatalf("inner CreateContainer called %d times, want 1", len(got))
	}
	want := &pb.CreateContainerRequest{
		Username:     "alice",
		Image:        recipeBaseImage,
		EnablePodman: true,
		Resources:    resourceLimits(mustRecipe(t, srv, "plain"), nil),
	}
	if !proto.Equal(got[0], want) {
		t.Errorf("inner create = %v, want %v", got[0], want)
	}
}

func mustRecipe(t *testing.T, srv *RecipeServer, id string) *pb.Recipe {
	t.Helper()
	r, err := srv.catalog.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// An invalid or over-bound key refuses the deploy with InvalidArgument
// naming the offending field, before the box exists and before post_start.
func TestDeployRecipe_BadSSHKeysRefusedBeforeCreate(t *testing.T) {
	valid := newTestPubKey(t)
	tooMany := make([]string, MaxSSHKeys+1)
	for i := range tooMany {
		tooMany[i] = valid
	}
	for _, tc := range []struct {
		name string
		keys []string
		want string
	}{
		{"not a key", []string{"not-a-key"}, "ssh_keys[0]"},
		{"second key invalid", []string{valid, "ssh-ed25519 AAAA"}, "ssh_keys[1]"},
		{"placeholder", []string{"ssh-ed25519 YOUR_KEY_HERE"}, "ssh_keys[0]"},
		{"too many keys", tooMany, "ssh_keys has 33 entries, max is 32"},
		{"oversized key", []string{strings.Repeat("a", MaxSSHKeyLength+1)}, "ssh_keys[0] is 8193 bytes, max is 8192"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, boxes := newSSHKeysRecipeServer(t)
			ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
			_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "plain", Name: "alice", SshKeys: tc.keys})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("deploy err = %v, want InvalidArgument", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("deploy err = %q, want it to name %q", err, tc.want)
			}
			if n := len(boxes.createRequests()); n != 0 {
				t.Errorf("inner CreateContainer called %d times for a refused deploy, want 0", n)
			}
			if len(boxes.events) != 0 {
				t.Errorf("box events %v for a refused deploy, want none (no create, no post_start)", boxes.events)
			}
		})
	}
}

// A guardrail-gated recipe refuses a bad key before the gate snapshots the
// dataset, so a refused deploy leaves no snapshot behind.
func TestDeployRecipe_BadSSHKeyRefusedBeforeGuardrailGate(t *testing.T) {
	f := newGateFixture(t)
	f.req.SshKeys = []string{"not-a-key"}
	_, err := f.srv.DeployRecipe(tenantWithScopes("alice", auth.ScopeContainersWrite), f.req)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "ssh_keys[0]") {
		t.Fatalf("deploy err = %v, want InvalidArgument naming ssh_keys[0]", err)
	}
	if len(f.boxes.created) != 0 {
		t.Errorf("created %v for a refused deploy", f.boxes.created)
	}
	f.assertNoSnapshotLeft(t)
}

// async: the keys are applied by the create, not by post_start, so the box
// carries them while post_start is still running.
func TestDeployRecipe_AsyncSSHKeysAppliedBeforePostStart(t *testing.T) {
	srv, boxes := newSSHKeysRecipeServer(t)
	boxes.holdPostStart = make(chan struct{})
	boxes.postStartRan = make(chan struct{})
	key := newTestPubKey(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId: "plain", Name: "alice", Async: true, SshKeys: []string{key},
	}); err != nil {
		t.Fatalf("async deploy: %v", err)
	}
	// post_start is still held: the create already carried the key.
	got := boxes.createRequests()
	if len(got) != 1 || len(got[0].GetSshKeys()) != 1 || got[0].GetSshKeys()[0] != key {
		t.Fatalf("inner create before post_start = %v, want ssh_keys [%q]", got, key)
	}
	close(boxes.holdPostStart)
	<-boxes.postStartRan
}
