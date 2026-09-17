package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/pkg/core/network"
)

// #1462: a recipe-deployed box's TCP/UDP passthrough routes must be removed
// on delete, the same way its HTTP routes already are — otherwise a deleted
// box's external_port stays claimed forever, and a later recipe deploy
// wanting the same port fails with a stale "already claimed" conflict.
func TestCascadeContainerCleanup_RemovesOwnedPassthroughRoutes(t *testing.T) {
	store := newFakePassthroughStore()
	ctx := context.Background()

	if err := store.Save(ctx, &network.PassthroughRecord{
		ExternalPort: 4566, TargetIP: "10.0.3.5", TargetPort: 4566,
		Protocol: "tcp", ContainerName: "alice-container", Active: true,
	}); err != nil {
		t.Fatalf("seed alice route: %v", err)
	}
	if err := store.Save(ctx, &network.PassthroughRecord{
		ExternalPort: 4567, TargetIP: "10.0.3.9", TargetPort: 4567,
		Protocol: "tcp", ContainerName: "bob-container", Active: true,
	}); err != nil {
		t.Fatalf("seed bob route: %v", err)
	}

	s := &ContainerServer{passthroughStore: store}
	s.cascadeContainerCleanup(ctx, "alice-container", "alice")

	if _, err := store.GetByPortProtocol(ctx, 4566, "tcp"); err != network.ErrPassthroughNotFound {
		t.Errorf("alice's passthrough route should be gone after delete, got err=%v", err)
	}
	if _, err := store.GetByPortProtocol(ctx, 4567, "tcp"); err != nil {
		t.Errorf("bob's passthrough route must survive alice's delete, got err=%v", err)
	}
}

// A daemon with no Postgres-backed passthrough store must skip this cascade
// step without panicking — the same nil handling routeStore already gets.
func TestCascadeContainerCleanup_NilPassthroughStoreIsSkippedGracefully(t *testing.T) {
	s := &ContainerServer{}
	s.cascadeContainerCleanup(context.Background(), "alice-container", "alice")
}
