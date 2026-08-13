//go:build integration

// Integration coverage for the collaborator store (#1300).
//
// This store is access control. A row grants a named user SSH access to
// someone else's container, and carries the privilege flags — sudo, container
// runtime — that decide what they can do once inside. None of its SQL had ever
// been executed by a test.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/collaborator/
package collaborator

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func collabStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping — this is access " +
			"control, and a skipped test looks exactly like a passing one.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS collaborators`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	pool.Close()

	s, err := NewStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func add(t *testing.T, s *Store, container, owner, user string, sudo bool) {
	t.Helper()
	err := s.Add(context.Background(), &Collaborator{
		ContainerName:        container,
		OwnerUsername:        owner,
		CollaboratorUsername: user,
		AccountName:          container + "-" + user,
		SSHPublicKey:         "ssh-ed25519 AAAA" + user,
		CreatedBy:            owner,
		HasSudo:              sudo,
	})
	if err != nil {
		t.Fatalf("add %s to %s: %v", user, container, err)
	}
}

// A grant must round-trip exactly, privilege flags included. Reading back a
// collaborator with more privilege than was granted is a silent escalation.
func TestCollaboratorStore_GrantRoundTripsWithItsPrivileges(t *testing.T) {
	ctx := context.Background()
	s := collabStore(t)

	add(t, s, "alice-container", "alice", "bob", false)

	got, err := s.Get(ctx, "alice-container", "bob")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.OwnerUsername != "alice" || got.SSHPublicKey != "ssh-ed25519 AAAAbob" {
		t.Errorf("grant did not round-trip: %+v", got)
	}
	if got.HasSudo {
		t.Error("a collaborator added without sudo reads back WITH sudo — a silent privilege " +
			"escalation, and nothing about it would look wrong to an operator")
	}
	if got.HasContainerRuntime {
		t.Error("container-runtime access appeared without being granted")
	}
}

// The privilege flag has to survive when it IS granted, or the opposite bug:
// an operator grants sudo, the store drops it, and the grant looks applied.
func TestCollaboratorStore_SudoSurvivesWhenGranted(t *testing.T) {
	ctx := context.Background()
	s := collabStore(t)

	add(t, s, "alice-container", "alice", "carol", true)

	got, err := s.Get(ctx, "alice-container", "carol")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.HasSudo {
		t.Error("granted sudo did not survive the round trip")
	}
}

// Listing by collaborator must return only that user's grants. A wrong WHERE
// clause here reports access to containers the caller was never given.
func TestCollaboratorStore_ListingIsScopedToTheSubject(t *testing.T) {
	ctx := context.Background()
	s := collabStore(t)

	add(t, s, "alice-container", "alice", "bob", false)
	add(t, s, "dave-container", "dave", "bob", false)
	add(t, s, "alice-container", "alice", "erin", false)

	byCollab, err := s.ListByCollaborator(ctx, "bob")
	if err != nil {
		t.Fatalf("ListByCollaborator: %v", err)
	}
	if len(byCollab) != 2 {
		t.Errorf("bob has %d grants, want 2", len(byCollab))
	}
	for _, c := range byCollab {
		if c.CollaboratorUsername != "bob" {
			t.Errorf("listing bob's access returned a grant to %q — one user's list would show "+
				"another's containers", c.CollaboratorUsername)
		}
	}

	perContainer, err := s.List(ctx, "alice-container")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(perContainer) != 2 {
		t.Errorf("alice-container has %d collaborators, want 2 (bob, erin); got %+v",
			len(perContainer), perContainer)
	}
	for _, c := range perContainer {
		if c.ContainerName != "alice-container" {
			t.Errorf("listing one container's collaborators returned a grant on %q", c.ContainerName)
		}
	}
}

// Removal is revocation. If it does not take, access continues after the
// operator has been told it was withdrawn.
func TestCollaboratorStore_RemoveRevokesOnlyThatGrant(t *testing.T) {
	ctx := context.Background()
	s := collabStore(t)

	add(t, s, "alice-container", "alice", "bob", false)
	add(t, s, "dave-container", "dave", "bob", false)

	if err := s.Remove(ctx, "alice-container", "bob"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := s.Get(ctx, "alice-container", "bob"); err == nil {
		t.Error("a removed collaborator is still readable — access continues after the operator " +
			"was told it was revoked")
	}

	// The same user's access to a different container must be untouched.
	if _, err := s.Get(ctx, "dave-container", "bob"); err != nil {
		t.Errorf("removing one grant revoked an unrelated one: %v", err)
	}
}
