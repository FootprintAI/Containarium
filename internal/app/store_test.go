package app

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Note: These tests require a running PostgreSQL instance.
// For unit testing without external dependencies, we'd need to mock the pgxpool.
// For now, these are integration-style tests that can be run with:
// docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=containarium postgres:16-alpine

func createTestApp(username, name string) *v1.App {
	now := timestamppb.Now()
	return &v1.App{
		Id:             uuid.New().String(),
		Name:           name,
		Username:       username,
		ContainerName:  username + "-container",
		Subdomain:      name,
		FullDomain:     name + ".containarium.dev",
		Port:           3000,
		State:          v1.AppState_APP_STATE_RUNNING,
		ContainerImage: username + "/" + name + ":latest",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func TestStoreOperations(t *testing.T) {
	// Gated on the DSN rather than skipped unconditionally. "Run integration
	// tests separately" deferred to a lane that did not exist, so these never
	// ran anywhere (#1300). The store-integration lane sets this.
	connString := os.Getenv("CONTAINARIUM_TEST_DSN")
	if connString == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}

	ctx := context.Background()

	store, err := NewStore(ctx, connString)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	// Test Save
	app := createTestApp("alice", "myapp")
	if err := store.Save(ctx, app); err != nil {
		t.Errorf("Save() error = %v", err)
	}

	// Test GetByID
	retrieved, err := store.GetByID(ctx, app.Id)
	if err != nil {
		t.Errorf("GetByID() error = %v", err)
	}
	if retrieved.Id != app.Id {
		t.Errorf("GetByID() id = %v, want %v", retrieved.Id, app.Id)
	}

	// Test GetByName
	retrieved, err = store.GetByName(ctx, "alice", "myapp")
	if err != nil {
		t.Errorf("GetByName() error = %v", err)
	}
	if retrieved.Name != "myapp" {
		t.Errorf("GetByName() name = %v, want myapp", retrieved.Name)
	}

	// Test List
	apps, err := store.List(ctx, "alice", v1.AppState_APP_STATE_UNSPECIFIED)
	if err != nil {
		t.Errorf("List() error = %v", err)
	}
	if len(apps) == 0 {
		t.Error("List() returned no apps")
	}

	// Test Count
	count, err := store.Count(ctx, "alice", v1.AppState_APP_STATE_UNSPECIFIED)
	if err != nil {
		t.Errorf("Count() error = %v", err)
	}
	if count == 0 {
		t.Error("Count() returned 0")
	}

	// Test Delete
	if err := store.Delete(ctx, app.Id); err != nil {
		t.Errorf("Delete() error = %v", err)
	}

	// Verify deleted
	_, err = store.GetByID(ctx, app.Id)
	if err != ErrNotFound {
		t.Errorf("GetByID() after delete error = %v, want ErrNotFound", err)
	}
}

func TestStoreErrors(t *testing.T) {
	connString := os.Getenv("CONTAINARIUM_TEST_DSN")
	if connString == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}

	ctx := context.Background()

	store, err := NewStore(ctx, connString)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	// Test GetByID not found
	_, err = store.GetByID(ctx, uuid.New().String())
	if err != ErrNotFound {
		t.Errorf("GetByID() error = %v, want ErrNotFound", err)
	}

	// Test GetByName not found
	_, err = store.GetByName(ctx, "nonexistent", "app")
	if err != ErrNotFound {
		t.Errorf("GetByName() error = %v, want ErrNotFound", err)
	}

	// Test Delete not found
	err = store.Delete(ctx, uuid.New().String())
	if err != ErrNotFound {
		t.Errorf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestNewStore_InvalidConnection(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, err := NewStore(ctx, "postgres://invalid:invalid@nonexistent:5432/test")
	if err == nil {
		t.Error("NewStore() with invalid connection expected error, got nil")
	}
}
