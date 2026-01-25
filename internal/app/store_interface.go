package app

import (
	"context"

	v1 "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// AppStore defines the interface for app storage
type AppStore interface {
	// Save saves an app to the store (insert or update)
	Save(ctx context.Context, app *v1.App) error

	// GetByID retrieves an app by its ID
	GetByID(ctx context.Context, id string) (*v1.App, error)

	// GetByName retrieves an app by username and app name
	GetByName(ctx context.Context, username, name string) (*v1.App, error)

	// List retrieves all apps, optionally filtered by username and state
	List(ctx context.Context, username string, stateFilter v1.AppState) ([]*v1.App, error)

	// Delete removes an app by ID
	Delete(ctx context.Context, id string) error

	// DeleteByName removes an app by username and name
	DeleteByName(ctx context.Context, username, name string) error

	// Count returns the total number of apps
	Count(ctx context.Context, username string, stateFilter v1.AppState) (int32, error)

	// Close closes the store connection
	Close()
}

// Ensure Store implements AppStore
var _ AppStore = (*Store)(nil)
