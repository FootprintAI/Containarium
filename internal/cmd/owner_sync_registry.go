//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
)

// openKeyRegistry opens the ssh_keys registry and returns it with a closer.
// A variable so tests can stand in for Postgres.
var openKeyRegistry = func(ctx context.Context, dsn string) (sshauthz.KeyLookup, func(), error) {
	if dsn == "" {
		return nil, nil, fmt.Errorf("no database connection configured")
	}
	// collaborator.NewStore bounds its connection check (5s); the extra
	// deadline keeps schema setup from stalling a startup goroutine.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	store, err := collaborator.NewStore(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	reg, err := sshauthz.NewPGKeyStore(ctx, store.Pool(), sshauthz.FileHolders{HomeRoot: "/home"})
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	return reg, store.Close, nil
}

// registryKeyFilter adapts a registry handle to the container package's
// KeyFilter. A nil registry (it could not be opened: openErr) yields a filter
// that always errors, so owner accounts are never seeded from unchecked keys
// (#3395).
func registryKeyFilter(reg sshauthz.KeyLookup, openErr error) container.KeyFilter {
	return func(ctx context.Context, keys []string) ([]string, int, error) {
		if reg == nil {
			return nil, 0, fmt.Errorf("key registry unavailable: %w", openErr)
		}
		return sshauthz.DropRevokedKeys(ctx, reg, keys)
	}
}

// syncOwnerAccountsFiltered runs the owner-account sync with the revocation
// filter wired to the key registry at dsn. It is the single entry point for
// `sync-accounts` and the daemon's startup sync. If the registry cannot be
// opened, no account is restored (fail closed) and the reason is in
// res.FilterErr.
func syncOwnerAccountsFiltered(mgr *container.Manager, dsn string, opts container.OwnerSyncOptions) (container.OwnerSyncResult, error) {
	reg, closeReg, openErr := openKeyRegistry(context.Background(), dsn)
	if closeReg != nil {
		defer closeReg()
	}
	opts.KeyFilter = registryKeyFilter(reg, openErr)
	return mgr.SyncOwnerAccounts(opts)
}
