//go:build !containarium_client

package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
)

// The collaborator store, the ssh_keys registry and the self-host SSH
// authorization decider as one late-install family (#3330, on the #3326
// helper). They share one pool and depend on each other in order: the
// registry lives on the collaborator store's pool, and the decider reads
// both. After a degraded start the collaborator RPCs answer UNAVAILABLE and
// the readiness entry is NOT_SERVING; once Postgres answers, one idempotent
// Install
//
//  1. opens the collaborator store over the shared pool and installs the
//     CollaboratorManager;
//  2. on the LXC runtime with a container manager (the condition boot
//     uses), creates the registry, wires it into the key write paths and
//     backfills it from /home; on a late install it then reconciles the
//     registry (#3335 Q14): key revokes during the window were no-ops on
//     the absent registry, and the decider's /home check does not refuse a
//     stale row, so rows no account holds are revoked;
//  3. sets the self-host decider, only after the backfill (and reconcile)
//     succeeded and only if boot reached the point where it sets it with no
//     cloud enrollment (enableSelfHostDecider; never recomputed here).
//
// A failing step returns its error, so the helper retries; completed steps
// are kept and not repeated. A startup install whose backfill fails is
// handed to the helper too, instead of leaving the decider off until a
// restart.

const (
	// collaboratorStoreService is the family's grpc.health.v1 readiness entry.
	collaboratorStoreService = "containarium.collaborators"
	collaboratorStoreDisplay = "collaborator store and SSH key registry"
	// sshKeysHomeRoot holds the jump accounts the registry backfills from and
	// the decider checks.
	sshKeysHomeRoot = "/home"
)

// errCollaboratorsNotInstalled is the collaborator RPCs' answer while the
// family is pending.
var errCollaboratorsNotInstalled = status.Error(codes.Unavailable,
	"collaborator store is not available yet (Postgres unavailable at startup); it installs in-process once Postgres answers — readiness "+collaboratorStoreService)

// sshKeyRegistryStore is what the family needs from the ssh_keys registry:
// the key write paths, the decider's lookup, the backfill and the
// reconcile. *sshauthz.PGKeyStore satisfies it.
type sshKeyRegistryStore interface {
	sshauthz.KeyRegistry
	sshauthz.KeyLookup
	sshauthz.BackfillStore
	sshauthz.ReconcileStore
}

// collaboratorFamilyDeps are the family's steps that touch Postgres or the
// host; zero fields mean the real ones.
type collaboratorFamilyDeps struct {
	openStore func(context.Context, *pgxpool.Pool) (*collaborator.Store, error)
	openKeys  func(context.Context, *pgxpool.Pool) (sshKeyRegistryStore, error)
	backfill  func(context.Context, sshauthz.BackfillStore) (int, error)
	reconcile func(context.Context, sshauthz.ReconcileStore) (sshauthz.ReconcileResult, error)
}

func (d collaboratorFamilyDeps) withDefaults() collaboratorFamilyDeps {
	if d.openStore == nil {
		d.openStore = collaborator.NewStoreOnPool
	}
	if d.openKeys == nil {
		d.openKeys = func(ctx context.Context, pool *pgxpool.Pool) (sshKeyRegistryStore, error) {
			keys, err := sshauthz.NewPGKeyStore(ctx, pool, sshauthz.FileHolders{HomeRoot: sshKeysHomeRoot})
			if err != nil {
				return nil, err // a true nil interface, never a nil *PGKeyStore in one
			}
			return keys, nil
		}
	}
	if d.backfill == nil {
		d.backfill = func(ctx context.Context, keys sshauthz.BackfillStore) (int, error) {
			return sshauthz.Backfill(ctx, keys, sshKeysHomeRoot, time.Now())
		}
	}
	if d.reconcile == nil {
		d.reconcile = func(ctx context.Context, keys sshauthz.ReconcileStore) (sshauthz.ReconcileResult, error) {
			return sshauthz.Reconcile(ctx, keys, sshKeysHomeRoot, time.Now())
		}
	}
	return d
}

// collaboratorFamilyConfig is fixed when NewDualServer builds the family.
type collaboratorFamilyConfig struct {
	// Registry is the LXC condition boot uses for the registry, backfill and
	// decider: Runtime != K8s and a container manager exists.
	Registry bool
	// Boxes lists live boxes for the decider (the container manager).
	Boxes sshauthz.BoxLister
	// MaxKeyAge is the decider's --ssh-authz-max-key-age.
	MaxKeyAge time.Duration

	deps collaboratorFamilyDeps
	logf func(string, ...any)
}

// collaboratorFamily carries the install's progress, so a retry resumes
// after the last completed step.
type collaboratorFamily struct {
	cs   *ContainerServer
	cfg  collaboratorFamilyConfig
	deps collaboratorFamilyDeps
	logf func(string, ...any)

	mu         sync.Mutex
	store      *collaborator.Store
	keys       sshKeyRegistryStore
	backfilled bool
	reconciled bool
	decider    *sshauthz.SelfHostDecider // built once the registry is complete
	authz      *SSHAuthzServer           // set by enableSelfHostDecider
	deciderSet bool
}

func newCollaboratorFamily(cs *ContainerServer, cfg collaboratorFamilyConfig) *collaboratorFamily {
	logf := cfg.logf
	if logf == nil {
		logf = log.Printf
	}
	return &collaboratorFamily{cs: cs, cfg: cfg, deps: cfg.deps.withDefaults(), logf: logf}
}

// family is the helper registration: open the store over the shared pool
// unless startup already did, then finish the registry and decider.
func (f *collaboratorFamily) family() storeFamily {
	return storeFamily{
		Service: collaboratorStoreService,
		Display: collaboratorStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.store == nil {
				st, err := f.deps.openStore(ctx, pool)
				if err != nil {
					return fmt.Errorf("open collaborator store: %w", err)
				}
				f.adoptLocked(st)
			}
			return f.finishLocked(ctx, true)
		},
	}
}

// registerPending hands the family to the helper: the startup install did
// not happen or did not finish. The collaborator RPCs answer UNAVAILABLE
// until the store is in.
func (f *collaboratorFamily) registerPending(r *storeRecovery) {
	f.mu.Lock()
	if f.store == nil {
		f.cs.collaboratorsPending.Store(true)
	}
	f.mu.Unlock()
	r.logf("Warning: collaborator store not installed (Postgres unavailable at startup, or the SSH key registry did not finish): readiness %s is NOT_SERVING; it installs in-process once Postgres answers", collaboratorStoreService)
	r.Register(f.family())
}

// registerInstalled lists the family after a complete startup install.
func (f *collaboratorFamily) registerInstalled(r *storeRecovery) {
	r.RegisterInstalled(f.family())
}

// installAtStartup runs the install on the store boot opened (its own
// pool). No reconcile: the registry was never absent while serving.
func (f *collaboratorFamily) installAtStartup(ctx context.Context, st *collaborator.Store) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adoptLocked(st)
	return f.finishLocked(ctx, false)
}

// enableSelfHostDecider records that this daemon decides SSH authorization
// itself (boot calls it only when no cloud is enrolled) and sets the
// decider now if the registry is complete, else when the install finishes.
func (f *collaboratorFamily) enableSelfHostDecider(srv *SSHAuthzServer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authz = srv
	f.setDeciderLocked()
}

// adoptLocked installs st and its CollaboratorManager (step 1).
func (f *collaboratorFamily) adoptLocked(st *collaborator.Store) {
	f.store = st
	f.cs.SetCollaboratorManager(container.NewCollaboratorManager(f.cs.GetManager(), st))
	f.cs.collaboratorsPending.Store(false)
	f.logf("Collaborator management service enabled")
}

// finishLocked runs steps 2 and 3, skipping what an earlier attempt did.
func (f *collaboratorFamily) finishLocked(ctx context.Context, late bool) error {
	if !f.cfg.Registry {
		return nil
	}
	if f.keys == nil {
		keys, err := f.deps.openKeys(ctx, f.store.Pool())
		if err != nil {
			return fmt.Errorf("ssh key registry: %w (SSH authorization decider off until it installs)", err)
		}
		f.keys = keys
		f.cs.SetSSHKeyRegistry(keys)
	}
	if !f.backfilled {
		added, err := f.deps.backfill(ctx, f.keys)
		if err != nil {
			return fmt.Errorf("ssh key registry backfill from %s after %d rows: %w (SSH authorization decider off until it succeeds)", sshKeysHomeRoot, added, err)
		}
		f.backfilled = true
		f.logf("ssh key registry: backfill from %s added %d key(s)", sshKeysHomeRoot, added)
	}
	if late && !f.reconciled {
		res, err := f.deps.reconcile(ctx, f.keys)
		if err != nil {
			return fmt.Errorf("ssh key registry reconcile: %w (SSH authorization decider off until it succeeds)", err)
		}
		f.reconciled = true
		f.logf("ssh key registry: reconciled after a degraded start: revoked %d key(s) no account holds, %d left active (holder unknown)", res.Revoked, res.Unresolved)
	}
	if f.decider == nil {
		f.decider = &sshauthz.SelfHostDecider{
			HomeRoot:      sshKeysHomeRoot,
			Boxes:         f.cfg.Boxes,
			Collaborators: collaboratorRows{store: f.store},
			Keys:          f.keys,
			MaxKeyAge:     f.cfg.MaxKeyAge,
		}
	}
	f.setDeciderLocked()
	return nil
}

// setDeciderLocked sets the self-host decider once both the registry is
// complete and boot enabled it; at most once.
func (f *collaboratorFamily) setDeciderLocked() {
	if f.deciderSet || f.authz == nil || f.decider == nil {
		return
	}
	f.authz.SetDecider(f.decider)
	f.deciderSet = true
	f.logf("SSH authorization: self-host decider enabled (max key age %v, 0 = no limit)", f.cfg.MaxKeyAge)
}

// lxcCollaboratorConfig is the family's configuration from boot's facts:
// the registry path needs the LXC runtime and a container manager.
func lxcCollaboratorConfig(lxcRuntime bool, mgr *container.Manager, maxKeyAge time.Duration) collaboratorFamilyConfig {
	cfg := collaboratorFamilyConfig{MaxKeyAge: maxKeyAge}
	if lxcRuntime && mgr != nil {
		cfg.Registry = true
		cfg.Boxes = mgr
	}
	return cfg
}
