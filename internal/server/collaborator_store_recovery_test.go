//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3330: the collaborator store, the ssh_keys registry and the self-host
// SSH decider as one late-install family on the #3326 helper. With Postgres
// down at startup the collaborator RPCs answer UNAVAILABLE, the
// `containarium.collaborators` readiness entry is NOT_SERVING and Authorize
// has no decider; once Postgres answers the store and manager install, the
// registry is created, backfilled and reconciled (Q14), and only then is the
// self-host decider set — and only where boot would have set it (no cloud
// enrollment, LXC runtime).

const collabRecoveryOwner = "collab-recovery-owner"

// fakeKeyRegistry is the ssh_keys registry the family installs.
type fakeKeyRegistry struct{}

func (fakeKeyRegistry) Register(context.Context, sshauthz.KeyRecord) error { return nil }
func (fakeKeyRegistry) Revoke(context.Context, sshauthz.KeyRecord, time.Time) error {
	return nil
}
func (fakeKeyRegistry) Lookup(context.Context, string) (sshauthz.KeyRecord, error) {
	return sshauthz.KeyRecord{}, sshauthz.ErrKeyNotFound
}
func (fakeKeyRegistry) InsertIfAbsent(context.Context, sshauthz.KeyRecord) (bool, error) {
	return false, nil
}
func (fakeKeyRegistry) ActiveRecords(context.Context) ([]sshauthz.KeyRecord, error) {
	return nil, nil
}

// collabFamilyFakes records every step the family runs and fails the
// backfill or reconcile the first N times.
type collabFamilyFakes struct {
	mu                sync.Mutex
	store             *collaborator.Store
	keys              *fakeKeyRegistry
	opens, keyOpens   int
	backfills         int
	reconciles        int
	backfillFailures  int
	reconcileFailures int
	openPools         []*pgxpool.Pool
}

func newCollabFamilyFakes() *collabFamilyFakes {
	return &collabFamilyFakes{store: &collaborator.Store{}, keys: &fakeKeyRegistry{}}
}

func (f *collabFamilyFakes) deps() collaboratorFamilyDeps {
	return collaboratorFamilyDeps{
		openStore: func(_ context.Context, pool *pgxpool.Pool) (*collaborator.Store, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.opens++
			f.openPools = append(f.openPools, pool)
			return f.store, nil
		},
		openKeys: func(context.Context, *pgxpool.Pool) (sshKeyRegistryStore, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.keyOpens++
			return f.keys, nil
		},
		backfill: func(context.Context, sshauthz.BackfillStore) (int, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.backfills++
			if f.backfills <= f.backfillFailures {
				return 0, errors.New("read /home: permission denied")
			}
			return 2, nil
		},
		reconcile: func(context.Context, sshauthz.ReconcileStore) (sshauthz.ReconcileResult, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.reconciles++
			if f.reconciles <= f.reconcileFailures {
				return sshauthz.ReconcileResult{}, errors.New("list active ssh keys: connection reset")
			}
			return sshauthz.ReconcileResult{Revoked: 1}, nil
		},
	}
}

func (f *collabFamilyFakes) counts() (opens, keyOpens, backfills, reconciles int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens, f.keyOpens, f.backfills, f.reconciles
}

type collabTestBoxes struct{}

func (collabTestBoxes) ExistingContainerNames() (map[string]bool, error) {
	return map[string]bool{collabRecoveryOwner + "-container": true}, nil
}

// newTestCollaboratorFamily builds the family over cs; lxc is the registry
// condition (Runtime != K8s with a container manager).
func newTestCollaboratorFamily(cs *ContainerServer, fakes *collabFamilyFakes, lxc bool, logf func(string, ...any)) *collaboratorFamily {
	cfg := collaboratorFamilyConfig{Registry: lxc, MaxKeyAge: 0, deps: fakes.deps(), logf: logf}
	if lxc {
		cfg.Boxes = collabTestBoxes{}
	}
	return newCollaboratorFamily(cs, cfg)
}

func collabOwnerCtx() context.Context {
	return kmsKeyTestCtx(collabRecoveryOwner, "member", "")
}

// assertCollaboratorRPCs calls the three collaborator RPCs as the box owner
// and wants code from each.
func assertCollaboratorRPCs(t *testing.T, cs *ContainerServer, want codes.Code) {
	t.Helper()
	ctx := collabOwnerCtx()
	calls := map[string]func() error{
		"AddCollaborator": func() error {
			_, err := cs.AddCollaborator(ctx, &pb.AddCollaboratorRequest{OwnerUsername: collabRecoveryOwner, CollaboratorUsername: "bob", SshPublicKey: "ssh-ed25519 AAAA bob"})
			return err
		},
		"RemoveCollaborator": func() error {
			_, err := cs.RemoveCollaborator(ctx, &pb.RemoveCollaboratorRequest{OwnerUsername: collabRecoveryOwner, CollaboratorUsername: "bob"})
			return err
		},
		"ListCollaborators": func() error {
			_, err := cs.ListCollaborators(ctx, &pb.ListCollaboratorsRequest{OwnerUsername: collabRecoveryOwner})
			return err
		},
	}
	for name, call := range calls {
		if code := status.Code(call()); code != want {
			t.Errorf("%s with no collaborator store = %v, want %v", name, code, want)
		}
	}
}

// AC1 + AC2 without a database: Postgres is down for two attempts. Before
// recovery the entry is NOT_SERVING, every collaborator RPC answers
// UNAVAILABLE and there is no manager, registry or decider. After it, the
// entry is SERVING, the store opened once over the shared pool, the manager
// and registry are the late-installed ones, the backfill and reconcile ran
// once each, and the decider is set. Readers run during the swap, so -race
// catches a field still read raw.
func TestCollaboratorRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 2})
	cs := &ContainerServer{}
	authz := NewSSHAuthzServer()
	fakes := newCollabFamilyFakes()
	fam := newTestCollaboratorFamily(cs, fakes, true, f.logs.logf)
	fam.registerPending(f.r)
	fam.enableSelfHostDecider(authz) // cloudClient == nil

	if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("collaborators readiness before recovery = %v, want NOT_SERVING", got)
	}
	if f.readiness.entries[collaboratorStoreService] == "" {
		t.Errorf("collaborator family published no readiness display name: %v", f.readiness.entries)
	}
	assertCollaboratorRPCs(t, cs, codes.Unavailable)
	if cs.loadCollaboratorManager() != nil || cs.loadSSHKeyRegistry() != nil || authz.currentDecider() != nil {
		t.Fatal("manager, registry or decider wired before the store installed")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = cs.loadCollaboratorManager()
				_ = cs.loadSSHKeyRegistry()
				_ = cs.collaboratorAccessor()
				_ = authz.currentDecider()
			}
		}()
	}
	f.runToCompletion(t, nil)
	close(stop)
	wg.Wait()

	if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("collaborators readiness after recovery = %v, want SERVING", got)
	}
	if cs.loadCollaboratorManager() == nil {
		t.Error("collaborator manager not installed")
	}
	if got := cs.loadSSHKeyRegistry(); got != sshauthz.KeyRegistry(fakes.keys) {
		t.Errorf("ssh key registry = %v, want the late-installed registry", got)
	}
	opens, keyOpens, backfills, reconciles := fakes.counts()
	if opens != 1 || keyOpens != 1 || backfills != 1 || reconciles != 1 {
		t.Errorf("open/keys/backfill/reconcile ran %d/%d/%d/%d times, want once each", opens, keyOpens, backfills, reconciles)
	}
	if len(fakes.openPools) != 1 || fakes.openPools[0] == nil {
		t.Errorf("collaborator store opened over %v, want the shared pool", fakes.openPools)
	}
	d, ok := authz.currentDecider().(*sshauthz.SelfHostDecider)
	if !ok {
		t.Fatalf("decider after recovery = %T, want the self-host decider", authz.currentDecider())
	}
	if d.Keys != sshauthz.KeyLookup(fakes.keys) || d.Collaborators == nil || d.Boxes == nil || d.HomeRoot != sshKeysHomeRoot {
		t.Errorf("self-host decider = %+v, want it over the installed registry, collaborator rows and boxes", d)
	}
	if f.r.pending() {
		t.Error("collaborator family still pending after it installed")
	}
}

// A backfill failure leaves the decider off and the family pending (the
// store and manager are in); the retry installs the rest without reopening
// the store or recreating the registry, then sets the decider. The same for
// a reconcile failure.
func TestCollaboratorRecovery_BackfillOrReconcileFailureRetries(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		backfillFails, reconcileFails int
		wantBackfills                 int
	}{
		{name: "backfill", backfillFails: 1, wantBackfills: 2},
		{name: "reconcile", reconcileFails: 1, wantBackfills: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreRecoveryFixture(t, &fakePostgres{})
			cs := &ContainerServer{}
			authz := NewSSHAuthzServer()
			fakes := newCollabFamilyFakes()
			fakes.backfillFailures = tc.backfillFails
			fakes.reconcileFailures = tc.reconcileFails
			fam := newTestCollaboratorFamily(cs, fakes, true, f.logs.logf)
			fam.registerPending(f.r)
			fam.enableSelfHostDecider(authz)

			if err := f.r.attempt(f.ctx); err == nil {
				t.Fatalf("first attempt succeeded with a failing %s", tc.name)
			}
			if authz.currentDecider() != nil {
				t.Errorf("decider set after a failed %s", tc.name)
			}
			if !f.r.pending() {
				t.Error("family not pending after a failed install")
			}
			if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
				t.Errorf("readiness after a failed %s = %v, want NOT_SERVING", tc.name, got)
			}
			if f.r.holdsRestart() != true {
				t.Error("a failed install does not hold the self-restart; it is not a config refusal")
			}

			if err := f.r.attempt(f.ctx); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if authz.currentDecider() == nil {
				t.Error("decider not set after the retry")
			}
			if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_SERVING {
				t.Errorf("readiness after the retry = %v, want SERVING", got)
			}
			opens, keyOpens, backfills, reconciles := fakes.counts()
			if opens != 1 || keyOpens != 1 {
				t.Errorf("store opened %d times, registry created %d times; want once each across the retry", opens, keyOpens)
			}
			if backfills != tc.wantBackfills || reconciles != 1+tc.reconcileFails {
				t.Errorf("backfill/reconcile ran %d/%d times, want %d/%d", backfills, reconciles, tc.wantBackfills, 1+tc.reconcileFails)
			}
		})
	}
}

// The K8s runtime (or no container manager) skips the registry, backfill
// and decider, and a managed-cloud daemon (enableSelfHostDecider never
// called) skips the decider and keeps its managed forwarder. Both still
// report SERVING for collaborators once the store installs.
func TestCollaboratorRecovery_K8sAndManagedCloudSkipRegistryOrDecider(t *testing.T) {
	t.Run("k8s", func(t *testing.T) {
		f := newStoreRecoveryFixture(t, &fakePostgres{})
		cs := &ContainerServer{}
		authz := NewSSHAuthzServer()
		fakes := newCollabFamilyFakes()
		fam := newTestCollaboratorFamily(cs, fakes, false, f.logs.logf)
		fam.registerPending(f.r)
		fam.enableSelfHostDecider(authz)
		f.runToCompletion(t, nil)

		if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("readiness = %v, want SERVING", got)
		}
		if cs.loadCollaboratorManager() == nil {
			t.Error("collaborator manager not installed on K8s")
		}
		_, keyOpens, backfills, reconciles := fakes.counts()
		if keyOpens != 0 || backfills != 0 || reconciles != 0 || cs.loadSSHKeyRegistry() != nil {
			t.Errorf("registry path ran on K8s: keys %d, backfill %d, reconcile %d", keyOpens, backfills, reconciles)
		}
		if authz.currentDecider() != nil {
			t.Error("self-host decider set on K8s")
		}
	})
	t.Run("managed cloud", func(t *testing.T) {
		f := newStoreRecoveryFixture(t, &fakePostgres{})
		cs := &ContainerServer{}
		authz := NewSSHAuthzServer()
		managed := &sshauthz.Decider{Managed: true}
		authz.SetDecider(managed)
		fakes := newCollabFamilyFakes()
		fam := newTestCollaboratorFamily(cs, fakes, true, f.logs.logf)
		fam.registerPending(f.r) // enableSelfHostDecider is not called: cloudClient != nil
		f.runToCompletion(t, nil)

		if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("readiness = %v, want SERVING", got)
		}
		if cs.loadSSHKeyRegistry() == nil {
			t.Error("registry not installed on an enrolled LXC daemon (the write paths still record keys)")
		}
		if got := authz.currentDecider(); got != SSHAuthzDecider(managed) {
			t.Errorf("decider = %T, want the managed forwarder left in place", got)
		}
	})
}

// The startup path: Postgres answered at boot. The family installs there,
// the decider is set where boot sets it, readiness is SERVING with nothing
// pending, and no reconcile runs (the registry was never absent).
func TestCollaboratorRecovery_StartupInstall(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	authz := NewSSHAuthzServer()
	fakes := newCollabFamilyFakes()
	fam := newTestCollaboratorFamily(cs, fakes, true, f.logs.logf)

	if err := fam.installAtStartup(context.Background(), fakes.store); err != nil {
		t.Fatalf("installAtStartup: %v", err)
	}
	fam.registerInstalled(f.r)
	if authz.currentDecider() != nil {
		t.Fatal("decider set before boot reached the cloud check")
	}
	fam.enableSelfHostDecider(authz)

	if authz.currentDecider() == nil {
		t.Error("decider not set at startup")
	}
	if got := f.status(t, collaboratorStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness = %v, want SERVING", got)
	}
	if f.r.pending() {
		t.Error("family pending after a startup install")
	}
	opens, keyOpens, backfills, reconciles := fakes.counts()
	if opens != 0 || keyOpens != 1 || backfills != 1 || reconciles != 0 {
		t.Errorf("open/keys/backfill/reconcile = %d/%d/%d/%d, want 0/1/1/0", opens, keyOpens, backfills, reconciles)
	}
}

// A startup backfill failure no longer leaves the decider off until a
// restart: the family is handed to the helper, which finishes it on the
// startup store without reopening it.
func TestCollaboratorRecovery_StartupBackfillFailureRetriedInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	authz := NewSSHAuthzServer()
	fakes := newCollabFamilyFakes()
	fakes.backfillFailures = 1
	fam := newTestCollaboratorFamily(cs, fakes, true, f.logs.logf)

	if err := fam.installAtStartup(context.Background(), fakes.store); err == nil {
		t.Fatal("installAtStartup succeeded with a failing backfill")
	}
	fam.registerPending(f.r)
	fam.enableSelfHostDecider(authz)
	if authz.currentDecider() != nil {
		t.Fatal("decider set after a failed startup backfill")
	}
	if cs.loadCollaboratorManager() == nil {
		t.Error("collaborator manager not installed although the store opened")
	}
	f.runToCompletion(t, nil)

	if authz.currentDecider() == nil {
		t.Error("decider not set once the backfill succeeded in-process")
	}
	opens, keyOpens, backfills, _ := fakes.counts()
	if opens != 0 || keyOpens != 1 || backfills != 2 {
		t.Errorf("open/keys/backfill = %d/%d/%d, want 0/1/2 (the startup store and registry are kept)", opens, keyOpens, backfills)
	}
}

// No Postgres configured: no family, and the RPCs keep their "not enabled"
// answer rather than claiming the store is coming.
func TestCollaboratorRecovery_NoPostgresIsNotUnavailable(t *testing.T) {
	assertCollaboratorRPCsNotUnavailable(t, &ContainerServer{})
}

func assertCollaboratorRPCsNotUnavailable(t *testing.T, cs *ContainerServer) {
	t.Helper()
	_, err := cs.ListCollaborators(collabOwnerCtx(), &pb.ListCollaboratorsRequest{OwnerUsername: collabRecoveryOwner})
	if status.Code(err) == codes.Unavailable || err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("ListCollaborators with no collaborator store configured = %v, want the not-enabled error", err)
	}
}

// The registry condition is boot's: the LXC runtime with a container
// manager. Without a manager the decider would have no box list, so the
// registry path is off rather than built over a nil lister.
func TestCollaboratorRecovery_RegistryConditionIsLXCWithManager(t *testing.T) {
	mgr := &container.Manager{}
	for _, tc := range []struct {
		name string
		lxc  bool
		mgr  *container.Manager
		want bool
	}{
		{"lxc with manager", true, mgr, true},
		{"lxc without manager", true, nil, false},
		{"k8s with manager", false, mgr, false},
	} {
		cfg := lxcCollaboratorConfig(tc.lxc, tc.mgr, time.Hour)
		if cfg.Registry != tc.want || (cfg.Boxes != nil) != tc.want || cfg.MaxKeyAge != time.Hour {
			t.Errorf("%s: config = %+v, want registry %v with boxes iff registry", tc.name, cfg, tc.want)
		}
	}
}
