package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
)

// The daemon's SSH key write paths feed the ssh_keys registry (#2517), the
// self-host source for SSHAuthzService.Authorize: box-creation keys,
// AddSSHKey and AddCollaborator register; RemoveSSHKey revokes. A daemon
// with no registry (no Postgres) skips all of it.

// authorizedKeysOps is the host-side authorized_keys surface the key RPCs
// use. A zero value means the real pkg/core/container functions; tests set
// it to keep off the host's /home.
type authorizedKeysOps struct {
	add    func(username, pubKey string) error
	remove func(username, pubKey string) error
	count  func(username string) (int32, error)
	// replace makes the file hold exactly keys (plus platform-managed lines).
	// hooks run inside the per-user critical section; see
	// container.ReplaceAuthorizedKeys.
	replace func(username string, keys []string, hooks container.ReplaceHooks) ([]string, error)
}

func (o authorizedKeysOps) replaceKeys(username string, keys []string, hooks container.ReplaceHooks) ([]string, error) {
	if o.replace != nil {
		return o.replace(username, keys, hooks)
	}
	return container.ReplaceAuthorizedKeys(username, keys, hooks)
}

func (o authorizedKeysOps) addKey(username, pubKey string) error {
	if o.add != nil {
		return o.add(username, pubKey)
	}
	return container.AddAuthorizedKey(username, pubKey)
}

func (o authorizedKeysOps) removeKey(username, pubKey string) error {
	if o.remove != nil {
		return o.remove(username, pubKey)
	}
	return container.RemoveAuthorizedKey(username, pubKey)
}

func (o authorizedKeysOps) countKeys(username string) (int32, error) {
	if o.count != nil {
		return o.count(username)
	}
	return container.CountAuthorizedKeys(username)
}

// SetSSHKeyRegistry wires the ssh_keys registry into the key write paths.
func (s *ContainerServer) SetSSHKeyRegistry(r sshauthz.KeyRegistry) { s.sshKeys = r }

func (s *ContainerServer) sshKeyClock() time.Time {
	if s.sshKeyNow != nil {
		return s.sshKeyNow()
	}
	return time.Now()
}

// registerSSHKey records pubKey for the jump account username. Nil
// registry = no-op.
func (s *ContainerServer) registerSSHKey(ctx context.Context, username, pubKey string, source sshauthz.KeySource) error {
	if s.sshKeys == nil {
		return nil
	}
	rec, err := sshauthz.NewKeyRecord(pubKey, username, source, s.sshKeyClock())
	if err != nil {
		return err
	}
	return s.sshKeys.Register(ctx, rec)
}

// revokeSSHKey revokes pubKey for every account. Nil registry = no-op.
func (s *ContainerServer) revokeSSHKey(ctx context.Context, username, pubKey string) error {
	if s.sshKeys == nil {
		return nil
	}
	now := s.sshKeyClock()
	rec, err := sshauthz.NewKeyRecord(pubKey, username, sshauthz.SourceAPI, now)
	if err != nil {
		return err
	}
	return s.sshKeys.Revoke(ctx, rec, now)
}

// syncCreateRequestKeys mirrors a box create request's keys into the host
// jump account's authorized_keys (#470) and registers each key written.
// Runs after the create has returned, so failures are logged.
func (s *ContainerServer) syncCreateRequestKeys(ctx context.Context, username string, keys []string) {
	for _, key := range keys {
		if err := s.authorizedKeys.addKey(username, key); err != nil {
			log.Printf("Warning: failed to sync create-request ssh key to jump account for %s: %v", username, err)
			continue
		}
		if err := s.registerSSHKey(ctx, username, key, sshauthz.SourceBoxCreate); err != nil {
			log.Printf("Warning: failed to register create-request ssh key for %s: %v", username, err)
		}
	}
}

// registerCollaboratorKeys registers a new collaborator's keys to its jump
// account ("<owner>-container-<collab>"). The collaborator already exists by
// now, so failures are logged.
func (s *ContainerServer) registerCollaboratorKeys(ctx context.Context, accountName string, keys []string) {
	for _, key := range keys {
		if err := s.registerSSHKey(ctx, accountName, key, sshauthz.SourceCollaborator); err != nil {
			log.Printf("Warning: failed to register collaborator ssh key for %s: %v", accountName, err)
		}
	}
}

// registryError wraps a registry failure from an idempotent key RPC.
func registryError(op string, err error) error {
	return fmt.Errorf("%s: record in ssh key registry: %w", op, err)
}

// collaboratorRows adapts the collaborator store to the decider's
// collaborator-row check.
type collaboratorRows struct{ store *collaborator.Store }

func (c collaboratorRows) CollaboratorExists(ctx context.Context, containerName, collaboratorUsername string) (bool, error) {
	_, err := c.store.Get(ctx, containerName, collaboratorUsername)
	if errors.Is(err, collaborator.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// setupSSHKeyRegistry creates the ssh_keys table on the collaborator store's
// pool, wires it into the key write paths, and runs the startup backfill
// from /home. It returns the self-host decider, or nil when the registry is
// unavailable or the backfill failed: without a complete backfill, existing
// keys would be refused as UNKNOWN_KEY, so the decider stays off until a
// restart backfills successfully.
func setupSSHKeyRegistry(ctx context.Context, collabStore *collaborator.Store, cs *ContainerServer, maxKeyAge time.Duration) *sshauthz.SelfHostDecider {
	keys, err := sshauthz.NewPGKeyStore(ctx, collabStore.Pool())
	if err != nil {
		log.Printf("Warning: ssh key registry unavailable: %v (SSH authorization decider disabled)", err)
		return nil
	}
	cs.SetSSHKeyRegistry(keys)

	const homeRoot = "/home"
	added, err := sshauthz.Backfill(ctx, keys, homeRoot, time.Now())
	if err != nil {
		log.Printf("Warning: ssh key registry backfill from %s failed after %d rows: %v (SSH authorization decider disabled until a restart backfills)", homeRoot, added, err)
		return nil
	}
	log.Printf("ssh key registry: backfill from %s added %d key(s)", homeRoot, added)

	return &sshauthz.SelfHostDecider{
		HomeRoot:      homeRoot,
		Boxes:         cs.GetManager(),
		Collaborators: collaboratorRows{store: collabStore},
		Keys:          keys,
		MaxKeyAge:     maxKeyAge,
	}
}
