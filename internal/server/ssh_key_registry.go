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

// sshKeyRegistryRef boxes the registry interface for the atomic swap.
type sshKeyRegistryRef struct{ r sshauthz.KeyRegistry }

// SetSSHKeyRegistry wires the ssh_keys registry into the key write paths.
// Safe while serving: the late install (#3330) calls it.
func (s *ContainerServer) SetSSHKeyRegistry(r sshauthz.KeyRegistry) {
	s.sshKeys.Store(&sshKeyRegistryRef{r: r})
}

// loadSSHKeyRegistry returns the installed registry, or nil.
func (s *ContainerServer) loadSSHKeyRegistry() sshauthz.KeyRegistry {
	if ref := s.sshKeys.Load(); ref != nil {
		return ref.r
	}
	return nil
}

func (s *ContainerServer) sshKeyClock() time.Time {
	if s.sshKeyNow != nil {
		return s.sshKeyNow()
	}
	return time.Now()
}

// registerSSHKey records pubKey for the jump account username. Nil
// registry = no-op.
func (s *ContainerServer) registerSSHKey(ctx context.Context, username, pubKey string, source sshauthz.KeySource) error {
	keys := s.loadSSHKeyRegistry()
	if keys == nil {
		return nil
	}
	rec, err := sshauthz.NewKeyRecord(pubKey, username, source, s.sshKeyClock())
	if err != nil {
		return err
	}
	return keys.Register(ctx, rec)
}

// revokeSSHKey revokes pubKey's registry entry if username owns it (by user
// id for an owner account) or the entry has no owner; an entry another
// account owns is left active (#3187, #3217). It returns
// sshauthz.ErrKeyHeldByOtherAccount while another account still holds the
// key (#3222), leaving the entry active and, if username owned it, releasing
// it (#3217). Nil registry = no-op.
func (s *ContainerServer) revokeSSHKey(ctx context.Context, username, pubKey string) error {
	keys := s.loadSSHKeyRegistry()
	if keys == nil {
		return nil
	}
	now := s.sshKeyClock()
	rec, err := sshauthz.NewKeyRecord(pubKey, username, sshauthz.SourceAPI, now)
	if err != nil {
		return err
	}
	return keys.Revoke(ctx, rec, now)
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
