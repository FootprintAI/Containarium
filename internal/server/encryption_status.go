package server

import (
	"context"
	"log"

	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Encryption state on container status (#1202), design resolved decision #3.
//
// ZFS allows a snapshot to be TAKEN while the key is unloaded and refuses
// only to read one back. That asymmetry is deliberate — blocking snapshot
// creation on key-custody reachability would let a transient outage suppress
// the backup window — but it means a tenant can accumulate snapshots that
// cannot be restored, and nothing would say so until someone tried.
//
// So the condition is surfaced on status, before anyone trips over it.

// encryptionStateFor reports whether a container is encrypted and whether its
// key is currently loaded.
//
// Never guesses. A state that could not be read is UNSPECIFIED, not NONE:
// an operator reading "not encrypted" would conclude there is nothing to
// investigate, which is the opposite of what an unreadable state means.
func (h *encryptionHooks) encryptionStateFor(ctx context.Context, containerName string) pb.EncryptionState {
	// A daemon with no encryption wired has no encrypted containers — that is
	// an answer, not an unknown.
	if !h.enabled() {
		return pb.EncryptionState_ENCRYPTION_STATE_NONE
	}

	root, _, encrypted, err := h.encryptionRootFor(containerName)
	if err != nil {
		log.Printf("[encryption] could not determine the encryption state of %s: %v", containerName, err)
		return pb.EncryptionState_ENCRYPTION_STATE_UNSPECIFIED
	}
	if !encrypted {
		return pb.EncryptionState_ENCRYPTION_STATE_NONE
	}

	status, err := h.zfs.KeyStatus(ctx, root)
	if err != nil {
		log.Printf("[encryption] could not read the key status of %s (%s): %v", containerName, root, err)
		return pb.EncryptionState_ENCRYPTION_STATE_UNSPECIFIED
	}
	if status == zfscrypt.KeyAvailable {
		return pb.EncryptionState_ENCRYPTION_STATE_UNLOCKED
	}
	return pb.EncryptionState_ENCRYPTION_STATE_KEY_UNAVAILABLE
}

// withEncryptionState stamps the encryption state onto a container being
// returned to a caller.
//
// Tolerant by design: this is decoration on a response, and a status field
// must never be the reason a list fails. An unreadable state is reported as
// UNSPECIFIED by encryptionStateFor rather than raised here.
func (s *ContainerServer) withEncryptionState(ctx context.Context, c *pb.Container) *pb.Container {
	if c == nil {
		return nil
	}
	c.EncryptionState = s.encryption.encryptionStateFor(ctx, c.Name)
	return c
}
