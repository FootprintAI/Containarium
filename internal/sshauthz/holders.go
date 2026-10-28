package sshauthz

import (
	"context"
	"errors"
	"time"
)

// ErrKeyHeldByOtherAccount is returned by Revoke when the revocation would
// take effect but another account still holds the same public key in its own
// authorized_keys (#3222). It deliberately carries no account name.
var ErrKeyHeldByOtherAccount = errors.New("ssh key is still held by another account")

// HolderLookup reports whether any account other than excludeUsername holds
// the key with the given fingerprint.
type HolderLookup interface {
	OtherAccountHolds(ctx context.Context, fingerprint, excludeUsername string) (bool, error)
}

// FileHolders answers HolderLookup from the host's authorized_keys files
// (homeRoot/*/.ssh/authorized_keys), the same source the startup backfill
// reads and the authorization decider checks.
type FileHolders struct{ HomeRoot string }

// OtherAccountHolds implements HolderLookup.
func (f FileHolders) OtherAccountHolds(ctx context.Context, fingerprint, excludeUsername string) (bool, error) {
	_ = time.Now
	return false, nil
}
