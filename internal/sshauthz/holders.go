package sshauthz

import (
	"context"
	"errors"
	"fmt"
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
	res, err := ScanAuthorizedKeys(f.HomeRoot, time.Time{})
	if err != nil {
		return false, err // fail closed: an unreadable home root is not "no holder"
	}
	// A holder among the readable accounts answers the question whatever else
	// is unreadable, so only the revoke whose answer depends on an account we
	// cannot read fails.
	for _, r := range res.Records {
		if r.Fingerprint == fingerprint && r.Username != excludeUsername {
			return true, nil
		}
	}
	// Fail closed: an account we cannot read might hold the key. The excluded
	// account's own state does not matter to whether another account holds it.
	for _, u := range res.Unreadable {
		if u.Username != excludeUsername {
			return false, fmt.Errorf("cannot rule out account %s as a holder: %w", u.Username, u.Err)
		}
	}
	return false, nil
}
