package sshauthz

import (
	"context"
	"errors"
	"log"
	"time"
)

// ErrKeyHeldByOtherAccount is returned by Revoke when the revocation would
// take effect but another account still holds the same public key in its own
// authorized_keys (#3222). It deliberately carries no account name.
var ErrKeyHeldByOtherAccount = errors.New("ssh key is still held by another account")

// ErrHolderUnknown is returned when an account's authorized_keys could not be
// read, so it cannot be ruled out as a holder and the revoke fails closed
// (#3241). It reaches API callers, possibly of a different tenant, so it
// names neither the account nor the filesystem state; both are in the
// daemon log.
var ErrHolderUnknown = errors.New("cannot rule out another account as a holder: an account's authorized_keys could not be read; check the daemon log")

// ErrHomeRootUnreadable is returned when the home root itself could not be
// scanned, so no account can be ruled out as a holder and the revoke fails
// closed (#3276). Like ErrHolderUnknown it reaches API callers, so it carries
// neither the path nor the os error; both are in the daemon log.
var ErrHomeRootUnreadable = errors.New("cannot rule out another account as a holder: the account home directory could not be read; check the daemon log")

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
		// Fail closed: an unreadable home root is not "no holder". The path and
		// os error stay in the daemon log, not in the caller's error.
		log.Printf("[ssh-keys] cannot read the home root, failing the revoke closed: %v (#3276)", err)
		return false, ErrHomeRootUnreadable
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
			log.Printf("[ssh-keys] cannot rule out account %s as a key holder, failing the revoke closed: %v (#3241)", u.Username, u.Err)
			return false, ErrHolderUnknown
		}
	}
	return false, nil
}
