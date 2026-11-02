package sshauthz

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Reconcile after a window without the registry (#3330, decision Q14 on
// #3335). While the daemon ran without the ssh_keys registry (a degraded
// start), every key revoke was a no-op on it, so a key removed from an
// authorized_keys file in that window keeps an active row, and the backfill
// only adds rows. The self-host decider's /home check does not cover it: it
// requires the login's account to hold SOME key, not the offered one, so a
// stale row is still allowed while the account keeps another key. Reconcile
// closes that: it revokes every active row whose key no account holds.

// ReconcileStore is what Reconcile needs from the registry. *PGKeyStore
// satisfies it.
type ReconcileStore interface {
	// ActiveRecords returns every row that is not revoked (released rows
	// included).
	ActiveRecords(ctx context.Context) ([]KeyRecord, error)
	Revoke(ctx context.Context, rec KeyRecord, at time.Time) error
}

// ReconcileResult counts what Reconcile did.
type ReconcileResult struct {
	// Revoked is the number of rows revoked because no account holds the key.
	Revoked int
	// Unresolved is the number of rows left active because a holder could
	// not be ruled out: an account's authorized_keys was unreadable, or a
	// holder turned up when the revoke ran.
	Unresolved int
}

// Reconcile revokes every active registry row whose key no account under
// homeRoot holds, as its own account (store.Revoke applies the ownership
// and other-holder rules). It is idempotent. Rows are never revoked while
// any account's authorized_keys is unreadable, because that account might
// hold the key (the #3241 rule for revokes); they are counted as Unresolved
// and the run still succeeds, so one bad home does not keep the registry
// off for everyone. An unreadable homeRoot, a registry read error or a
// revoke failing for another reason is returned, and the caller retries.
func Reconcile(ctx context.Context, store ReconcileStore, homeRoot string, now time.Time) (ReconcileResult, error) {
	var out ReconcileResult
	// Rows first, /home second. A key write path writes the file before it
	// registers the row, so every row read here already has its file, and
	// the scan below sees it. In the other order a key added between the
	// scan and the read would look unheld and be revoked, and Revoke's own
	// holder check would not stop it: it excludes the row's own account.
	rows, err := store.ActiveRecords(ctx)
	if err != nil {
		return out, fmt.Errorf("reconcile ssh keys: %w", err)
	}
	scan, err := ScanAuthorizedKeys(homeRoot, now)
	if err != nil {
		return out, fmt.Errorf("reconcile ssh keys: %w", err)
	}
	held := make(map[string]bool, len(scan.Records))
	for _, r := range scan.Records {
		held[r.Fingerprint] = true
	}
	for _, row := range rows {
		if held[row.Fingerprint] {
			continue
		}
		if len(scan.Unreadable) > 0 {
			out.Unresolved++
			continue
		}
		err := store.Revoke(ctx, row, now)
		switch {
		case errors.Is(err, ErrKeyHeldByOtherAccount), errors.Is(err, ErrHolderUnknown):
			// A holder appeared, or could not be ruled out, at revoke time.
			out.Unresolved++
		case err != nil:
			return out, fmt.Errorf("reconcile ssh keys: %w", err)
		default:
			out.Revoked++
		}
	}
	if out.Unresolved > 0 && len(scan.Unreadable) > 0 {
		log.Printf("[ssh-keys] reconcile left %d row(s) with no readable holder active: %d account(s) under %s could not be read, so a holder cannot be ruled out (#3241)",
			out.Unresolved, len(scan.Unreadable), homeRoot)
	}
	return out, nil
}
