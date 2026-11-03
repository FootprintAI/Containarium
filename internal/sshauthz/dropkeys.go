package sshauthz

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DropRevokedKeys returns keys (authorized_keys lines) without the ones the
// registry has revoked, preserving order, plus how many were dropped. A key the
// registry has no row for is kept: it predates the registry and cannot be
// known revoked. An unparseable line is dropped (it could not be authorized
// anyway). Any other lookup error fails closed: nothing is returned.
func DropRevokedKeys(ctx context.Context, reg KeyLookup, keys []string) (kept []string, dropped int, err error) {
	for _, k := range keys {
		rec, perr := NewKeyRecord(k, "", "", time.Time{})
		if perr != nil {
			dropped++
			continue
		}
		cur, lerr := reg.Lookup(ctx, rec.Fingerprint)
		switch {
		case errors.Is(lerr, ErrKeyNotFound):
		case lerr != nil:
			return nil, 0, fmt.Errorf("look up %s: %w", rec.Fingerprint, lerr)
		case !cur.RevokedAt.IsZero():
			dropped++
			continue
		}
		kept = append(kept, k)
	}
	return kept, dropped, nil
}
