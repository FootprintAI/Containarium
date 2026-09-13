// Package runlease implements the pure lifecycle of a run's credentials.
//
// A Lease bundles a run id, the box (container) its seed files live in, and
// the one or two Credentials minted for the run. End revokes every
// credential first, then wipes the seed files out of the box. The order is
// deliberate: revoking kills a credential the instant it is called, even if
// a copy has already left the box (exfiltrated, cached, whatever); wiping
// only closes the read path inside the box itself. Doing it in the other
// order would leave a window where a credential copied out before the wipe
// remains valid until the (later) revoke lands. Both steps are always
// attempted, even when one of them fails, so a slow or unreachable
// revocation store never prevents the seed files from being wiped and vice
// versa.
//
// End has no logging of its own — the caller logs and audits from the
// returned Outcome — which keeps this package pure and its tests
// table-driven.
package runlease

import (
	"context"
	"fmt"
	"time"
)

// Kind identifies what a Credential is for.
type Kind string

const (
	KindPlatformJWT  Kind = "platform_jwt"
	KindGatewayToken Kind = "gateway_token"
)

// Credential is one token minted for a run.
type Credential struct {
	Kind      Kind
	JTI       string
	ExpiresAt time.Time
}

// Lease is the run-scoped bundle of credentials and where their seed files
// live.
type Lease struct {
	RunID       string
	Box         string       // container name the seed files live in
	SeedDir     string       // /etc/containarium/agent
	Credentials []Credential // 1..2 today
}

// Revoker is the subset of auth.RevocationStore End needs.
type Revoker interface {
	Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error
}

// Wiper is the subset of *container.Manager End needs.
type Wiper interface {
	Exec(container string, cmd []string) error
}

// Outcome reports what End actually did.
type Outcome struct {
	Revoked   []string // jtis the store accepted
	Unrevoked []string // jtis the store rejected or that had no store
	Wiped     bool
	Errs      []error // one per failed step; never aborts the others
}

const (
	revokeTimeout = 2 * time.Second
	wipeTimeout   = 3 * time.Second
)

// End revokes every credential, then wipes the seed files. Both steps always
// run; the order is deliberate: revocation kills an exfiltrated copy, the
// wipe closes the in-box read. A nil revoker records every jti as
// Unrevoked. The caller is expected to pass a context already detached from
// its own request (context.WithoutCancel) so a cancelled caller still gets
// its credentials revoked.
func End(ctx context.Context, l Lease, rev Revoker, w Wiper, reason string) Outcome {
	var out Outcome

	for _, c := range l.Credentials {
		revoked, err := revokeOne(ctx, rev, c, reason)
		if revoked {
			out.Revoked = append(out.Revoked, c.JTI)
		} else {
			out.Unrevoked = append(out.Unrevoked, c.JTI)
		}
		if err != nil {
			out.Errs = append(out.Errs, err)
		}
	}

	wiped, err := wipeSeed(w, l.Box, l.SeedDir)
	out.Wiped = wiped
	if err != nil {
		out.Errs = append(out.Errs, err)
	}

	return out
}

// revokeOne revokes a single credential under its own timeout. A nil rev
// counts the jti as unrevoked without treating that as an error step — it
// means there is no store configured, not that revocation failed.
func revokeOne(ctx context.Context, rev Revoker, c Credential, reason string) (revoked bool, err error) {
	if rev == nil {
		return false, nil
	}

	rctx, cancel := context.WithTimeout(ctx, revokeTimeout)
	defer cancel()

	if err := rev.Revoke(rctx, c.JTI, c.ExpiresAt, reason); err != nil {
		return false, fmt.Errorf("runlease: revoke %s: %w", c.JTI, err)
	}
	return true, nil
}

// wipeSeed removes the run's seed files from the box. w.Exec has no context
// parameter of its own, so the timeout is enforced by racing its result
// against a timer; an Exec that is still running past wipeTimeout is
// reported as failed (Wiped=false) even though it may still complete in the
// background.
func wipeSeed(w Wiper, box, seedDir string) (bool, error) {
	if w == nil {
		return false, nil
	}
	if seedDir == "" {
		// An empty SeedDir would otherwise build "rm -f /token
		// /gateway.env" — a box-root-relative command nobody asked
		// for. Refuse instead of running it.
		return false, fmt.Errorf("runlease: wipe seed: empty seed dir")
	}

	cmd := []string{"rm", "-f", seedDir + "/token", seedDir + "/gateway.env"}

	done := make(chan error, 1)
	go func() {
		done <- w.Exec(box, cmd)
	}()

	select {
	case err := <-done:
		if err != nil {
			return false, fmt.Errorf("runlease: wipe seed: %w", err)
		}
		return true, nil
	case <-time.After(wipeTimeout):
		return false, fmt.Errorf("runlease: wipe seed: timed out after %s", wipeTimeout)
	}
}
