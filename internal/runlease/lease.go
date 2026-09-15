// Package runlease implements the pure lifecycle of a run's credentials.
//
// A Lease bundles a run id, the box (container) its seed files live in, and
// the one or two Credentials minted for the run. End revokes every
// credential first, then wipes the seed files out of the box, then (#1860)
// removes the seed directory and workspace directory entirely. The order is
// deliberate: revoking kills a credential the instant it is called, even if
// a copy has already left the box (exfiltrated, cached, whatever); wiping
// the two named files closes the read path inside the box itself quickly;
// removing the whole directory afterward cleans up everything else a run
// left behind (prompt, input, a fetched repo). Doing revoke after wipe would
// leave a window where a credential copied out before the wipe remains
// valid until the (later) revoke lands. Every step is always attempted, even
// when an earlier one fails, so a slow or unreachable revocation store never
// prevents the seed files from being wiped, and vice versa.
//
// End has no logging of its own — the caller logs and audits from the
// returned Outcome — which keeps this package pure and its tests
// table-driven.
package runlease

import (
	"context"
	"fmt"
	"path"
	"strings"
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
	SeedDir     string       // e.g. /etc/containarium/agent/runs/<run_id>
	Workspace   string       // e.g. /workspace/runs/<run_id>; "" = no fetched repo for this run (#1859)
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
	Revoked     []string // jtis the store accepted
	Unrevoked   []string // jtis the store rejected or that had no store
	Wiped       bool     // the two seed files (token, gateway.env) are gone
	DirsRemoved bool     // #1860: the seed dir and (if set) the workspace are gone entirely
	Errs        []error  // one per failed step; never aborts the others
}

const (
	revokeTimeout     = 2 * time.Second
	wipeTimeout       = 3 * time.Second
	removeDirsTimeout = 3 * time.Second
)

// End revokes every credential, wipes the seed files, then (#1860) removes
// the seed directory and workspace entirely. Every step always runs; the
// order is deliberate: revocation kills an exfiltrated copy, the file wipe
// closes the specific credential read path quickly, and the directory
// removal afterward cleans up everything else (prompt, input, a fetched
// repo) without racing the two steps that matter most for credential safety.
// A nil revoker records every jti as Unrevoked. The caller is expected to
// pass a context already detached from its own request
// (context.WithoutCancel) so a cancelled caller still gets its credentials
// revoked.
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

	dirsRemoved, err := removeDirs(w, l.Box, l.SeedDir, l.Workspace)
	out.DirsRemoved = dirsRemoved
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

// removeDirs removes the run's seed directory and, if set, its workspace
// with one `rm -rf`, under its own timeout — a slow or unreachable box here
// never blocks the caller past removeDirsTimeout. Both paths must pass
// isSafeToRemove or nothing is removed and the reason is reported as an
// error: the command is refused as a whole rather than built from half a
// validated pair.
func removeDirs(w Wiper, box, seedDir, workspace string) (bool, error) {
	if w == nil {
		return false, nil
	}
	if !isSafeToRemove(seedDir) {
		return false, fmt.Errorf("runlease: remove dirs: seed dir %q is not safe to remove", seedDir)
	}
	cmd := []string{"rm", "-rf", seedDir}
	if workspace != "" {
		if !isSafeToRemove(workspace) {
			return false, fmt.Errorf("runlease: remove dirs: workspace %q is not safe to remove", workspace)
		}
		cmd = append(cmd, workspace)
	}

	done := make(chan error, 1)
	go func() {
		done <- w.Exec(box, cmd)
	}()

	select {
	case err := <-done:
		if err != nil {
			return false, fmt.Errorf("runlease: remove dirs: %w", err)
		}
		return true, nil
	case <-time.After(removeDirsTimeout):
		return false, fmt.Errorf("runlease: remove dirs: timed out after %s", removeDirsTimeout)
	}
}

// isSafeToRemove reports whether p is a plausible per-run directory to
// remove with `rm -rf`: an absolute, already-clean path with at least three
// segments (e.g. "/workspace/runs/<run_id>" or
// "/etc/containarium/agent/runs/<run_id>"). This is a sanity floor, not an
// allowlist of specific roots — runlease has no knowledge of the caller's
// actual root paths, so it can only refuse implausible input (empty,
// relative, unclean, or shallow like "/" or "/etc") rather than enforce a
// specific one. The caller is responsible for constructing SeedDir/Workspace
// under its own fixed, per-run roots.
func isSafeToRemove(p string) bool {
	if p == "" || !path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	segments := strings.Count(strings.TrimPrefix(p, "/"), "/") + 1
	return segments >= 3
}
