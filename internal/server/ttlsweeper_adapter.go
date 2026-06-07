package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/ttlsweeper"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ttlsweeperIncusAdapter bridges *incus.Client → ttlsweeper.IncusClient.
//
// The ttlsweeper package was deliberately decoupled from
// pkg/core/incus and pkg/pb to keep its decision logic pure-Go and
// trivially testable; the wiring lives here on the daemon side, where
// the binding to the real Incus client costs ~15 lines and keeps the
// dependency arrow pointing the right way (daemon → sweeper, never
// sweeper → daemon).
//
// The adapter strips ListContainers down to just (Name, TTLExpiresAt)
// — the only fields Decide actually consumes — and skips core
// containers entirely. Core containers must never carry a TTL; this
// is defense in depth in case a writer somewhere stamps the key by
// mistake. Decide would still skip them (because no one should be
// setting the key in the first place), but excluding here means a
// stray key never even reaches the decision function.
type ttlsweeperIncusAdapter struct {
	ic *incus.Client
}

// ListContainers returns one ContainerView per non-core container
// the Incus client knows about. Containers whose TTL key parses as
// the zero time (missing/empty/malformed) carry a nil TTLExpiresAt
// so Decide's "skip" branch is naturally exercised.
func (a *ttlsweeperIncusAdapter) ListContainers() ([]ttlsweeper.ContainerView, error) {
	raw, err := a.ic.ListContainers()
	if err != nil {
		return nil, err
	}
	out := make([]ttlsweeper.ContainerView, 0, len(raw))
	for i := range raw {
		c := raw[i]
		if c.Role.IsCoreRole() {
			continue
		}
		v := ttlsweeper.ContainerView{Name: c.Name}
		if !c.TTLExpiresAt.IsZero() {
			t := c.TTLExpiresAt
			v.TTLExpiresAt = &t
		}
		// Stopped→delete inputs (#525). Only a genuinely STOPPED box with a
		// recorded stop time and an opted-in window is eligible; everything
		// else leaves these nil/false and Decide skips the stopped rule.
		v.Stopped = strings.EqualFold(c.State, "Stopped")
		if !c.StoppedAt.IsZero() {
			s := c.StoppedAt
			v.StoppedAt = &s
		}
		if c.DeleteAfterStoppedSeconds > 0 {
			d := time.Duration(c.DeleteAfterStoppedSeconds) * time.Second
			v.DeleteAfterStopped = &d
		}
		// Protected boxes (#284) are never auto-reaped, regardless of any timer.
		v.Protected = c.DeletePolicy == incus.DeletePolicyProtected
		out = append(out, v)
	}
	return out, nil
}

// ttlsweeperDeleter routes the sweeper's "delete this container"
// requests through the existing DeleteContainer RPC plumbing so audit
// logging, event emission, route/Caddy cascade cleanup, the IP-map
// refresh, and the Guacamole-deregister step all fire — same code
// path a human invocation of `containarium delete` would take.
//
// Bypassing the handler and calling incus.Client.DeleteContainer
// directly would technically delete the LXC but leave Caddy routes
// pointing at a dead upstream IP (502s on the public hostname),
// orphan TLS-cert ACME renewals, and skip every event subscriber that
// downstream observers rely on. So we go through the handler.
//
// reason is propagated as a structured log line — the sweeper already
// logs a [ttlsweeper] line on success; the duplicate log here is
// intentional, it bridges the sweeper's log namespace and the
// handler's existing log namespace so an operator grepping either
// surface sees the event.
type ttlsweeperDeleter struct {
	cs *ContainerServer
}

func (d *ttlsweeperDeleter) DeleteContainer(ctx context.Context, name, reason string) error {
	// Promote to the daemon-internal identity so the handler's authz
	// checks pass (mirrors what StopForAutoSleep does for the
	// autosleep ticker).
	ctx = auth.ContextWithSystemIdentity(ctx)

	// The container key is "<username>-container" in this codebase
	// (see ToggleAutoSleep, StopContainer, etc.). Strip the suffix
	// to recover the username the handler expects in
	// DeleteContainerRequest.
	username := name
	const suffix = "-container"
	if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
		username = name[:len(name)-len(suffix)]
	} else {
		// Defensive: anything that doesn't fit the "-container"
		// convention isn't a user box the sweeper should delete.
		// Don't bypass that check by guessing a username.
		return fmt.Errorf("ttlsweeper: refusing to delete %q (not in <username>-container form)", name)
	}

	log.Printf("[ttl] auto-deleting container=%s reason=%q", name, reason)
	_, err := d.cs.DeleteContainer(ctx, &pb.DeleteContainerRequest{
		Username: username,
		// Force=true: TTL expiry is a "delete now" event, not a
		// "ask the container nicely" event. The CI box may well be
		// in a broken state (that's often why it was kept); a
		// graceful stop request could hang and leave the box
		// straddling the TTL deadline.
		Force: true,
	})
	return err
}
