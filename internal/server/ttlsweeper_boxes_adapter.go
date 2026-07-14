package server

import (
	"context"
	"time"

	"github.com/footprintai/containarium/internal/ttlsweeper"
	"github.com/footprintai/containarium/pkg/core/box"
)

// ttlsweeperBoxAdapter bridges box.BoxBackend → ttlsweeper.IncusClient for
// runtimes with no Incus (the K8s backend). Sibling of ttlsweeperIncusAdapter:
// same one-method seam, different source.
//
// The view is deliberately thinner than the Incus adapter's: only the
// absolute TTL rule is fed (from the backend's ttl_expires_at meta, which the
// K8s backend mirrors off the Sandbox's spec.shutdownTime). Stopped→delete
// (#525) and protected boxes (#284) aren't modeled by the K8s backend yet, so
// those fields stay zero and Decide skips their rules.
//
// Names are surfaced in "<tenant>-container" form so ttlsweeperDeleter's
// suffix-strip recovers the username exactly as it does for LXC boxes.
type ttlsweeperBoxAdapter struct {
	bb box.BoxBackend
}

func (a *ttlsweeperBoxAdapter) ListContainers() ([]ttlsweeper.ContainerView, error) {
	// The sweeper interface is synchronous; bound the backend call so a hung
	// apiserver can't wedge the tick loop forever.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	boxes, err := a.bb.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ttlsweeper.ContainerView, 0, len(boxes))
	for i := range boxes {
		b := boxes[i]
		v := ttlsweeper.ContainerView{Name: b.Ref.Tenant + "-container"}
		if raw := b.Labels["ttl_expires_at"]; raw != "" {
			if t, perr := time.Parse(time.RFC3339, raw); perr == nil {
				v.TTLExpiresAt = &t
			}
		}
		out = append(out, v)
	}
	return out, nil
}
