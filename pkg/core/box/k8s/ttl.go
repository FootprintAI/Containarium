package k8s

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/footprintai/containarium/pkg/core/box"
)

// metaTTLExpiresAtKey is the meta key (under metaAnnotationPrefix) mirroring
// the Sandbox's spec.shutdownTime. The daemon's TTL sweeper reads box meta
// (BoxStatus.Labels, fed from these annotations) — it never parses the CRD —
// so the expiry is mirrored here in the same RFC3339 form the sweeper already
// understands from the Incus path.
const metaTTLExpiresAtKey = "ttl_expires_at"

var _ box.TTLCapable = (*Backend)(nil)

// SetTTL stamps (or clears, expiresAt == nil) the box's absolute auto-delete
// time.
//
// Two cooperating mechanisms, one patch:
//   - spec.shutdownTime + shutdownPolicy Retain: the agent-sandbox controller
//     stops the pod at the deadline even if the daemon is down (defense in
//     depth). Retain — not Delete — because a controller-side Sandbox delete
//     would orphan everything the daemon owns around it (Pipe, Secrets, PVC,
//     namespace, Caddy routes) and skip the DeleteContainer audit cascade.
//   - the ttl_expires_at meta annotation: the daemon's sweeper reads it off
//     List() and routes the actual delete through DeleteContainer, so the
//     full cascade fires exactly as it does for an LXC box.
func (b *Backend) SetTTL(ctx context.Context, ref box.BoxRef, expiresAt *time.Time) error {
	var patch []byte
	if expiresAt == nil {
		// Merge-patch nulls delete the map key / clear the scalar.
		patch = fmt.Appendf(nil, `{"metadata":{"annotations":{%q:null}},"spec":{"shutdownTime":null}}`,
			metaAnnotationPrefix+metaTTLExpiresAtKey)
	} else {
		ts := expiresAt.UTC().Format(time.RFC3339)
		patch = fmt.Appendf(nil, `{"metadata":{"annotations":{%q:%q}},"spec":{"shutdownTime":%q,"shutdownPolicy":"Retain"}}`,
			metaAnnotationPrefix+metaTTLExpiresAtKey, ts, ts)
	}
	_, err := b.sandboxes.AgentsV1beta1().Sandboxes(b.namespaceFor(ref.Tenant)).
		Patch(ctx, sandboxName, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}
