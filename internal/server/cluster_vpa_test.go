package server

// VPA deployment through the reconciler (#1416): the pinned bundle and
// a per-cluster webhook secret land on the CP via the k3s auto-apply
// dir, exactly once.

import (
	"context"
	"strings"
	"testing"

	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
)

func TestReconciler_DeploysVPAOntoCP(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	ctx := context.Background()
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)

	cp := "alice-k8s-demo-cp"
	manifests := string(host.files[cp+":"+clustercore.VPAManifestPath])
	if !strings.Contains(manifests, "vpa-recommender") || !strings.Contains(manifests, "@sha256:") {
		t.Fatal("digest-pinned VPA manifests not deployed to the CP")
	}
	secretA := string(host.files[cp+":"+clustercore.VPACertsPath])
	if !strings.Contains(secretA, "vpa-tls-certs") {
		t.Fatal("VPA webhook secret not deployed")
	}
	// Further passes never rotate the webhook secret.
	rec.ReconcileOnce(ctx)
	if string(host.files[cp+":"+clustercore.VPACertsPath]) != secretA {
		t.Fatal("reconciler pass rotated the deployed VPA webhook secret")
	}

	// Disabled reconcilers deploy no VPA.
	srv2, rec2, host2 := testReconcilerRig(t)
	rec2.SetVPADisabled(true)
	mustCreate(t, srv2, tenantCtx("alice"), "demo")
	rec2.ReconcileOnce(ctx)
	rec2.ReconcileOnce(ctx)
	if _, ok := host2.files["alice-k8s-demo-cp:"+clustercore.VPAManifestPath]; ok {
		t.Fatal("VPA deployed despite being disabled")
	}
}
