//go:build k8s

package k8s

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestE2E_BoxLifecycle drives the reconciler against a REAL apiserver (a kind
// cluster in CI). It is gated on CONTAINARIUM_K8S_E2E so it never runs in the
// plain unit suite — only scripts/k8s-e2e.sh (and the k8s-e2e workflow) set it,
// with KUBECONFIG pointing at the cluster.
//
//	CONTAINARIUM_K8S_E2E=1 KUBECONFIG=... go test -tags k8s -run TestE2E ./pkg/core/box/k8s/
func TestE2E_BoxLifecycle(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}

	b, err := New(Config{
		Kubeconfig:  os.Getenv("KUBECONFIG"),
		BoxImage:    "registry.k8s.io/pause:3.9",
		GatewayHost: "gateway.example.com",
	})
	if err != nil {
		t.Fatalf("New (is the cluster reachable?): %v", err)
	}

	ctx := context.Background()
	ref := box.BoxRef{Tenant: "e2e"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })

	// Create reconciles namespace + Secret + Service + NetworkPolicy + StatefulSet.
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "registry.k8s.io/pause:3.9",
		SSHKeys:   []string{"ssh-ed25519 AAAAExampleKeyForE2E test@e2e"},
		AutoStart: true,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Poll until the pod is Ready (the apiserver + kubelet actually schedule it).
	st := waitForState(t, b, ref, pb.ContainerState_CONTAINER_STATE_RUNNING, 3*time.Minute)
	if st.IPAddress == "" {
		t.Errorf("running box has no pod IP")
	}

	// Stop scales to 0 → STOPPED.
	if err := b.Stop(ctx, ref, false); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitForState(t, b, ref, pb.ContainerState_CONTAINER_STATE_STOPPED, time.Minute)

	// Start scales back to 1 → RUNNING.
	if err := b.Start(ctx, ref); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForState(t, b, ref, pb.ContainerState_CONTAINER_STATE_RUNNING, 3*time.Minute)

	// SetAuthorizedKeys upserts the Secret without error.
	if err := b.SetAuthorizedKeys(ctx, ref, []string{"ssh-ed25519 BBBBRotatedKey test@e2e"}); err != nil {
		t.Fatalf("SetAuthorizedKeys: %v", err)
	}

	// Delete removes the namespace; Get eventually reports absent.
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		got, gerr := b.Get(ctx, ref)
		if gerr == nil && got == nil {
			return // gone
		}
		time.Sleep(3 * time.Second)
	}
	t.Error("box still present 2m after Delete")
}

func waitForState(t *testing.T, b *Backend, ref box.BoxRef, want pb.ContainerState, timeout time.Duration) *box.BoxStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last *box.BoxStatus
	for time.Now().Before(deadline) {
		st, err := b.Get(context.Background(), ref)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		last = st
		if st != nil && st.State == want {
			return st
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("box did not reach %v within %s (last: %+v)", want, timeout, last)
	return nil
}

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

// TestE2E_GatewayPipe installs the sshpiper Pipe CRD into the kind cluster
// (just the CRD, not sshpiper itself), then asserts the reconciler programs and
// removes the Pipe against the real apiserver — validating the GVR + spec shape
// end to end. A full data-plane e2e (deploy sshpiper, SSH through the gateway)
// needs the real agent-box image and is a follow-up.
func TestE2E_GatewayPipe(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("rest config: %v", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	ctx := context.Background()

	installPipeCRD(t, dyn)

	const gwNS = "sshpiper"
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gwNS}}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create gateway namespace: %v", err)
	}

	b, err := New(Config{
		Kubeconfig:       kubeconfig,
		BoxImage:         "registry.k8s.io/pause:3.9",
		GatewayNamespace: gwNS,
		GatewayHost:      "gateway.example.com",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ref := box.BoxRef{Tenant: "gw-e2e"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })

	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "registry.k8s.io/pause:3.9",
		SSHKeys:   []string{"ssh-ed25519 AAAAExampleKey test@gw-e2e"},
		AutoStart: true,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The reconciler should have created a Pipe in the gateway namespace.
	p, err := dyn.Resource(pipeGVR).Namespace(gwNS).Get(ctx, pipeName("gw-e2e"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pipe: %v", err)
	}
	host, _, _ := unstructured.NestedString(p.Object, "spec", "to", "host")
	if host != "box-0.boxes.tenant-gw-e2e.svc.cluster.local:2222" {
		t.Errorf("pipe to.host = %q", host)
	}

	// Delete removes the Pipe (it lives in the gateway ns, outside the cascade).
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := dyn.Resource(pipeGVR).Namespace(gwNS).Get(ctx, pipeName("gw-e2e"), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("pipe still present after Delete (err=%v)", err)
	}
}

// TestE2E_CSIStorage drives the PVC lifecycle against a real apiserver using
// kind's default "standard" StorageClass (local-path-provisioner, pre-installed
// by kind). It verifies Create provisions a PVC + wires the data volume into the
// StatefulSet, Delete retains the namespace + PVC while removing compute objects,
// and Purge removes both.
//
// The PVC stays in Pending until a pod is scheduled (local-path binds on pod
// assignment); we assert the object exists, not that it is Bound — the mount
// wiring is what matters for storage correctness.
func TestE2E_CSIStorage(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}
	kubeconfig := os.Getenv("KUBECONFIG")

	b, err := New(Config{
		Kubeconfig:   kubeconfig,
		BoxImage:     "registry.k8s.io/pause:3.9",
		GatewayHost:  "gateway.example.com",
		StorageClass: "standard", // kind's default local-path StorageClass
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("rest config: %v", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}

	ctx := context.Background()
	ref := box.BoxRef{Tenant: "csi-e2e"}
	ns := "tenant-csi-e2e"
	t.Cleanup(func() { _ = b.Purge(context.Background(), ref) })

	// Create: PVC provisioned, StatefulSet mounts it at /home/agent.
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "registry.k8s.io/pause:3.9",
		SSHKeys:   []string{"ssh-ed25519 AAAAExampleKeyForCSIE2E test@csi-e2e"},
		Resources: box.ResourceLimits{Disk: "1Gi"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("PVC not found after Create: %v", err)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "standard" {
		t.Errorf("PVC StorageClass = %v, want 'standard'", pvc.Spec.StorageClassName)
	}
	if q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; q.String() != "1Gi" {
		t.Errorf("PVC storage request = %q, want 1Gi", q.String())
	}

	ss, err := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("StatefulSet not found: %v", err)
	}
	mounts := map[string]string{}
	for _, m := range ss.Spec.Template.Spec.Containers[0].VolumeMounts {
		mounts[m.MountPath] = m.Name
	}
	if mounts[dataMount] == "" {
		t.Errorf("data volume not mounted at %s; mounts: %v", dataMount, mounts)
	}

	// Delete: compute objects removed; namespace + PVC retained so data survives a node reap.
	if err := b.Delete(ctx, ref, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		t.Errorf("namespace removed by Delete: %v", err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{}); err != nil {
		t.Errorf("PVC removed by Delete: %v", err)
	}
	if _, err := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{}); err == nil {
		t.Error("StatefulSet still present after Delete")
	}

	// Purge: PVC and namespace gone. Namespace deletion is asynchronous in K8s
	// (goes through Terminating state), so poll until NotFound.
	if err := b.Purge(ctx, ref); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		_, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			break // gone
		}
		time.Sleep(3 * time.Second)
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("namespace still present 2m after Purge (err=%v)", err)
	}
	// Purge of an already-gone box is a no-op.
	if err := b.Purge(ctx, ref); err != nil {
		t.Errorf("second Purge = %v, want nil", err)
	}
}

// installPipeCRD applies a minimal sshpiper Pipe CRD (open schema via
// x-kubernetes-preserve-unknown-fields) and waits for it to be Established.
func installPipeCRD(t *testing.T, dyn dynamic.Interface) {
	t.Helper()
	ctx := context.Background()
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": "pipes.sshpiper.com"},
		"spec": map[string]any{
			"group": "sshpiper.com",
			"scope": "Namespaced",
			"names": map[string]any{
				"plural":   "pipes",
				"singular": "pipe",
				"kind":     "Pipe",
				"listKind": "PipeList",
			},
			"versions": []any{map[string]any{
				"name":    "v1beta1",
				"served":  true,
				"storage": true,
				"schema": map[string]any{
					"openAPIV3Schema": map[string]any{
						"type":                                 "object",
						"x-kubernetes-preserve-unknown-fields": true,
					},
				},
			}},
		},
	}}
	if _, err := dyn.Resource(crdGVR).Create(ctx, crd, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("install Pipe CRD: %v", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		got, err := dyn.Resource(crdGVR).Get(ctx, "pipes.sshpiper.com", metav1.GetOptions{})
		if err == nil {
			conds, _, _ := unstructured.NestedSlice(got.Object, "status", "conditions")
			for _, c := range conds {
				cm, ok := c.(map[string]any)
				if ok && cm["type"] == "Established" && cm["status"] == "True" {
					return
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("Pipe CRD not Established within 60s")
}
