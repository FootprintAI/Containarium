//go:build k8s

package k8s

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// These tests drive the real reconciler against a fake clientset, so they run
// in plain `go test -tags k8s` with no cluster. The kind e2e (e2e_test.go)
// covers behavior against a real apiserver.

func testBackend() (*Backend, *fake.Clientset, *sandboxfake.Clientset) {
	cs := fake.NewSimpleClientset()
	sc := sandboxfake.NewSimpleClientset()
	return NewWithClientset(cs, sc, Config{BoxImage: "registry.k8s.io/pause:3.9", GatewayHost: "gw.example.com"}), cs, sc
}

// getSandbox fetches the tenant's Sandbox CR from the fake clientset.
func getSandbox(t *testing.T, sc *sandboxfake.Clientset, ns string) *sandboxv1beta1.Sandbox {
	t.Helper()
	sb, err := sc.AgentsV1beta1().Sandboxes(ns).Get(context.Background(), sandboxName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("sandbox not created: %v", err)
	}
	return sb
}

func TestKindAndCapabilities(t *testing.T) {
	b, _, _ := testBackend()
	if b.Kind() != box.KindK8s {
		t.Fatalf("Kind() = %q, want %q", b.Kind(), box.KindK8s)
	}
	// K8s provisioning is image-baked → no in-box exec seam.
	if _, ok := interface{}(b).(box.ExecCapable); ok {
		t.Error("k8s Backend must not implement box.ExecCapable")
	}
}

func TestCreateReconcilesObjects(t *testing.T) {
	b, cs, sc := testBackend()
	ctx := context.Background()
	st, err := b.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Image:     "registry.k8s.io/pause:3.9",
		SSHKeys:   []string{"ssh-ed25519 AAAA"},
		AutoStart: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if st == nil || st.Ref.Tenant != "alice" || st.Ref.Name != sandboxName {
		t.Fatalf("status = %+v", st)
	}

	ns := "tenant-alice"
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		t.Errorf("namespace not created: %v", err)
	}
	sb := getSandbox(t, sc, ns)
	podSpec := sb.Spec.PodTemplate.Spec
	{
		// restricted-PSA hardening the box image is built for.
		csc := podSpec.Containers[0].SecurityContext
		if csc == nil || csc.RunAsNonRoot == nil || !*csc.RunAsNonRoot {
			t.Errorf("container not runAsNonRoot: %+v", csc)
		}
		if csc != nil && (csc.Capabilities == nil || len(csc.Capabilities.Drop) != 1 || string(csc.Capabilities.Drop[0]) != "ALL") {
			t.Errorf("container does not drop ALL caps: %+v", csc.Capabilities)
		}
		if pscPort := podSpec.Containers[0].Ports[0].ContainerPort; pscPort != 2222 {
			t.Errorf("container port = %d, want 2222", pscPort)
		}
		// authorized_keys mounted where the image reads it (or the box rejects
		// every login — found in live test), and the stable host key mounted
		// (so the gateway can pin it).
		mounts := map[string]string{} // mountPath set
		for _, m := range podSpec.Containers[0].VolumeMounts {
			mounts[m.MountPath] = m.Name
		}
		if mounts["/etc/agent-box"] == "" {
			t.Errorf("authorized_keys not mounted at /etc/agent-box: %+v", podSpec.Containers[0].VolumeMounts)
		}
		if mounts["/etc/agent-box-hostkey"] == "" {
			t.Errorf("host key not mounted at /etc/agent-box-hostkey")
		}
		vols := map[string]string{} // volume name -> secret name
		for _, v := range podSpec.Volumes {
			if v.Secret != nil {
				vols[v.Name] = v.Secret.SecretName
			}
		}
		if vols[authorizedKeysVolume] != secretName("alice") {
			t.Errorf("authorized-keys volume secret = %q", vols[authorizedKeysVolume])
		}
		if vols[hostKeyVolume] != hostKeySecretName("alice") {
			t.Errorf("host-key volume secret = %q", vols[hostKeyVolume])
		}
	}
	// The controller owns the headless Service; the Sandbox must ask for it.
	if sb.Spec.Service == nil || !*sb.Spec.Service {
		t.Error("sandbox spec.service not enabled; the gateway needs the headless Service")
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, "default-deny", metav1.GetOptions{}); err != nil {
		t.Errorf("networkpolicy not created: %v", err)
	}
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, secretName("alice"), metav1.GetOptions{})
	if err != nil {
		t.Errorf("secret not created: %v", err)
	} else if string(sec.Data[authorizedKeysKey]) != "ssh-ed25519 AAAA\n" {
		t.Errorf("authorized_keys = %q", sec.Data[authorizedKeysKey])
	}

	// AutoStart=true → desired 1 replica, not yet ready under the fake → PROVISIONING.
	if st.State != pb.ContainerState_CONTAINER_STATE_PROVISIONING {
		t.Errorf("state = %v, want PROVISIONING", st.State)
	}
}

func TestCreateIdempotent(t *testing.T) {
	b, _, _ := testBackend()
	ctx := context.Background()
	spec := box.BoxSpec{Ref: box.BoxRef{Tenant: "bob"}, Image: "x", AutoStart: true}
	if _, err := b.Create(ctx, spec); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := b.Create(ctx, spec); err != nil {
		t.Fatalf("re-Create should be idempotent, got: %v", err)
	}
}

func TestGetMissing(t *testing.T) {
	b, _, _ := testBackend()
	st, err := b.Get(context.Background(), box.BoxRef{Tenant: "ghost"})
	if err != nil || st != nil {
		t.Fatalf("Get(missing) = (%+v, %v), want (nil, nil)", st, err)
	}
}

func TestStartStopScale(t *testing.T) {
	b, _, sc := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "carol"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil { // AutoStart false → 0
		t.Fatalf("Create: %v", err)
	}
	if sb := getSandbox(t, sc, "tenant-carol"); sb.Spec.OperatingMode != sandboxv1beta1.SandboxOperatingModeSuspended {
		t.Fatalf("created operatingMode = %q, want Suspended", sb.Spec.OperatingMode)
	}
	if err := b.Start(ctx, ref); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sb := getSandbox(t, sc, "tenant-carol"); sb.Spec.OperatingMode != sandboxv1beta1.SandboxOperatingModeRunning {
		t.Errorf("after Start operatingMode = %q, want Running", sb.Spec.OperatingMode)
	}
	if err := b.Stop(ctx, ref, false); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if sb := getSandbox(t, sc, "tenant-carol"); sb.Spec.OperatingMode != sandboxv1beta1.SandboxOperatingModeSuspended {
		t.Errorf("after Stop operatingMode = %q, want Suspended", sb.Spec.OperatingMode)
	}
}

func TestDeleteRemovesNamespace(t *testing.T) {
	b, cs, _ := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "dave"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, "tenant-dave", metav1.GetOptions{}); err == nil {
		t.Error("namespace still present after Delete")
	}
	// Delete of an absent box is a no-op.
	if err := b.Delete(ctx, box.BoxRef{Tenant: "nobody"}, true); err != nil {
		t.Errorf("Delete(missing) = %v, want nil", err)
	}
}

func TestSetGetMeta(t *testing.T) {
	b, _, _ := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "erin"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.SetMeta(ctx, ref, map[string]string{"ttl": "3600", "team": "infra"}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	meta, err := b.GetMeta(ctx, ref)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta["ttl"] != "3600" || meta["team"] != "infra" {
		t.Errorf("meta = %+v", meta)
	}
}

func TestResolveGatewayEndpoint(t *testing.T) {
	b, _, _ := testBackend()
	ep, err := b.Resolve(context.Background(), box.BoxRef{Tenant: "alice"})
	if err != nil || ep == nil {
		t.Fatalf("Resolve = (%+v, %v)", ep, err)
	}
	if ep.SSHHost != "gw.example.com" || ep.SSHUser != "alice" || ep.SSHPort != 22 {
		t.Errorf("endpoint = %+v", ep)
	}
}

// TestGPUResourceRequirements verifies that a non-empty GPUs list maps to an
// nvidia.com/gpu limit on the container, and that the pod carries the
// gpu-count annotation for observability.
func TestGPUResourceRequirements(t *testing.T) {
	b, _, sc := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "gpu-user"}
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:   ref,
		Image: "x",
		GPUs:  []string{"gpu", "gpu1"}, // 2 GPUs
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ns := "tenant-gpu-user"
	sb := getSandbox(t, sc, ns)

	// Container must carry nvidia.com/gpu: 2 in both limits and requests.
	c := sb.Spec.PodTemplate.Spec.Containers[0]
	gpuLimit := c.Resources.Limits[nvidiaGPUResource]
	if gpuLimit.Value() != 2 {
		t.Errorf("nvidia.com/gpu limit = %v, want 2", gpuLimit.Value())
	}
	gpuReq := c.Resources.Requests[nvidiaGPUResource]
	if gpuReq.Value() != 2 {
		t.Errorf("nvidia.com/gpu request = %v, want 2", gpuReq.Value())
	}

	// Pod template must carry the gpu-count annotation.
	ann := sb.Spec.PodTemplate.ObjectMeta.Annotations[gpuCountAnnotation]
	if ann != "2" {
		t.Errorf("gpu-count annotation = %q, want 2", ann)
	}
}

// TestNoGPUResourceWhenGPUsEmpty verifies no nvidia.com/gpu limit is set and
// no gpu-count annotation is added when GPUs is nil/empty.
func TestNoGPUResourceWhenGPUsEmpty(t *testing.T) {
	b, _, sc := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "no-gpu"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ns := "tenant-no-gpu"
	sb := getSandbox(t, sc, ns)
	c := sb.Spec.PodTemplate.Spec.Containers[0]
	if _, ok := c.Resources.Limits[nvidiaGPUResource]; ok {
		t.Error("nvidia.com/gpu limit set on non-GPU box")
	}
	if sb.Spec.PodTemplate.ObjectMeta.Annotations[gpuCountAnnotation] != "" {
		t.Errorf("gpu-count annotation unexpectedly set: %q", sb.Spec.PodTemplate.ObjectMeta.Annotations[gpuCountAnnotation])
	}
}

// builtinMemDefaults is the resolved built-in floor, as newBackend would supply
// it when the operator sets no Config override.
func builtinMemDefaults() memDefaults {
	return memDefaults{request: defaultMemoryRequest, limit: defaultMemoryLimit}
}

// TestDefaultMemoryFloor verifies a box with no explicit memory gets the
// default memory request+limit, so the scheduler can bin-pack it and it can't
// balloon and pressure neighbors on the shared kernel — with the request kept
// below the limit for dense packing.
func TestDefaultMemoryFloor(t *testing.T) {
	r := resourceRequirements(box.ResourceLimits{}, 0, builtinMemDefaults())
	if r == nil {
		t.Fatal("resourceRequirements returned nil; want default memory floor")
	}
	lim := r.Limits["memory"]
	if lim.String() != defaultMemoryLimit {
		t.Errorf("memory limit = %q, want %q", lim.String(), defaultMemoryLimit)
	}
	req := r.Requests["memory"]
	if req.String() != defaultMemoryRequest {
		t.Errorf("memory request = %q, want %q", req.String(), defaultMemoryRequest)
	}
	if req.Cmp(lim) >= 0 {
		t.Errorf("memory request %q must be below limit %q for dense packing", req.String(), lim.String())
	}
}

// TestExplicitMemoryOverridesDefault verifies an explicit memory pins
// request==limit and suppresses the default floor.
func TestExplicitMemoryOverridesDefault(t *testing.T) {
	r := resourceRequirements(box.ResourceLimits{Memory: "2Gi"}, 0, builtinMemDefaults())
	lim := r.Limits["memory"]
	req := r.Requests["memory"]
	if lim.String() != "2Gi" || req.String() != "2Gi" {
		t.Errorf("memory request/limit = %q/%q, want 2Gi/2Gi", req.String(), lim.String())
	}
}

// TestSpecInvalidMemoryFallsBackToDefault verifies an incus-native quantity in
// the spec that isn't a valid K8s quantity ("4GB") is skipped and the default
// floor applies, rather than leaving the box unconstrained.
func TestSpecInvalidMemoryFallsBackToDefault(t *testing.T) {
	r := resourceRequirements(box.ResourceLimits{Memory: "4GB"}, 0, builtinMemDefaults())
	lim := r.Limits["memory"]
	if lim.String() != defaultMemoryLimit {
		t.Errorf("memory limit = %q, want default %q", lim.String(), defaultMemoryLimit)
	}
}

// TestGPUBoxExemptFromMemoryFloor verifies GPU boxes don't get the small default
// memory cap (which would OOM the workload); they're sized explicitly.
func TestGPUBoxExemptFromMemoryFloor(t *testing.T) {
	r := resourceRequirements(box.ResourceLimits{}, 1, builtinMemDefaults())
	if _, ok := r.Limits["memory"]; ok {
		t.Error("GPU box got the default memory floor; want exempt")
	}
}

// TestDisabledMemoryFloor verifies an empty floor (DisableDefaultMemoryFloor)
// leaves a box with no explicit resources unconstrained.
func TestDisabledMemoryFloor(t *testing.T) {
	if r := resourceRequirements(box.ResourceLimits{}, 0, memDefaults{}); r != nil {
		t.Errorf("disabled floor still set resources: %+v", r)
	}
}

// TestDefaultRequestClampedToLimit verifies that when an operator override sets
// a limit below the (default) request, the request is clamped to the limit so
// the pod doesn't fail admission (request must not exceed limit).
func TestDefaultRequestClampedToLimit(t *testing.T) {
	r := resourceRequirements(box.ResourceLimits{}, 0, memDefaults{request: "256Mi", limit: "128Mi"})
	req := r.Requests["memory"]
	lim := r.Limits["memory"]
	if req.Cmp(lim) > 0 {
		t.Errorf("request %q exceeds limit %q; want clamped", req.String(), lim.String())
	}
	if req.String() != "128Mi" {
		t.Errorf("request = %q, want clamped to 128Mi", req.String())
	}
}

// TestConfigOverrideMemoryFloor verifies newBackend resolves operator Config
// overrides, and that a typo'd quantity degrades to the safe built-in default
// rather than disabling the floor.
func TestConfigOverrideMemoryFloor(t *testing.T) {
	// Valid overrides flow through.
	b := NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(), Config{
		DefaultMemoryRequest: "512Mi",
		DefaultMemoryLimit:   "2Gi",
	})
	if d := b.memDefaults(); d.request != "512Mi" || d.limit != "2Gi" {
		t.Errorf("memDefaults = %+v, want {512Mi 2Gi}", d)
	}

	// A typo'd limit degrades to the built-in default (not unconstrained).
	bad := NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(), Config{DefaultMemoryLimit: "2GB"})
	if d := bad.memDefaults(); d.limit != defaultMemoryLimit {
		t.Errorf("invalid override limit = %q, want built-in %q", d.limit, defaultMemoryLimit)
	}

	// Disable clears the floor entirely.
	off := NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(), Config{DisableDefaultMemoryFloor: true})
	if d := off.memDefaults(); d.limit != "" || d.request != "" {
		t.Errorf("disabled memDefaults = %+v, want empty", d)
	}
}

// testBackendWithStorage returns a backend with a StorageClass set, exercising
// the CSI PVC lifecycle paths.
func testBackendWithStorage() (*Backend, *fake.Clientset, *sandboxfake.Clientset) {
	cs := fake.NewSimpleClientset()
	sc := sandboxfake.NewSimpleClientset()
	return NewWithClientset(cs, sc, Config{
		BoxImage:     "registry.k8s.io/pause:3.9",
		GatewayHost:  "gw.example.com",
		StorageClass: "standard",
	}), cs, sc
}

// TestPVCObjectBuilder verifies that pvcObject produces a well-formed PVC with
// the correct namespace, labels, StorageClass, and storage request.
func TestPVCObjectBuilder(t *testing.T) {
	pvc := pvcObject("tenant-alice", "alice", "standard", "20Gi")

	if pvc.Name != pvcName {
		t.Errorf("PVC name = %q, want %q", pvc.Name, pvcName)
	}
	if pvc.Namespace != "tenant-alice" {
		t.Errorf("PVC namespace = %q, want tenant-alice", pvc.Namespace)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "standard" {
		t.Errorf("StorageClassName = %v", pvc.Spec.StorageClassName)
	}
	q := pvc.Spec.Resources.Requests["storage"]
	if q.String() != "20Gi" {
		t.Errorf("storage request = %q, want 20Gi", q.String())
	}
}

// TestPVCObjectBuilderDefaults verifies the disk-size default when spec leaves
// Resources.Disk empty.
func TestPVCObjectBuilderDefaults(t *testing.T) {
	pvc := pvcObject("tenant-bob", "bob", "fast", "")
	q := pvc.Spec.Resources.Requests["storage"]
	if q.String() != defaultDisk {
		t.Errorf("default storage = %q, want %q", q.String(), defaultDisk)
	}
}

// TestCreateProvisionsPVC verifies that Create provisions a PVC when
// StorageClass is configured.
func TestCreateProvisionsPVC(t *testing.T) {
	b, cs, sc := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "frank"}
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "x",
		Resources: box.ResourceLimits{Disk: "30Gi"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ns := "tenant-frank"
	pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("PVC not created: %v", err)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "standard" {
		t.Errorf("StorageClassName = %v", pvc.Spec.StorageClassName)
	}
	q := pvc.Spec.Resources.Requests["storage"]
	if q.String() != "30Gi" {
		t.Errorf("storage request = %q, want 30Gi", q.String())
	}

	// The Sandbox pod template must mount the data volume at
	// /home/agent/workspace as a plain persistentVolumeClaim volume (NOT a
	// volumeClaimTemplate, which the controller would owner-reference and GC
	// with the Sandbox).
	sb := getSandbox(t, sc, ns)
	if len(sb.Spec.VolumeClaimTemplates) != 0 {
		t.Errorf("sandbox uses volumeClaimTemplates; the data PVC must stay daemon-owned")
	}
	mounts := map[string]string{}
	for _, m := range sb.Spec.PodTemplate.Spec.Containers[0].VolumeMounts {
		mounts[m.MountPath] = m.Name
	}
	if mounts[dataMount] == "" {
		t.Errorf("data volume not mounted at %s: mounts=%v", dataMount, mounts)
	}
	var claims []string
	for _, v := range sb.Spec.PodTemplate.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			claims = append(claims, v.PersistentVolumeClaim.ClaimName)
		}
	}
	if len(claims) != 1 || claims[0] != pvcName {
		t.Errorf("pod volumes reference claims %v, want [%s]", claims, pvcName)
	}
}

// TestDataMountDoesNotOverrideHomeDirectory is a regression test for #974:
// the data PVC must never be mounted directly at /home/agent, because that
// replaces the image's real home directory (owned by `agent`,
// dropbear-strict-modes-compatible permissions) with the provisioner's fresh
// volume root — typically root:root and group/world-writable or otherwise
// wrong for the non-root `agent` user — which makes dropbear reject every
// SSH login outright. The PVC must land one level down, at a subdirectory of
// the home directory, so the home directory itself is untouched. It also
// confirms the authorized_keys Secret mount (dropbear's login credential
// source) is unaffected: same path, still read-only, still a Secret volume.
func TestDataMountDoesNotOverrideHomeDirectory(t *testing.T) {
	if dataMount == "/home/agent" {
		t.Fatalf("dataMount = %q, must not be the home directory itself (#974)", dataMount)
	}
	if !strings.HasPrefix(dataMount, "/home/agent/") {
		t.Fatalf("dataMount = %q, want a subdirectory of /home/agent", dataMount)
	}

	b, cs, sc := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "ivy"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = cs

	sb := getSandbox(t, sc, "tenant-ivy")
	container := sb.Spec.PodTemplate.Spec.Containers[0]

	var dataMountFound, homeMountFound, authKeysFound bool
	for _, m := range container.VolumeMounts {
		switch m.MountPath {
		case dataMount:
			dataMountFound = true
			if m.Name != dataVolume {
				t.Errorf("mount at %s uses volume %q, want %q", dataMount, m.Name, dataVolume)
			}
		case "/home/agent":
			homeMountFound = true
		case authorizedKeysMount:
			authKeysFound = true
			if !m.ReadOnly {
				t.Errorf("authorized_keys mount at %s is writable, want read-only", authorizedKeysMount)
			}
			if m.Name != authorizedKeysVolume {
				t.Errorf("authorized_keys mount uses volume %q, want %q", m.Name, authorizedKeysVolume)
			}
		}
	}
	if !dataMountFound {
		t.Errorf("no volume mount found at dataMount (%s)", dataMount)
	}
	if homeMountFound {
		t.Errorf("a volume is mounted directly at /home/agent — this overrides the image's home directory and breaks dropbear strict modes (#974)")
	}
	if !authKeysFound {
		t.Errorf("authorized_keys Secret mount at %s missing — unaffected by the data-PVC mount path change", authorizedKeysMount)
	}
}

// TestCreateNoPVCWhenStorageClassEmpty verifies backward compat: no PVC when
// StorageClass is unset, and the StatefulSet has no data volume mount.
func TestCreateNoPVCWhenStorageClassEmpty(t *testing.T) {
	b, cs, sc := testBackend() // no StorageClass
	_ = sc
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{Ref: box.BoxRef{Tenant: "grace"}, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ns := "tenant-grace"
	pvcs, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(pvcs.Items) != 0 {
		t.Errorf("expected no PVCs when StorageClass is empty, got %d", len(pvcs.Items))
	}
	sb := getSandbox(t, sc, ns)
	for _, m := range sb.Spec.PodTemplate.Spec.Containers[0].VolumeMounts {
		if m.MountPath == dataMount {
			t.Errorf("data volume mounted even without StorageClass")
		}
	}
}

// TestDeleteRetainsPVC verifies that Delete removes box compute objects but
// keeps the namespace and PVC when StorageClass is configured.
func TestDeleteRetainsPVC(t *testing.T) {
	b, cs, sc := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "henry"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Delete(ctx, ref, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	ns := "tenant-henry"
	// Namespace must survive (PVC lives in it).
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		t.Errorf("namespace removed by Delete: %v", err)
	}
	// PVC must survive.
	if _, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{}); err != nil {
		t.Errorf("PVC removed by Delete: %v", err)
	}
	// The Sandbox must be gone (its pod + Service go with it via owner refs).
	if _, err := sc.AgentsV1beta1().Sandboxes(ns).Get(ctx, sandboxName, metav1.GetOptions{}); err == nil {
		t.Error("Sandbox still present after Delete")
	}
}

// TestPurgeRemovesPVCAndNamespace verifies that Purge removes both the PVC and
// the namespace, and is a no-op on an absent box.
func TestPurgeRemovesPVCAndNamespace(t *testing.T) {
	b, cs, _ := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "iris"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Delete(ctx, ref, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Purge(ctx, ref); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	ns := "tenant-iris"
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
		t.Error("namespace still present after Purge")
	}
	// Purge of an absent box is a no-op.
	if err := b.Purge(ctx, box.BoxRef{Tenant: "nobody"}); err != nil {
		t.Errorf("Purge(missing) = %v, want nil", err)
	}
}

// TestCreatePerBoxStorageClassOverride verifies that a per-box
// spec.Resources.StorageClass takes precedence over the global Config.StorageClass.
func TestCreatePerBoxStorageClassOverride(t *testing.T) {
	b, cs, _ := testBackendWithStorage() // Config.StorageClass = "standard"
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "jane"}

	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:   ref,
		Image: "x",
		Resources: box.ResourceLimits{
			StorageClass: "fast-nvme", // per-box override
		},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ns := "tenant-jane"
	pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("PVC not created: %v", err)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "fast-nvme" {
		t.Errorf("StorageClassName = %v; want fast-nvme", pvc.Spec.StorageClassName)
	}
}

// TestCreatePerBoxStorageClassEmpty verifies that an empty per-box StorageClass
// falls back to the global Config.StorageClass.
func TestCreatePerBoxStorageClassEmpty(t *testing.T) {
	b, cs, _ := testBackendWithStorage() // Config.StorageClass = "standard"
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "ken"}

	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "x",
		Resources: box.ResourceLimits{}, // no per-box override
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ns := "tenant-ken"
	pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("PVC not created: %v", err)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "standard" {
		t.Errorf("StorageClassName = %v; want standard (global default)", pvc.Spec.StorageClassName)
	}
}
