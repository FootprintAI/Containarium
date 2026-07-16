package k8s

import (
	"fmt"
	"log"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/footprintai/containarium/pkg/core/box"
)

// Object naming + labels. One box per tenant namespace: the agent-sandbox
// Sandbox CR is always "box"; its controller creates the pod (also "box") and
// a headless Service (also "box") that gives the pod stable in-cluster DNS.
const (
	sandboxName = "box"
	sshPortName = "ssh"

	// pvcName is the PersistentVolumeClaim name inside the tenant namespace.
	// It holds the box's persistent data, mounted at dataMount below. Owned by
	// the daemon, NOT declared via the Sandbox's volumeClaimTemplates:
	// template-derived PVCs are owner-referenced to the Sandbox and
	// garbage-collected with it, which would break delete-retains-data.
	// Created before the Sandbox, mounted as a plain persistentVolumeClaim
	// volume, retained on Delete; removed only by Purge.
	pvcName    = "data"
	dataVolume = "data"
	// dataMount is a subdirectory of the home directory, NOT the home
	// directory itself (#974). Mounting the PVC directly at /home/agent
	// replaces the image's real home with the provisioner's fresh volume
	// root — typically 0777 root:root (kind/local-path) or 0755 root:root
	// (a typical CSI ext4 root) — either of which either fails dropbear's
	// strict-modes home-directory check (group/world-writable) or leaves
	// uid-1000 `agent` unable to write its own home at all. Mounting one
	// level down keeps /home/agent itself exactly as the image built it
	// (owned by `agent`, dropbear-compatible perms, authorized_keys layered
	// in via a separate Secret mount) while still giving the box a
	// persistent, per-tenant working directory. Trade-off: only this
	// subdirectory survives box recreation now, not the whole home — see
	// the CSI persistent storage section in
	// docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
	dataMount   = "/home/agent/workspace"
	defaultDisk = "10Gi"

	// Default per-box memory bounds, applied when a box's spec carries no valid
	// memory quantity. The request (what the scheduler reserves) is deliberately
	// kept below the limit (the hard cap) so a mostly-idle box packs densely on
	// the shared host kernel — preserving the memory density LXC gave us — while
	// the limit still stops any single box from ballooning and pressuring its
	// neighbors (noisy-neighbor). GPU boxes are exempt: they're sized explicitly
	// and a small cap would OOM the workload. Override per box via
	// Resources.Memory (CLI --memory / Resize); a future Config knob can retune
	// the cluster-wide floor. CPU is intentionally left undefaulted — it's
	// compressible (a limit throttles rather than kills), so an implicit CPU cap
	// would surprise more than it protects.
	defaultMemoryRequest = "256Mi"
	defaultMemoryLimit   = "1Gi"
	// sshPort is the box's in-pod SSH port. 2222 (unprivileged) so the box
	// runs fully non-root with no added capabilities — the agent connects to
	// the gateway on :22; this is the internal sshpiper→pod hop.
	sshPort = 2222
	// boxSSHUser is the fixed login user inside the box. The gateway connects
	// upstream as this user (Pipe spec.to.username); tenant identity is
	// enforced at the gateway, not by per-tenant box users.
	boxSSHUser = "agent"

	managedByLabel       = "app.kubernetes.io/managed-by"
	managedByValue       = "containarium"
	tenantLabel          = "containarium.dev/tenant"
	metaAnnotationPrefix = "containarium.dev/meta."
	gpuCountAnnotation   = "containarium.dev/gpu-count"

	// nvidiaGPUResource is the K8s extended-resource name for NVIDIA GPUs.
	// A non-zero limit causes the cluster autoscaler to scale up a GPU node pool.
	nvidiaGPUResource = corev1.ResourceName("nvidia.com/gpu")

	authorizedKeysKey = "authorized_keys"
	// authorizedKeysMount is where the box image (dropbear entrypoint) reads
	// authorized_keys; the box's Secret is mounted here.
	authorizedKeysMount  = "/etc/agent-box"
	authorizedKeysVolume = "authorized-keys"

	// Per-box stable host key (so the gateway can pin it). The entrypoint reads
	// the private key here; the daemon stores it (+ the public half) in the
	// host-key Secret.
	hostKeyField       = "host_key"     // ed25519 private (OpenSSH PEM)
	hostKeyPubField    = "host_key.pub" // ed25519 public (authorized-key)
	hostKeyRSAField    = "host_key_rsa" // RSA private — dropbear needs an RSA host key (rsa-sha2)
	hostKeyRSAPubField = "host_key_rsa.pub"
	hostKeyMount       = "/etc/agent-box-hostkey"
	hostKeyVolume      = "host-key"
)

func hostKeySecretName(tenant string) string { return tenant + "-host-key" }

// pvcObject builds the PersistentVolumeClaim for the box's data volume.
// storageClass "" disables PVC provisioning (caller must not call this).
// disk is the requested size (e.g. "20Gi"); defaults to defaultDisk when empty
// or unparseable (see parseDiskQuantity).
func pvcObject(ns, tenant, storageClass, disk string) *corev1.PersistentVolumeClaim {
	quantity := parseDiskQuantity(disk)
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: ns,
			Labels:    boxLabels(tenant),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: quantity,
				},
			},
		},
	}
	// A non-empty StorageClass is set explicitly. Empty string is not stored
	// (nil pointer) so the cluster's default StorageClass takes over — but in
	// practice callers with StorageClass=="" skip PVC creation entirely (see
	// Config.StorageClass semantics), so this branch is defensive-only.
	pvc.Spec.StorageClassName = &storageClass
	return pvc
}

// parseDiskQuantity resolves a caller-supplied disk size into a valid K8s
// resource.Quantity, never panicking regardless of what the caller sent
// (#973: an incus-style "50GB" — the CLI's own default — reached
// resource.MustParse and killed the daemon; this is the CreateContainer
// request path, so a bad string is remote-triggerable by any authenticated
// caller). Empty defaults to defaultDisk. A valid K8s quantity ("20Gi")
// passes straight through. An incus-style quantity (two-letter GB/MB/KB/...
// suffix, decimal scale) is normalized to the K8s single-letter equivalent
// (same decimal scale, so this is a straight rewrite, not a unit
// conversion) and reparsed. Anything else — including total garbage —
// degrades to defaultDisk with a log line, mirroring resourceRequirements'
// lenient handling of invalid CPU/Memory strings elsewhere in this file.
func parseDiskQuantity(disk string) resource.Quantity {
	if disk == "" {
		disk = defaultDisk
	}
	if q, err := resource.ParseQuantity(disk); err == nil {
		return q
	}
	if normalized, ok := normalizeIncusDiskSuffix(disk); ok {
		if q, err := resource.ParseQuantity(normalized); err == nil {
			return q
		}
	}
	log.Printf("[k8s] invalid disk quantity %q; falling back to default %q", disk, defaultDisk)
	// defaultDisk is a package constant known to be a valid quantity, so
	// MustParse here can't panic on caller input.
	return resource.MustParse(defaultDisk)
}

// normalizeIncusDiskSuffix rewrites an incus-style two-letter decimal size
// suffix (KB/MB/GB/TB/PB/EB) into the single-letter K8s equivalent
// (K/M/G/T/P/E). Incus's GB etc. are decimal (10^3-scaled), matching K8s's
// unsuffixed-i letters exactly, so no scale conversion is needed — just the
// suffix rewrite. Returns ok=false when disk doesn't end in one of these
// suffixes (e.g. it's already a K8s quantity, or garbage).
func normalizeIncusDiskSuffix(disk string) (normalized string, ok bool) {
	for _, suf := range []string{"KB", "MB", "GB", "TB", "PB", "EB"} {
		if strings.HasSuffix(disk, suf) {
			return strings.TrimSuffix(disk, suf) + suf[:1], true
		}
	}
	return "", false
}

func int64p(i int64) *int64 { return &i }
func boolp(b bool) *bool    { return &b }

// boxLabels are the identity labels shared by all of a tenant box's objects;
// the pod selector and the cross-namespace List selector both key off them.
func boxLabels(tenant string) map[string]string {
	return map[string]string{
		managedByLabel: managedByValue,
		tenantLabel:    tenant,
	}
}

func secretName(tenant string) string { return tenant + "-authorized-keys" }

// namespaceObject builds the per-tenant namespace.
func namespaceObject(name, tenant string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: boxLabels(tenant)},
	}
}

// secretObject holds the box's authorized_keys (what dropbear reads — the
// gateway upstream key in gateway mode) plus the client_keys record (the
// agent's own keys, served to the sentinel via /authorized-keys).
func secretObject(ns, tenant string, boxKeys, clientKeys []string) *corev1.Secret {
	join := func(keys []string) []byte {
		var buf []byte
		for _, k := range keys {
			buf = append(buf, []byte(k)...)
			buf = append(buf, '\n')
		}
		return buf
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName(tenant), Namespace: ns, Labels: boxLabels(tenant)},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			authorizedKeysKey: join(boxKeys),
			clientKeysKey:     join(clientKeys),
		},
	}
}

// networkPolicyObject is the default-deny posture: deny all ingress/egress
// except SSH ingress on :22 and DNS egress. (Gateway-only ingress narrowing and
// the egress allowlist land with the gateway wiring; this is the v1 floor.)
func networkPolicyObject(ns, tenant string) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	dnsPort := intstr.FromInt(53)
	ssh := intstr.FromInt(sshPort)
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: ns, Labels: boxLabels(tenant)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: boxLabels(tenant)},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &ssh}},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				Ports: []networkingv1.NetworkPolicyPort{
					{Protocol: &udp, Port: &dnsPort},
					{Protocol: &tcp, Port: &dnsPort},
				},
			}},
		},
	}
}

// memDefaults is the resolved cluster-wide default memory floor (from Config),
// threaded into the object builders. An empty limit disables the floor — boxes
// with no explicit memory then run unconstrained.
type memDefaults struct {
	request string
	limit   string
}

// resourceRequirements maps the runtime-neutral limits onto K8s requests/limits.
// CPU and Memory strings that aren't valid K8s quantities (e.g. incus-native
// "4GB") are silently skipped so the pod doesn't fail admission. Explicit CPU
// and Memory pin request==limit (Guaranteed for that resource).
//
// When the spec sets no valid memory limit, the resolved default memory floor
// (def.request < def.limit) is applied so the scheduler can bin-pack the box
// and no single box can balloon and pressure its neighbors on the shared host
// kernel. GPU boxes are exempt — sized explicitly, a small cap would OOM them.
// An empty def.limit disables the floor (box runs unconstrained). gpuCount > 0
// adds nvidia.com/gpu (request==limit, as the device plugin requires); the
// cluster autoscaler uses it to scale up a GPU node pool. Returns nil only when
// nothing at all is set.
//
// def.request / def.limit are pre-validated quantities (resolved in newBackend),
// so the floor block parses them with MustParse; if the operator's request
// exceeds the limit it is clamped to the limit (a request may not exceed a
// limit, which would otherwise fail admission).
func resourceRequirements(r box.ResourceLimits, gpuCount int, def memDefaults) *corev1.ResourceRequirements {
	requests := corev1.ResourceList{}
	limits := corev1.ResourceList{}
	if r.CPU != "" {
		if q, err := resource.ParseQuantity(r.CPU); err == nil {
			requests[corev1.ResourceCPU] = q
			limits[corev1.ResourceCPU] = q
		}
	}
	if r.Memory != "" {
		if q, err := resource.ParseQuantity(r.Memory); err == nil {
			requests[corev1.ResourceMemory] = q
			limits[corev1.ResourceMemory] = q
		}
	}
	// Apply the default memory floor when the spec set no valid memory limit.
	// Skip it for GPU boxes (sized explicitly) and when the floor is disabled.
	if _, ok := limits[corev1.ResourceMemory]; !ok && gpuCount == 0 && def.limit != "" {
		limQ := resource.MustParse(def.limit)
		reqQ := resource.MustParse(def.request)
		if reqQ.Cmp(limQ) > 0 {
			reqQ = limQ
		}
		requests[corev1.ResourceMemory] = reqQ
		limits[corev1.ResourceMemory] = limQ
	}
	if gpuCount > 0 {
		q := resource.MustParse(fmt.Sprintf("%d", gpuCount))
		requests[nvidiaGPUResource] = q
		limits[nvidiaGPUResource] = q
	}
	if len(limits) == 0 && len(requests) == 0 {
		return nil
	}
	return &corev1.ResourceRequirements{Limits: limits, Requests: requests}
}
