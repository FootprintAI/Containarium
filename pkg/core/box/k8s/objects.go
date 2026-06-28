package k8s

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/footprintai/containarium/pkg/core/box"
)

// Object naming + labels. One box per tenant namespace: the StatefulSet is
// always "box" (pod "box-0"), fronted by the headless Service "boxes".
const (
	statefulSetName = "box"
	serviceName     = "boxes"
	sshPortName     = "ssh"

	// pvcName is the PersistentVolumeClaim name inside the tenant namespace.
	// It holds the box's persistent data (home directory). Created before the
	// StatefulSet and retained on Delete; removed only by Purge.
	pvcName     = "data"
	dataMount   = "/home/agent"
	dataVolume  = "data"
	defaultDisk = "10Gi"
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
// disk is the requested size (e.g. "20Gi"); defaults to defaultDisk when empty.
func pvcObject(ns, tenant, storageClass, disk string) *corev1.PersistentVolumeClaim {
	if disk == "" {
		disk = defaultDisk
	}
	quantity := resource.MustParse(disk)
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

func int32p(i int32) *int32 { return &i }
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

// secretObject holds the box's authorized_keys.
func secretObject(ns, tenant string, keys []string) *corev1.Secret {
	var buf []byte
	for _, k := range keys {
		buf = append(buf, []byte(k)...)
		buf = append(buf, '\n')
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName(tenant), Namespace: ns, Labels: boxLabels(tenant)},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{authorizedKeysKey: buf},
	}
}

// serviceObject is the headless Service that gives the pod a stable DNS name
// (box-0.boxes.<ns>.svc) the gateway routes to.
func serviceObject(ns, tenant string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns, Labels: boxLabels(tenant)},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone, // headless
			Selector:  boxLabels(tenant),
			Ports: []corev1.ServicePort{{
				Name:       sshPortName,
				Port:       sshPort,
				TargetPort: intstr.FromInt(sshPort),
				Protocol:   corev1.ProtocolTCP,
			}},
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

// statefulSetObject builds the per-tenant box. replicas is 1 when the spec
// asks to auto-start, else 0 (created stopped). withPVC mounts the data PVC
// at dataMount (/home/agent) when true; the PVC must already exist.
func statefulSetObject(ns string, spec box.BoxSpec, withPVC bool) *appsv1.StatefulSet {
	replicas := int32(0)
	if spec.AutoStart {
		replicas = 1
	}
	labels := boxLabels(spec.Ref.Tenant)

	// restricted-PSA container hardening: non-root, no privilege escalation,
	// all capabilities dropped, default seccomp. The box image (dropbear on
	// :2222) is built to run under exactly this.
	gpuCount := len(spec.GPUs)
	container := corev1.Container{
		Name:  "agent-box",
		Image: spec.Image,
		Ports: []corev1.ContainerPort{{Name: sshPortName, ContainerPort: sshPort, Protocol: corev1.ProtocolTCP}},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolp(false),
			RunAsNonRoot:             boolp(true),
			RunAsUser:                int64p(1000),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		// Mount the box's authorized_keys (so it accepts logins) and its stable
		// host key (so the gateway can pin it). Without the first the box
		// rejects every login.
		VolumeMounts: []corev1.VolumeMount{
			{Name: authorizedKeysVolume, MountPath: authorizedKeysMount, ReadOnly: true},
			{Name: hostKeyVolume, MountPath: hostKeyMount, ReadOnly: true},
		},
	}
	if res := resourceRequirements(spec.Resources, gpuCount); res != nil {
		container.Resources = *res
	}

	volumes := []corev1.Volume{
		{
			Name: authorizedKeysVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: secretName(spec.Ref.Tenant)},
			},
		},
		{
			Name: hostKeyVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: hostKeySecretName(spec.Ref.Tenant)},
			},
		},
	}
	if withPVC {
		volumes = append(volumes, corev1.Volume{
			Name: dataVolume,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: pvcName,
				},
			},
		})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      dataVolume,
			MountPath: dataMount,
		})
	}

	podMeta := metav1.ObjectMeta{Labels: labels}
	if gpuCount > 0 {
		podMeta.Annotations = map[string]string{
			gpuCountAnnotation: fmt.Sprintf("%d", gpuCount),
		}
	}

	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: statefulSetName, Namespace: ns, Labels: labels},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    int32p(replicas),
			ServiceName: serviceName,
			Selector:    &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: podMeta,
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: boolp(false), // the box is a leaf, never a kube-apiserver client
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   boolp(true),
						RunAsUser:      int64p(1000),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{container},
					Volumes:    volumes,
				},
			},
		},
	}
}

// resourceRequirements maps the runtime-neutral limits onto K8s requests/limits.
// CPU and Memory strings that aren't valid K8s quantities (e.g. incus-native
// "4GB") are silently skipped so the pod runs unconstrained rather than failing
// admission. gpuCount > 0 adds nvidia.com/gpu; the cluster autoscaler uses this
// to scale up a GPU node pool when no schedulable node exists.
// Returns nil when nothing parsed.
func resourceRequirements(r box.ResourceLimits, gpuCount int) *corev1.ResourceRequirements {
	limits := corev1.ResourceList{}
	if r.CPU != "" {
		if q, err := resource.ParseQuantity(r.CPU); err == nil {
			limits[corev1.ResourceCPU] = q
		}
	}
	if r.Memory != "" {
		if q, err := resource.ParseQuantity(r.Memory); err == nil {
			limits[corev1.ResourceMemory] = q
		}
	}
	if gpuCount > 0 {
		q := resource.MustParse(fmt.Sprintf("%d", gpuCount))
		limits[nvidiaGPUResource] = q
	}
	if len(limits) == 0 {
		return nil
	}
	return &corev1.ResourceRequirements{Limits: limits, Requests: limits}
}
