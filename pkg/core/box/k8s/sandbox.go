package k8s

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"

	"github.com/footprintai/containarium/pkg/core/box"
)

// sandboxObject builds the agent-sandbox Sandbox CR for a tenant box. The
// agent-sandbox controller owns the children: it creates the pod (named after
// the Sandbox) and, because spec.service is true, a headless Service (also
// named after the Sandbox) that gives the pod stable in-cluster DNS — the name
// the gateway Pipe routes to.
//
// AutoStart maps onto spec.operatingMode: Running creates the pod immediately,
// Suspended parks the Sandbox with no pod (the CR-native form of the old
// replicas=0). withPVC mounts the daemon-owned data PVC at dataMount
// (/home/agent) as a plain persistentVolumeClaim volume — deliberately not a
// volumeClaimTemplate, which the controller would owner-reference and GC on
// Sandbox deletion, breaking delete-retains-data. def is the resolved default
// memory floor applied when the spec sets no explicit memory.
func sandboxObject(ns string, spec box.BoxSpec, withPVC bool, def memDefaults) *sandboxv1beta1.Sandbox {
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
	if res := resourceRequirements(spec.Resources, gpuCount, def); res != nil {
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

	// Pod labels propagate from the template (the controller merges them onto
	// the pod), keeping the NetworkPolicy pod selector matching.
	podMeta := sandboxv1beta1.PodMetadata{Labels: labels}
	if gpuCount > 0 {
		podMeta.Annotations = map[string]string{
			gpuCountAnnotation: fmt.Sprintf("%d", gpuCount),
		}
	}

	mode := sandboxv1beta1.SandboxOperatingModeSuspended
	if spec.AutoStart {
		mode = sandboxv1beta1.SandboxOperatingModeRunning
	}

	return &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{Name: sandboxName, Namespace: ns, Labels: labels},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
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
				Service: boolp(true), // headless Service = the gateway's routing target
			},
			OperatingMode: mode,
		},
	}
}
