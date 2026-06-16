//go:build k8s

package k8s

import (
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
	sshPort         = 22

	managedByLabel       = "app.kubernetes.io/managed-by"
	managedByValue       = "containarium"
	tenantLabel          = "containarium.dev/tenant"
	metaAnnotationPrefix = "containarium.dev/meta."

	authorizedKeysKey = "authorized_keys"
)

func int32p(i int32) *int32 { return &i }

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
// asks to auto-start, else 0 (created stopped).
func statefulSetObject(ns string, spec box.BoxSpec) *appsv1.StatefulSet {
	replicas := int32(0)
	if spec.AutoStart {
		replicas = 1
	}
	labels := boxLabels(spec.Ref.Tenant)
	falsePtr := false

	container := corev1.Container{
		Name:  "agent-box",
		Image: spec.Image,
		Ports: []corev1.ContainerPort{{Name: sshPortName, ContainerPort: sshPort, Protocol: corev1.ProtocolTCP}},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: &falsePtr,
		},
	}
	if res := resourceRequirements(spec.Resources); res != nil {
		container.Resources = *res
	}

	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: statefulSetName, Namespace: ns, Labels: labels},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    int32p(replicas),
			ServiceName: serviceName,
			Selector:    &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &falsePtr, // the box is a leaf, never a kube-apiserver client
					Containers:                   []corev1.Container{container},
				},
			},
		},
	}
}

// resourceRequirements maps the runtime-neutral limits onto K8s requests/limits,
// skipping any field that isn't a valid K8s quantity (the incus-native strings
// like "4GB" aren't K8s quantities; "4Gi"/"2"/"500m" are). Returns nil when
// nothing parsed, so the pod runs unconstrained rather than failing admission.
func resourceRequirements(r box.ResourceLimits) *corev1.ResourceRequirements {
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
	if len(limits) == 0 {
		return nil
	}
	return &corev1.ResourceRequirements{Limits: limits, Requests: limits}
}
