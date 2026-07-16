package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
)

// BoxWriter upserts a Box CR from a runtime-neutral box.BoxSpec. It is the
// convergence primitive (#995, slice 4): when the operator is enabled, the
// imperative create path writes a Box CR through this instead of calling the
// backend directly, so the reconciler is the single builder for both the
// imperative and the declarative (kubectl apply / GitOps) paths.
type BoxWriter struct {
	client    ctrlclient.Client
	namespace string
}

// NewBoxWriter builds a BoxWriter with a direct (uncached) client. namespace is
// where Box CRs are created.
func NewBoxWriter(namespace string) (*BoxWriter, error) {
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	if err := containariumv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	cl, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	return &BoxWriter{client: cl, namespace: namespace}, nil
}

// Upsert creates or updates the tenant's Box CR to match spec.
func (w *BoxWriter) Upsert(ctx context.Context, spec box.BoxSpec) error {
	return upsertBox(ctx, w.client, w.namespace, spec)
}

// upsertBox is the testable core: a client + namespace + spec.
func upsertBox(ctx context.Context, cl ctrlclient.Client, namespace string, spec box.BoxSpec) error {
	desired := boxFromSpec(spec, namespace)
	var existing containariumv1alpha1.Box
	err := cl.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: desired.Name}, &existing)
	if apierrors.IsNotFound(err) {
		return cl.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	existing.Spec = desired.Spec
	return cl.Update(ctx, &existing)
}

// boxFromSpec maps a runtime-neutral box.BoxSpec onto a Box CR — the inverse of
// specFromBox in the reconciler.
func boxFromSpec(spec box.BoxSpec, namespace string) *containariumv1alpha1.Box {
	autoStart := spec.AutoStart
	return &containariumv1alpha1.Box{
		ObjectMeta: metav1.ObjectMeta{Name: spec.Ref.Tenant, Namespace: namespace},
		Spec: containariumv1alpha1.BoxSpec{
			Tenant:  spec.Ref.Tenant,
			Image:   spec.Image,
			Mode:    spec.Mode,
			SSHKeys: spec.SSHKeys,
			Resources: containariumv1alpha1.BoxResources{
				CPU:          spec.Resources.CPU,
				Memory:       spec.Resources.Memory,
				Disk:         spec.Resources.Disk,
				StorageClass: spec.Resources.StorageClass,
			},
			Stack:         spec.Stack,
			StackParams:   spec.StackParams,
			GitSource:     spec.GitSource,
			GitRef:        spec.GitRef,
			WorkspacePath: spec.WorkspacePath,
			Labels:        spec.Labels,
			AutoStart:     &autoStart,
		},
	}
}
