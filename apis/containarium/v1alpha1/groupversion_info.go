// Package v1alpha1 contains the API types for the containarium.dev group — the
// Box CRD the daemon reconciles into a per-tenant agent-box (Sandbox + Pipe +
// Secret + NetworkPolicy). See issue #995 for the operator design.
//
// +kubebuilder:object:generate=true
// +groupName=containarium.dev
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the group/version for the containarium.dev API.
var GroupVersion = schema.GroupVersion{Group: "containarium.dev", Version: "v1alpha1"}

// SchemeBuilder collects the containarium.dev types for registration with a
// runtime.Scheme. Kept to apimachinery-only deps (no controller-runtime) so
// the API package stays cheap to import.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds the containarium.dev types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &Box{}, &BoxList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
