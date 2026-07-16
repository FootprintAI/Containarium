package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
)

// StartOperator builds a controller-runtime manager, registers the Box
// reconciler over the given backend, and runs it until ctx is cancelled.
//
// It blocks — call it in a goroutine. The REST config is resolved the standard
// controller-runtime way (in-cluster first, then KUBECONFIG / ~/.kube/config).
// The manager's own metrics listener is disabled (BindAddress "0") so it does
// not contend for a port with the daemon's API/metrics.
func StartOperator(ctx context.Context, backend box.BoxBackend) error {
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := containariumv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return err
	}
	if err := (&BoxReconciler{Client: mgr.GetClient(), Backend: backend}).SetupWithManager(mgr); err != nil {
		return err
	}
	return mgr.Start(ctx)
}
