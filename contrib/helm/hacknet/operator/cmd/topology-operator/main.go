// Command topology-operator reconciles StacksNetwork workloads.
package main

import (
	"flag"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	manageroptions "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/manager"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
)

func main() {
	configureLogging := manageroptions.BindLogging(flag.CommandLine)
	options := manageroptions.Options{}
	options.Bind(flag.CommandLine)
	flag.Parse()
	configureLogging()
	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme))
	must(appsv1.AddToScheme(scheme))
	must(corev1.AddToScheme(scheme))
	must(attacknetv1alpha1.AddToScheme(scheme))
	mgr, err := options.New(scheme, "topology-operator.testing.stacks.org")
	must(err)
	reconciler := &topology.Reconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}
	must(reconciler.SetupWithManager(mgr, options.Concurrency))
	must(mgr.Start(ctrl.SetupSignalHandler()))
}

func must(err error) {
	if err != nil {
		ctrl.Log.Error(err, "fatal error")
		os.Exit(1)
	}
}
