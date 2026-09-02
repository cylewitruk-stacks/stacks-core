// Command topology-operator reconciles StacksNetwork workloads.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchainpolicy"
	manageroptions "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/manager"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/upgrade"
)

func main() {
	configureLogging := manageroptions.BindLogging(flag.CommandLine)
	options := manageroptions.Options{}
	options.Bind(flag.CommandLine)
	clockImage := flag.String("burnchain-clock-image", "", "immutable or locally loaded burnchain-clock image reference")
	clockImagePull := flag.String("burnchain-clock-image-pull-policy", string(corev1.PullIfNotPresent), "burnchain-clock image pull policy")
	probeImage := flag.String("probe-image", "stacks-hacknet-probe:dev", "default credential-free actor probe image reference")
	probeImagePull := flag.String("probe-image-pull-policy", string(corev1.PullIfNotPresent), "probe image pull policy")
	flag.Parse()
	configureLogging()
	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme))
	must(appsv1.AddToScheme(scheme))
	must(corev1.AddToScheme(scheme))
	must(attacknetv1alpha1.AddToScheme(scheme))
	must(attacknetv1beta1.AddToScheme(scheme))
	mgr, err := options.New(scheme, "topology-operator.testing.stacks.org")
	must(err)
	probePullPolicy, err := imagePullPolicy(*probeImagePull)
	must(err)
	reconciler := &topology.V1Beta1Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		ProbeImage: *probeImage, ProbeImagePull: probePullPolicy,
	}
	must(reconciler.SetupWithManager(mgr, options.Concurrency))
	upgradeReconciler := &upgrade.Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		Observations: &protocolobservation.Reader{APIReader: mgr.GetAPIReader()},
	}
	must(upgradeReconciler.SetupWithManager(mgr, options.Concurrency))
	pullPolicy, err := imagePullPolicy(*clockImagePull)
	must(err)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	clockReconciler := &burnchainpolicy.Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		ClockImage: *clockImage, ClockImagePull: pullPolicy,
		StatusReader: burnchainpolicy.HTTPStatusReader{Client: &http.Client{
			Transport: transport, Timeout: 3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}},
	}
	must(clockReconciler.SetupWithManager(mgr, options.Concurrency))
	must(mgr.Start(ctrl.SetupSignalHandler()))
}

func imagePullPolicy(value string) (corev1.PullPolicy, error) {
	switch corev1.PullPolicy(value) {
	case corev1.PullAlways, corev1.PullIfNotPresent, corev1.PullNever:
		return corev1.PullPolicy(value), nil
	default:
		return "", fmt.Errorf("invalid burnchain clock image pull policy %q", value)
	}
}

func must(err error) {
	if err != nil {
		ctrl.Log.Error(err, "fatal error")
		os.Exit(1)
	}
}
