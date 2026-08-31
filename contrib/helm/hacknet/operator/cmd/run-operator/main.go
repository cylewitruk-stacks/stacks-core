// Command run-operator reconciles FaultCampaign and AttacknetRun resources.
package main

import (
	"flag"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	controllermetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchainworker"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	manageroptions "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/manager"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/orchestratormetrics"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
	runcontroller "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/run"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "burnchain-reorg-worker" {
		os.Exit(burnchainworker.Main())
	}
	configureLogging := manageroptions.BindLogging(flag.CommandLine)
	options := manageroptions.Options{}
	options.Bind(flag.CommandLine)
	ioPressureImage := flag.String("io-pressure-image", os.Getenv("IO_PRESSURE_IMAGE"), "Trusted I/O-pressure helper image.")
	ioPressurePull := flag.String("io-pressure-image-pull-policy", defaultString(os.Getenv("IO_PRESSURE_IMAGE_PULL_POLICY"), "IfNotPresent"), "I/O-pressure helper image pull policy.")
	ioArchitectures := flag.String("iochaos-supported-architectures", defaultString(os.Getenv("IOCHAOS_SUPPORTED_ARCHITECTURES"), "x64"), "Comma-separated probe architectures admitted for IOChaos.")
	timeArchitectures := flag.String("timechaos-supported-architectures", defaultString(os.Getenv("TIMECHAOS_SUPPORTED_ARCHITECTURES"), "x64"), "Comma-separated probe architectures admitted for TimeChaos.")
	reorgWorkerImage := flag.String("burnchain-reorg-worker-image", os.Getenv("BURNCHAIN_REORG_WORKER_IMAGE"), "Trusted image containing the bounded burnchain reorg worker.")
	reorgWorkerPull := flag.String("burnchain-reorg-worker-pull-policy", defaultString(os.Getenv("BURNCHAIN_REORG_WORKER_PULL_POLICY"), "IfNotPresent"), "Burnchain reorg worker image pull policy.")
	flag.Parse()
	configureLogging()
	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme))
	must(corev1.AddToScheme(scheme))
	must(attacknetv1beta1.AddToScheme(scheme))
	mgr, err := options.New(scheme, "run-operator.testing.stacks.org")
	must(err)
	compilationCache, err := fault.NewCompilationCache(128)
	must(err)
	protocolReader := &protocolobservation.Reader{APIReader: mgr.GetAPIReader()}
	signerSets := &signerset.HTTPResolver{}
	faults := &fault.V1Beta1Reconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
		Observations: &fault.KubernetesTriggerObservationReader{
			Reader: mgr.GetAPIReader(), Protocol: protocolReader,
		},
		IOPressureImage:        *ioPressureImage,
		IOPressurePull:         corev1.PullPolicy(*ioPressurePull),
		IOChaosArchitectures:   stringSet(*ioArchitectures),
		TimeChaosArchitectures: stringSet(*timeArchitectures),
		CompilationCache:       compilationCache,
		ReorgWorkerImage:       *reorgWorkerImage,
		ReorgWorkerPull:        corev1.PullPolicy(*reorgWorkerPull),
		SignerSets:             signerSets,
	}
	runs := &runcontroller.V1Beta1Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		Observations: &runcontroller.KubernetesObservationReader{
			Reader: mgr.GetAPIReader(), Protocol: protocolReader,
		},
		SignerSets: signerSets,
	}
	controllermetrics.Registry.MustRegister(orchestratormetrics.NewCollector(mgr.GetClient()))
	must(faults.SetupWithManager(mgr, options.Concurrency))
	must(runs.SetupWithManager(mgr, options.Concurrency))
	must(mgr.Start(ctrl.SetupSignalHandler()))
}

func must(err error) {
	if err != nil {
		ctrl.Log.Error(err, "fatal error")
		os.Exit(1)
	}
}
func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func stringSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result[trimmed] = true
		}
	}
	return result
}
