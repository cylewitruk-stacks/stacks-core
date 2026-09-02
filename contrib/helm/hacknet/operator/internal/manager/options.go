// Package manager owns common controller-runtime manager configuration.
package manager

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// Options contains the shared command-line settings for one controller manager.
type Options struct {
	MetricsAddress string
	ProbeAddress   string
	Namespace      string
	Concurrency    int
}

// Bind registers controller manager flags.
func (o *Options) Bind(flags *flag.FlagSet) {
	flags.StringVar(&o.MetricsAddress, "metrics-bind-address", ":8080", "Address for Prometheus controller metrics.")
	flags.StringVar(&o.ProbeAddress, "health-probe-bind-address", ":8081", "Address for health and readiness probes.")
	flags.StringVar(&o.Namespace, "watch-namespace", os.Getenv("WATCH_NAMESPACE"), "Namespace to watch; defaults to the ServiceAccount namespace.")
	flags.IntVar(&o.Concurrency, "max-concurrent-reconciles", 1, "Maximum concurrent reconciles per controller.")
}

// New constructs a namespaced controller-runtime manager with native probes and metrics.
func (o Options) New(scheme *runtime.Scheme, leaderElectionID string) (ctrl.Manager, error) {
	if o.Concurrency < 1 {
		return nil, fmt.Errorf("max-concurrent-reconciles must be positive")
	}
	namespace := o.Namespace
	if namespace == "" {
		data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, fmt.Errorf("determine watch namespace: %w", err)
		}
		namespace = strings.TrimSpace(string(data))
	}
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes REST configuration: %w", err)
	}
	options := ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: o.MetricsAddress}, HealthProbeBindAddress: o.ProbeAddress, LeaderElection: false, LeaderElectionID: leaderElectionID, Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}}}
	mgr, err := ctrl.NewManager(config, options)
	if err != nil {
		return nil, fmt.Errorf("create controller manager: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("register liveness check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", apiReadyChecker(mgr, namespace)); err != nil {
		return nil, fmt.Errorf("register readiness check: %w", err)
	}
	return mgr, nil
}

func apiReadyChecker(mgr ctrl.Manager, namespace string) healthz.Checker {
	return func(request *http.Request) error {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		return mgr.GetAPIReader().List(ctx, &corev1.ConfigMapList{}, client.InNamespace(namespace), client.Limit(1))
	}
}

// BindLogging registers controller-runtime's structured logging flags and
// returns the post-parse logger installer.
func BindLogging(flags *flag.FlagSet) func() {
	options := zap.Options{Development: false, TimeEncoder: zapcore.ISO8601TimeEncoder}
	options.BindFlags(flags)
	return func() {
		ctrl.SetLogger(zap.New(zap.UseFlagOptions(&options)))
	}
}
