// Command attacknet is the typed host-side client for Attacknet resources.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/attacknetcli"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{})
	namespace, _, namespaceErr := clientConfig.Namespace()
	if namespaceErr != nil {
		namespace = "default"
	}
	var configOnce sync.Once
	var config *rest.Config
	var configErr error
	loadConfig := func() (*rest.Config, error) {
		configOnce.Do(func() {
			if namespaceErr != nil {
				configErr = fmt.Errorf("resolve Kubernetes namespace: %w", namespaceErr)
				return
			}
			config, configErr = clientConfig.ClientConfig()
			if configErr != nil {
				configErr = fmt.Errorf("load Kubernetes configuration: %w", configErr)
			}
		})
		return config, configErr
	}
	app := attacknetcli.NewLazyApp(func() (attacknetcli.Backend, error) {
		config, err := loadConfig()
		if err != nil {
			return nil, err
		}
		return attacknetcli.NewKubernetesBackend(config)
	}, namespace, os.Stdin, os.Stdout, os.Stderr)
	app.IncidentFactory = func() (attacknetcli.IncidentEvidenceReader, error) {
		config, err := loadConfig()
		if err != nil {
			return nil, err
		}
		return attacknetcli.NewClientGoIncidentReader(config)
	}
	app.LogExportFactory = func() (attacknetcli.RetainedLogExporter, error) {
		config, err := loadConfig()
		if err != nil {
			return nil, err
		}
		return attacknetcli.NewClientGoLokiExporter(config)
	}
	app.FuzzRuntimeFactory = func(corpusRoot, runtimeNamespace string) (fuzzsession.Runtime, error) {
		config, err := loadConfig()
		if err != nil {
			return nil, err
		}
		backend, err := attacknetcli.NewKubernetesBackend(config)
		if err != nil {
			return nil, err
		}
		incident, err := attacknetcli.NewClientGoIncidentReader(config)
		if err != nil {
			return nil, err
		}
		logs, err := attacknetcli.NewClientGoLokiExporter(config)
		if err != nil {
			return nil, err
		}
		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, err
		}
		escrowImage := os.Getenv("ATTACKNET_CAPACITY_ESCROW_IMAGE")
		if escrowImage == "" {
			escrowImage = "stacks-hacknet-io-pressure:dev"
		}
		infrastructure, err := attacknetcli.NewKubernetesFuzzInfrastructure(
			client, runtimeNamespace, corpusRoot, escrowImage, corev1.PullIfNotPresent, time.Now,
		)
		if err != nil {
			return nil, err
		}
		rendererPath := os.Getenv("ATTACKNET_OBSERVABILITY_RENDERER")
		if rendererPath == "" {
			rendererPath = "contrib/attacknet/observability/render.mjs"
		}
		runOperatorTarget := os.Getenv("ATTACKNET_RUN_OPERATOR_TARGET")
		if runOperatorTarget == "" {
			runOperatorTarget = "hacknet-run:8080"
		}
		renderer, err := attacknetcli.NewJSEvidenceRenderer(rendererPath, runOperatorTarget)
		if err != nil {
			return nil, err
		}
		evidencePlane, err := attacknetcli.NewKubernetesFuzzEvidencePlane(config, renderer)
		if err != nil {
			return nil, err
		}
		return &attacknetcli.KubernetesFuzzRuntime{
			Backend: backend, Infrastructure: infrastructure,
			EvidencePlane: evidencePlane, Incident: incident, Logs: logs,
			CorpusRoot: corpusRoot, Now: time.Now,
		}, nil
	}
	app.CommandRunner = attacknetcli.ExecCommandRunner{}
	app.PortForwards = attacknetcli.NewOSPortForwardManager("kubectl", attacknetcli.DefaultPortForwardStateDir())
	os.Exit(app.Run(ctx, os.Args[1:]))
}
