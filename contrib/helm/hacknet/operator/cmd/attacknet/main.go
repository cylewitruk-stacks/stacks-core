// Command attacknet is the typed host-side client for Attacknet resources.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/attacknetcli"
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
	app.CommandRunner = attacknetcli.ExecCommandRunner{}
	app.PortForwards = attacknetcli.NewOSPortForwardManager("kubectl", attacknetcli.DefaultPortForwardStateDir())
	os.Exit(app.Run(ctx, os.Args[1:]))
}
