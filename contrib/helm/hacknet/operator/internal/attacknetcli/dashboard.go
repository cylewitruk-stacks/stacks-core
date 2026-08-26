package attacknetcli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
)

// DashboardTarget names one supported local dashboard endpoint.
type DashboardTarget string

const (
	DashboardGrafana DashboardTarget = "grafana"
	DashboardChaos   DashboardTarget = "chaos"
)

var serviceResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}

// DashboardEndpoint is one uniquely discovered Kubernetes Service endpoint.
type DashboardEndpoint struct {
	Target     DashboardTarget `json:"target"`
	Namespace  string          `json:"namespace"`
	Service    string          `json:"service"`
	RemotePort int             `json:"remotePort"`
}

// DashboardDiscovery resolves a dashboard to exactly one Kubernetes Service.
type DashboardDiscovery interface {
	DiscoverDashboard(context.Context, DashboardTarget, string) (DashboardEndpoint, error)
}

// PortForwardRequest describes one loopback-only local process.
type PortForwardRequest struct {
	Endpoint       DashboardEndpoint
	LocalPort      int
	StartupTimeout time.Duration
}

// PortForwardStatus is the stable machine output for dashboard commands.
type PortForwardStatus struct {
	SchemaVersion string          `json:"schemaVersion"`
	Target        DashboardTarget `json:"target"`
	Namespace     string          `json:"namespace,omitempty"`
	Service       string          `json:"service,omitempty"`
	LocalAddress  string          `json:"localAddress"`
	LocalPort     int             `json:"localPort,omitempty"`
	RemotePort    int             `json:"remotePort,omitempty"`
	PID           int             `json:"pid,omitempty"`
	Running       bool            `json:"running"`
	Ready         bool            `json:"ready"`
	URL           string          `json:"url,omitempty"`
	LogPath       string          `json:"logPath,omitempty"`
	Detail        string          `json:"detail,omitempty"`
}

// PortForwardManager owns local process state without deciding Kubernetes
// service identity.
type PortForwardManager interface {
	Start(context.Context, PortForwardRequest) (PortForwardStatus, error)
	Stop(context.Context, DashboardTarget) (PortForwardStatus, error)
	Status(context.Context, DashboardTarget) (PortForwardStatus, error)
}

type dashboardDefinition struct {
	defaultNamespace string
	defaultLocalPort int
	remotePort       int
	serviceName      string
	selector         string
}

func dashboardDefinitionFor(target DashboardTarget) (dashboardDefinition, error) {
	switch target {
	case DashboardGrafana:
		return dashboardDefinition{
			defaultLocalPort: 3000, remotePort: 3000,
			selector: "app.kubernetes.io/name=attacknet-grafana,app.kubernetes.io/part-of=stacks-attacknet",
		}, nil
	case DashboardChaos:
		return dashboardDefinition{defaultNamespace: "chaos-mesh", defaultLocalPort: 2333, remotePort: 2333, serviceName: "chaos-dashboard"}, nil
	default:
		return dashboardDefinition{}, usageError("--target must be grafana or chaos")
	}
}

func parseDashboardTarget(value string) (DashboardTarget, dashboardDefinition, error) {
	target := DashboardTarget(value)
	definition, err := dashboardDefinitionFor(target)
	return target, definition, err
}

func (app *App) runDashboard(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet dashboard start|stop|status [OPTIONS]")
	}
	switch args[0] {
	case "start":
		return app.runDashboardStart(ctx, args[1:])
	case "stop", "status":
		return app.runDashboardControl(ctx, args[0], args[1:])
	default:
		return usageError(fmt.Sprintf("unknown dashboard command %q", args[0]))
	}
}

func (app *App) runDashboardStart(ctx context.Context, args []string) error {
	flags := newFlagSet("dashboard start", app.Stderr)
	targetValue := flags.String("target", "", "grafana or chaos")
	namespace := flags.String("namespace", "", "dashboard Service namespace")
	localPort := flags.Int("local-port", 0, "unprivileged loopback port")
	startupTimeout := flags.Duration("startup-timeout", 15*time.Second, "maximum listener startup time")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 0 || *targetValue == "" {
		return usageError("usage: attacknet dashboard start --target grafana|chaos [--namespace NS] [--local-port PORT]")
	}
	target, definition, err := parseDashboardTarget(*targetValue)
	if err != nil {
		return err
	}
	if *localPort == 0 {
		*localPort = definition.defaultLocalPort
	}
	if *localPort < 1024 || *localPort > 65535 {
		return usageError("--local-port must be between 1024 and 65535")
	}
	if *startupTimeout <= 0 || *startupTimeout > time.Minute {
		return usageError("--startup-timeout must be greater than zero and at most 1m")
	}
	resolvedNamespace := *namespace
	if resolvedNamespace == "" {
		resolvedNamespace = definition.defaultNamespace
		if resolvedNamespace == "" {
			resolvedNamespace = app.DefaultNamespace
		}
	}
	if problems := validateDashboardNamespace(resolvedNamespace); problems != "" {
		return usageError(problems)
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	discovery, ok := backend.(DashboardDiscovery)
	if !ok {
		return errors.New("Kubernetes backend does not support dashboard discovery")
	}
	endpoint, err := discovery.DiscoverDashboard(ctx, target, resolvedNamespace)
	if err != nil {
		return err
	}
	if app.PortForwards == nil {
		return errors.New("dashboard port-forward manager is unavailable")
	}
	status, err := app.PortForwards.Start(ctx, PortForwardRequest{
		Endpoint: endpoint, LocalPort: *localPort, StartupTimeout: *startupTimeout,
	})
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, status)
}

func validateDashboardNamespace(namespace string) string {
	if problems := kubevalidation.IsDNS1123Label(namespace); len(problems) != 0 {
		return "namespace is not a valid DNS label"
	}
	return ""
}

func (app *App) runDashboardControl(ctx context.Context, action string, args []string) error {
	flags := newFlagSet("dashboard "+action, app.Stderr)
	targetValue := flags.String("target", "", "grafana or chaos")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 0 || *targetValue == "" {
		return usageError("usage: attacknet dashboard " + action + " --target grafana|chaos")
	}
	target, _, err := parseDashboardTarget(*targetValue)
	if err != nil {
		return err
	}
	if app.PortForwards == nil {
		return errors.New("dashboard port-forward manager is unavailable")
	}
	var status PortForwardStatus
	if action == "stop" {
		status, err = app.PortForwards.Stop(ctx, target)
	} else {
		status, err = app.PortForwards.Status(ctx, target)
	}
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, status)
}

// DiscoverDashboard resolves exactly one Service and confirms its expected
// dashboard port without relying on kubectl output parsing.
func (backend *KubernetesBackend) DiscoverDashboard(ctx context.Context, target DashboardTarget, namespace string) (DashboardEndpoint, error) {
	definition, err := dashboardDefinitionFor(target)
	if err != nil {
		return DashboardEndpoint{}, err
	}
	var service *unstructured.Unstructured
	if definition.serviceName != "" {
		service, err = backend.dynamic.Resource(serviceResource).Namespace(namespace).Get(ctx, definition.serviceName, metav1.GetOptions{})
		if err != nil {
			return DashboardEndpoint{}, fmt.Errorf("discover %s dashboard Service %s/%s: %w", target, namespace, definition.serviceName, err)
		}
	} else {
		services, listErr := backend.dynamic.Resource(serviceResource).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: definition.selector})
		if listErr != nil {
			return DashboardEndpoint{}, fmt.Errorf("discover %s dashboard Service in %s: %w", target, namespace, listErr)
		}
		if len(services.Items) != 1 {
			return DashboardEndpoint{}, fmt.Errorf("discover %s dashboard Service in %s: expected exactly one match, got %d", target, namespace, len(services.Items))
		}
		service = &services.Items[0]
	}
	if !serviceExposesPort(service, definition.remotePort) {
		return DashboardEndpoint{}, fmt.Errorf("dashboard Service %s/%s does not expose port %d", namespace, service.GetName(), definition.remotePort)
	}
	return DashboardEndpoint{Target: target, Namespace: namespace, Service: service.GetName(), RemotePort: definition.remotePort}, nil
}

func serviceExposesPort(service *unstructured.Unstructured, expected int) bool {
	ports, found, err := unstructured.NestedSlice(service.Object, "spec", "ports")
	if err != nil || !found {
		return false
	}
	for _, value := range ports {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		port, ok := item["port"]
		if !ok {
			continue
		}
		switch typed := port.(type) {
		case int64:
			if typed == int64(expected) {
				return true
			}
		case float64:
			if typed == float64(expected) {
				return true
			}
		case string:
			parsed, parseErr := strconv.Atoi(typed)
			if parseErr == nil && parsed == expected {
				return true
			}
		}
	}
	return false
}
