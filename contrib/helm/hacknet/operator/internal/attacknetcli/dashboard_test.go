package attacknetcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

type dashboardBackend struct {
	*fakeBackend
	endpoint DashboardEndpoint
	err      error
	requests []DashboardEndpoint
}

func (backend *dashboardBackend) DiscoverDashboard(_ context.Context, target DashboardTarget, namespace string) (DashboardEndpoint, error) {
	backend.requests = append(backend.requests, DashboardEndpoint{Target: target, Namespace: namespace})
	return backend.endpoint, backend.err
}

type fakePortForwardManager struct {
	started []PortForwardRequest
	stopped []DashboardTarget
	status  []DashboardTarget
	result  PortForwardStatus
	err     error
}

func (manager *fakePortForwardManager) Start(_ context.Context, request PortForwardRequest) (PortForwardStatus, error) {
	manager.started = append(manager.started, request)
	return manager.result, manager.err
}

func (manager *fakePortForwardManager) Stop(_ context.Context, target DashboardTarget) (PortForwardStatus, error) {
	manager.stopped = append(manager.stopped, target)
	return manager.result, manager.err
}

func (manager *fakePortForwardManager) Status(_ context.Context, target DashboardTarget) (PortForwardStatus, error) {
	manager.status = append(manager.status, target)
	return manager.result, manager.err
}

func TestDashboardStartUsesTypedDiscoveryAndLoopbackManager(t *testing.T) {
	backend := &dashboardBackend{fakeBackend: &fakeBackend{}, endpoint: DashboardEndpoint{
		Target: DashboardGrafana, Namespace: "observability", Service: "network-attacknet-grafana", RemotePort: 3000,
	}}
	manager := &fakePortForwardManager{result: PortForwardStatus{SchemaVersion: portForwardSchema, Target: DashboardGrafana, Running: true, Ready: true}}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "experiment", strings.NewReader(""), stdout, stderr)
	app.PortForwards = manager
	code := app.Run(context.Background(), []string{
		"dashboard", "start", "--target", "grafana", "--namespace", "observability", "--local-port", "3100",
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(backend.requests) != 1 || backend.requests[0].Namespace != "observability" || len(manager.started) != 1 {
		t.Fatalf("unexpected discovery/start: %#v %#v", backend.requests, manager.started)
	}
	request := manager.started[0]
	if request.LocalPort != 3100 || request.Endpoint.Service != "network-attacknet-grafana" || request.StartupTimeout != 15*time.Second {
		t.Fatalf("unexpected request: %#v", request)
	}
	if !strings.Contains(stdout.String(), `"ready": true`) {
		t.Fatalf("status not emitted: %s", stdout.String())
	}
}

func TestDashboardChaosUsesItsOwnDefaultNamespace(t *testing.T) {
	backend := &dashboardBackend{fakeBackend: &fakeBackend{}, endpoint: DashboardEndpoint{
		Target: DashboardChaos, Namespace: "chaos-mesh", Service: "chaos-dashboard", RemotePort: 2333,
	}}
	manager := &fakePortForwardManager{result: stoppedDashboardStatus(DashboardChaos, "test")}
	app := NewApp(backend, "experiment", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	app.PortForwards = manager
	if code := app.Run(context.Background(), []string{"dashboard", "start", "--target", "chaos"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if backend.requests[0].Namespace != "chaos-mesh" || manager.started[0].LocalPort != 2333 {
		t.Fatalf("wrong Chaos defaults: %#v %#v", backend.requests, manager.started)
	}
}

func TestDashboardArgumentsFailBeforeBackendOrProcessCreation(t *testing.T) {
	created := false
	manager := &fakePortForwardManager{}
	stderr := &bytes.Buffer{}
	app := NewLazyApp(func() (Backend, error) {
		created = true
		return &dashboardBackend{fakeBackend: &fakeBackend{}}, nil
	}, "experiment", strings.NewReader(""), &bytes.Buffer{}, stderr)
	app.PortForwards = manager
	if code := app.Run(context.Background(), []string{"dashboard", "start", "--target", "grafana", "--local-port", "443"}); code != 2 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if created || len(manager.started) != 0 {
		t.Fatal("invalid local port reached a runtime boundary")
	}
}

func TestDashboardStatusAndStopAreHermeticLocalOperations(t *testing.T) {
	created := false
	manager := &fakePortForwardManager{result: stoppedDashboardStatus(DashboardGrafana, "not running")}
	app := NewLazyApp(func() (Backend, error) {
		created = true
		return &fakeBackend{}, nil
	}, "experiment", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	app.PortForwards = manager
	if code := app.Run(context.Background(), []string{"dashboard", "status", "--target", "grafana"}); code != 0 {
		t.Fatalf("status exit %d", code)
	}
	if code := app.Run(context.Background(), []string{"dashboard", "stop", "--target", "grafana"}); code != 0 {
		t.Fatalf("stop exit %d", code)
	}
	if created || len(manager.status) != 1 || len(manager.stopped) != 1 {
		t.Fatalf("local controls initialized Kubernetes: created=%v manager=%#v", created, manager)
	}
}

func TestKubernetesDashboardDiscoveryRequiresExactServiceAndPort(t *testing.T) {
	scheme := runtime.NewScheme()
	grafana := dashboardService("network-attacknet-grafana", "observability", 3000, map[string]string{
		"app.kubernetes.io/name": "attacknet-grafana", "app.kubernetes.io/part-of": "stacks-attacknet",
	})
	chaos := dashboardService("chaos-dashboard", "chaos-mesh", 2333, nil)
	backend := &KubernetesBackend{dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme, map[schema.GroupVersionResource]string{serviceResource: "ServiceList"}, grafana, chaos,
	)}

	endpoint, err := backend.DiscoverDashboard(context.Background(), DashboardGrafana, "observability")
	if err != nil || endpoint.Service != grafana.GetName() || endpoint.RemotePort != 3000 {
		t.Fatalf("Grafana discovery = %#v, %v", endpoint, err)
	}
	endpoint, err = backend.DiscoverDashboard(context.Background(), DashboardChaos, "chaos-mesh")
	if err != nil || endpoint.Service != chaos.GetName() || endpoint.RemotePort != 2333 {
		t.Fatalf("Chaos discovery = %#v, %v", endpoint, err)
	}

	wrongPort := dashboardService("wrong", "wrong", 9999, map[string]string{
		"app.kubernetes.io/name": "attacknet-grafana", "app.kubernetes.io/part-of": "stacks-attacknet",
	})
	wrongBackend := &KubernetesBackend{dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme, map[schema.GroupVersionResource]string{serviceResource: "ServiceList"}, wrongPort,
	)}
	if _, err := wrongBackend.DiscoverDashboard(context.Background(), DashboardGrafana, "wrong"); err == nil || !strings.Contains(err.Error(), "does not expose port 3000") {
		t.Fatalf("wrong port accepted: %v", err)
	}
	duplicate := dashboardService("duplicate", "observability", 3000, map[string]string{
		"app.kubernetes.io/name": "attacknet-grafana", "app.kubernetes.io/part-of": "stacks-attacknet",
	})
	ambiguousBackend := &KubernetesBackend{dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme, map[schema.GroupVersionResource]string{serviceResource: "ServiceList"}, grafana, duplicate,
	)}
	if _, err := ambiguousBackend.DiscoverDashboard(context.Background(), DashboardGrafana, "observability"); err == nil || !strings.Contains(err.Error(), "exactly one match, got 2") {
		t.Fatalf("ambiguous Grafana Services accepted: %v", err)
	}
}

func dashboardService(name, namespace string, port int64, labels map[string]string) *unstructured.Unstructured {
	unstructuredLabels := map[string]any{}
	for key, value := range labels {
		unstructuredLabels[key] = value
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": namespace, "labels": unstructuredLabels},
		"spec":     map[string]any{"ports": []any{map[string]any{"port": port}}},
	}}
	return object
}

type fakeStartedProcess int

func (process fakeStartedProcess) PID() int { return int(process) }

type fakePortForwardRuntime struct {
	running       bool
	pid           int
	startedBinary string
	startedArgs   []string
	terminated    int
	terminateErr  error
	inspectErr    error
}

func (runtime *fakePortForwardRuntime) Start(binary string, arguments []string, _ string) (startedPortForward, error) {
	runtime.startedBinary, runtime.startedArgs, runtime.running = binary, append([]string(nil), arguments...), true
	if runtime.pid == 0 {
		runtime.pid = 42
	}
	return fakeStartedProcess(runtime.pid), nil
}

func (runtime *fakePortForwardRuntime) Running(_ int, _ []string) (bool, error) {
	return runtime.running, runtime.inspectErr
}

func (runtime *fakePortForwardRuntime) Terminate(ctx context.Context, _ int, _ []string) error {
	runtime.terminated++
	runtime.terminateErr = ctx.Err()
	runtime.running = false
	return nil
}

func TestOSPortForwardManagerPersistsInspectsAndStopsOwnedProcess(t *testing.T) {
	runtime := &fakePortForwardRuntime{}
	manager := NewOSPortForwardManager("kubectl", t.TempDir())
	manager.runtime = runtime
	probeCalls := 0
	manager.probe = func(context.Context, string) bool {
		probeCalls++
		return probeCalls > 1
	}
	request := PortForwardRequest{
		Endpoint:  DashboardEndpoint{Target: DashboardGrafana, Namespace: "test", Service: "grafana", RemotePort: 3000},
		LocalPort: 3000, StartupTimeout: time.Second,
	}
	started, err := manager.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !started.Running || !started.Ready || runtime.startedBinary != "kubectl" || started.LocalAddress != loopbackAddress {
		t.Fatalf("unexpected start: %#v runtime=%#v", started, runtime)
	}
	observed, err := manager.Status(context.Background(), DashboardGrafana)
	if err != nil || !observed.Running || !observed.Ready {
		t.Fatalf("unexpected status: %#v %v", observed, err)
	}
	stopped, err := manager.Stop(context.Background(), DashboardGrafana)
	if err != nil || stopped.Running || runtime.terminated != 1 {
		t.Fatalf("unexpected stop: %#v %v runtime=%#v", stopped, err, runtime)
	}
	if _, err := os.Stat(manager.statePath(DashboardGrafana)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state survived stop: %v", err)
	}
}

func TestOSPortForwardManagerCancellationCleansPartialStart(t *testing.T) {
	runtime := &fakePortForwardRuntime{}
	manager := NewOSPortForwardManager("kubectl", t.TempDir())
	manager.runtime = runtime
	manager.probe = func(context.Context, string) bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := manager.Start(ctx, PortForwardRequest{
		Endpoint:  DashboardEndpoint{Target: DashboardChaos, Namespace: "chaos-mesh", Service: "chaos-dashboard", RemotePort: 2333},
		LocalPort: 2333, StartupTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "context canceled") || runtime.terminated != 1 {
		t.Fatalf("partial start was not cleaned: %v runtime=%#v", err, runtime)
	}
	if _, statErr := os.Stat(manager.statePath(DashboardChaos)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state survived canceled start: %v", statErr)
	}
}

func TestOSPortForwardManagerRefusesAnOccupiedLocalPortBeforeSpawn(t *testing.T) {
	runtime := &fakePortForwardRuntime{}
	manager := NewOSPortForwardManager("kubectl", t.TempDir())
	manager.runtime = runtime
	manager.probe = func(context.Context, string) bool { return true }
	_, err := manager.Start(context.Background(), PortForwardRequest{
		Endpoint:  DashboardEndpoint{Target: DashboardGrafana, Namespace: "test", Service: "grafana", RemotePort: 3000},
		LocalPort: 3000, StartupTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "already in use") || runtime.startedBinary != "" {
		t.Fatalf("occupied port reached process spawn: %v runtime=%#v", err, runtime)
	}
}

func TestOSPortForwardManagerFinishesVerifiedStopAfterSignal(t *testing.T) {
	runtime := &fakePortForwardRuntime{running: true}
	manager := NewOSPortForwardManager("kubectl", t.TempDir())
	manager.runtime = runtime
	state := portForwardState{
		SchemaVersion: portForwardSchema,
		Endpoint:      DashboardEndpoint{Target: DashboardChaos, Namespace: "chaos-mesh", Service: "chaos-dashboard", RemotePort: 2333},
		LocalPort:     2333, PID: 77, Arguments: []string{"owned"}, LogPath: "log",
	}
	if err := manager.save(state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Stop(ctx, DashboardChaos); err != nil {
		t.Fatalf("signal interrupted verified cleanup: %v", err)
	}
	if runtime.terminated != 1 || runtime.terminateErr != nil {
		t.Fatalf("cleanup inherited cancellation: %#v", runtime)
	}
}

func TestOSPortForwardManagerRefusesMismatchedPIDIdentity(t *testing.T) {
	runtime := &fakePortForwardRuntime{running: true, inspectErr: errors.New("command identity mismatch")}
	manager := NewOSPortForwardManager("kubectl", t.TempDir())
	manager.runtime = runtime
	state := portForwardState{
		SchemaVersion: portForwardSchema,
		Endpoint:      DashboardEndpoint{Target: DashboardGrafana, Namespace: "test", Service: "grafana", RemotePort: 3000},
		LocalPort:     3000, PID: 55, Arguments: []string{"owned"}, LogPath: "log",
	}
	if err := manager.save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Stop(context.Background(), DashboardGrafana); err == nil || runtime.terminated != 0 {
		t.Fatalf("mismatched PID was signaled: %v runtime=%#v", err, runtime)
	}
}

func TestOSPortForwardManagerReclaimsOnlyDeadOperationLocks(t *testing.T) {
	manager := NewOSPortForwardManager("kubectl", t.TempDir())
	path := filepath.Join(manager.stateDir, string(DashboardGrafana)+".lock")
	if err := os.MkdirAll(manager.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("99999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := manager.acquire(DashboardGrafana)
	if err != nil {
		t.Fatalf("dead lock was not reclaimed: %v", err)
	}
	release()
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(DashboardGrafana); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("live lock was stolen: %v", err)
	}
}

func TestDashboardCommandContractIsMachineReadable(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "default", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"commands", "--json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var document struct {
		Commands []CommandContract `json:"commands"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, command := range document.Commands {
		names[command.Name] = true
	}
	for _, name := range []string{"dashboard start", "dashboard stop", "dashboard status"} {
		if !names[name] {
			t.Fatalf("command contract omits %s", name)
		}
	}
}
