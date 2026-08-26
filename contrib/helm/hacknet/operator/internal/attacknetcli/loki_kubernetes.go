package attacknetcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	clientspdy "k8s.io/client-go/transport/spdy"
)

// RetainedLogExporter captures a complete Loki interval and writes export.json,
// logs.jsonl.gz, and kubernetes-source.json beneath the requested directory.
type RetainedLogExporter interface {
	Export(context.Context, string, string, time.Time, time.Time, string) (LokiExportMetadata, error)
}

// ClientGoLokiExporter discovers Loki and uses a client-go Pod port-forward;
// it does not require a public Service or a kubectl subprocess.
type ClientGoLokiExporter struct {
	config *rest.Config
	client kubernetes.Interface
	now    func() time.Time
}

// NewClientGoLokiExporter constructs the production retained-log exporter.
func NewClientGoLokiExporter(config *rest.Config) (*ClientGoLokiExporter, error) {
	if config == nil {
		return nil, errors.New("Kubernetes REST config is required")
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client for Loki export: %w", err)
	}
	return &ClientGoLokiExporter{config: rest.CopyConfig(config), client: client, now: time.Now}, nil
}

// Export resolves exactly one ready Loki Pod, records the source objects, and
// captures the complete requested interval over a temporary loopback tunnel.
func (exporter *ClientGoLokiExporter) Export(ctx context.Context, namespace, network string, start, end time.Time, output string) (LokiExportMetadata, error) {
	if len(kubevalidation.IsDNS1123Label(namespace)) != 0 || !networkLabelPattern.MatchString(network) {
		return LokiExportMetadata{}, errors.New("namespace and network must be bounded Kubernetes names")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return LokiExportMetadata{}, err
	}
	service, pod, err := exporter.resolveSource(ctx, namespace, network)
	if err != nil {
		return LokiExportMetadata{}, err
	}
	if err := writePrivateJSON(filepath.Join(output, "kubernetes-source.json"), map[string]any{"service": service, "pod": pod}); err != nil {
		return LokiExportMetadata{}, err
	}
	endpoint, stop, err := exporter.forward(ctx, namespace, pod.Name)
	if err != nil {
		return LokiExportMetadata{}, err
	}
	defer close(stop)
	result, exportErr := ExportLokiRange(ctx, &http.Client{Timeout: 15 * time.Second}, LokiExportOptions{
		Endpoint: endpoint, Network: network, Start: start, End: end, OutputDirectory: output,
		VerifyBeforeSeal: func() error {
			return exporter.verifySource(ctx, namespace, service, pod)
		},
	}, exporter.now)
	if exportErr != nil {
		return result, exportErr
	}
	return result, nil
}

func (exporter *ClientGoLokiExporter) verifySource(ctx context.Context, namespace string, service *corev1.Service, pod *corev1.Pod) error {
	liveService, err := exporter.client.CoreV1().Services(namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("re-read Loki Service after export: %w", err)
	}
	livePod, err := exporter.client.CoreV1().Pods(namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("re-read Loki Pod after export: %w", err)
	}
	if liveService.UID != service.UID || livePod.UID != pod.UID || !podReady(livePod) {
		return errors.New("Loki source identity changed during export")
	}
	return nil
}

func (exporter *ClientGoLokiExporter) resolveSource(ctx context.Context, namespace, network string) (*corev1.Service, *corev1.Pod, error) {
	selector := "app.kubernetes.io/name=attacknet-loki,testing.stacks.org/network=" + network
	services, err := exporter.client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, nil, fmt.Errorf("list Loki Services: %w", err)
	}
	if len(services.Items) != 1 {
		return nil, nil, fmt.Errorf("expected exactly one Loki Service for %s; found %d", network, len(services.Items))
	}
	service := services.Items[0].DeepCopy()
	if len(service.Spec.Selector) == 0 {
		return nil, nil, errors.New("Loki Service has no Pod selector")
	}
	pods, err := exporter.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(service.Spec.Selector).String()})
	if err != nil {
		return nil, nil, fmt.Errorf("list Loki Pods: %w", err)
	}
	ready := make([]*corev1.Pod, 0, len(pods.Items))
	for index := range pods.Items {
		if podReady(&pods.Items[index]) {
			ready = append(ready, pods.Items[index].DeepCopy())
		}
	}
	if len(ready) != 1 {
		return nil, nil, fmt.Errorf("expected exactly one ready Loki Pod for %s; found %d", network, len(ready))
	}
	return service, ready[0], nil
}

func (exporter *ClientGoLokiExporter) forward(ctx context.Context, namespace, pod string) (string, chan struct{}, error) {
	roundTripper, upgrader, err := clientspdy.RoundTripperFor(exporter.config)
	if err != nil {
		return "", nil, fmt.Errorf("create Loki port-forward transport: %w", err)
	}
	host, err := url.Parse(exporter.config.Host)
	if err != nil {
		return "", nil, err
	}
	server := &url.URL{Scheme: host.Scheme, Host: host.Host, Path: fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, pod)}
	dialer := clientspdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, server)
	stop := make(chan struct{})
	ready := make(chan struct{})
	errorOutput := &bytes.Buffer{}
	forwarder, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:3100"}, stop, ready, nil, errorOutput)
	if err != nil {
		return "", nil, err
	}
	forwardErr := make(chan error, 1)
	go func() { forwardErr <- forwarder.ForwardPorts() }()
	select {
	case <-ctx.Done():
		close(stop)
		return "", nil, ctx.Err()
	case err := <-forwardErr:
		close(stop)
		return "", nil, fmt.Errorf("start Loki port-forward: %w: %s", err, errorOutput.String())
	case <-ready:
	}
	ports, err := forwarder.GetPorts()
	if err != nil || len(ports) != 1 {
		close(stop)
		return "", nil, errors.New("Loki port-forward did not publish one local port")
	}
	return fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local), stop, nil
}

func podReady(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
