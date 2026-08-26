package topology

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sptr "k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestV1Beta1TelemetryRequiresVerifiableServiceBinding(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Telemetry = &attacknetv1beta1.TelemetrySpec{Enabled: k8sptr.To(true), ExporterEndpoint: "http://network-attacknet-events:4318"}
	if _, err := CompileV1Beta1(network); err == nil || !strings.Contains(err.Error(), "exporterServiceRef") {
		t.Fatalf("missing exporter service binding error = %v", err)
	}
	network.Spec.Telemetry.ExporterServiceRef = &attacknetv1beta1.TelemetryExporterServiceReference{Name: "different-service", PortName: "otlp-http", Port: 4318}
	if _, err := CompileV1Beta1(network); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched exporter service binding error = %v", err)
	}
	network.Spec.Telemetry.ExporterServiceRef.Name = "network-attacknet-events"
	if _, err := CompileV1Beta1(network); err != nil {
		t.Fatalf("valid exporter service binding was rejected: %v", err)
	}
}

func TestObserveV1Beta1TelemetryFailsClosedUntilEndpointReady(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Telemetry = &attacknetv1beta1.TelemetrySpec{
		Enabled: k8sptr.To(true), ExporterEndpoint: "http://network-attacknet-events:4318",
		ExporterServiceRef: &attacknetv1beta1.TelemetryExporterServiceReference{Name: "network-attacknet-events", PortName: "otlp-http", Port: 4318},
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	reader := fake.NewClientBuilder().WithScheme(scheme).Build()
	ready, reason, _, err := observeV1Beta1Telemetry(context.Background(), reader, network)
	if err != nil || ready || reason != "TelemetryExporterServiceNotFound" {
		t.Fatalf("missing service observation = ready %t, reason %q, err %v", ready, reason, err)
	}

	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "network-attacknet-events", Namespace: network.Namespace}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "otlp-http", Port: 4318}}}}
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()
	ready, reason, _, err = observeV1Beta1Telemetry(context.Background(), reader, network)
	if err != nil || ready || reason != "TelemetryExporterUnavailable" {
		t.Fatalf("missing endpoint observation = ready %t, reason %q, err %v", ready, reason, err)
	}

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "network-attacknet-events-a", Namespace: network.Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: service.Name}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: k8sptr.To("otlp-http"), Port: k8sptr.To[int32](4318)}},
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.8"}, Conditions: discoveryv1.EndpointConditions{Ready: k8sptr.To(true)}}},
	}
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(service, slice).Build()
	ready, reason, _, err = observeV1Beta1Telemetry(context.Background(), reader, network)
	if err != nil || !ready || reason != "TelemetryExporterReady" {
		t.Fatalf("ready endpoint observation = ready %t, reason %q, err %v", ready, reason, err)
	}
}

func TestSetV1Beta1TelemetryConditionWithdrawsOverallReadyOnlyOnFailure(t *testing.T) {
	status := attacknetv1beta1.StacksNetworkStatus{Phase: "Ready", Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "ActorsReady", ObservedGeneration: 3}}}
	setV1Beta1TelemetryCondition(&status, 3, false, "TelemetryExporterUnavailable", "no ready endpoint")
	if status.Phase != "Pending" {
		t.Fatalf("phase = %q", status.Phase)
	}
	ready := findCondition(status.Conditions, "Ready")
	telemetry := findCondition(status.Conditions, telemetryReadyCondition)
	if ready == nil || ready.Status != metav1.ConditionFalse || telemetry == nil || telemetry.Status != metav1.ConditionFalse {
		t.Fatalf("conditions = %#v", status.Conditions)
	}
}
