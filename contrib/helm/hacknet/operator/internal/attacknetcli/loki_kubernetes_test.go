package attacknetcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLokiSourceRequiresOneReadySelectedPod(t *testing.T) {
	const namespace = "attacknet"
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "test-loki",
			Labels: map[string]string{
				"app.kubernetes.io/name":     "attacknet-loki",
				"testing.stacks.org/network": "test",
			},
		},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "loki"}},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "test-loki-0", Labels: map[string]string{"app": "loki"}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
	exporter := &ClientGoLokiExporter{client: fake.NewSimpleClientset(service, pod)}
	observedService, observedPod, err := exporter.resolveSource(context.Background(), namespace, "test")
	if err != nil {
		t.Fatalf("resolve Loki source: %v", err)
	}
	if observedService.Name != service.Name || observedPod.Name != pod.Name {
		t.Fatalf("resolved unexpected source: service=%s pod=%s", observedService.Name, observedPod.Name)
	}

	second := pod.DeepCopy()
	second.Name = "test-loki-1"
	if _, err := exporter.client.CoreV1().Pods(namespace).Create(context.Background(), second, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := exporter.resolveSource(context.Background(), namespace, "test"); err == nil || !strings.Contains(err.Error(), "exactly one ready Loki Pod") {
		t.Fatalf("ambiguous Loki source did not fail closed: %v", err)
	}
}

func TestLokiSourceIdentityIsStableThroughExport(t *testing.T) {
	const namespace = "attacknet"
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: "loki", UID: types.UID("service-uid"),
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: "loki-0", UID: types.UID("pod-uid"),
	}, Status: corev1.PodStatus{
		Phase:      corev1.PodRunning,
		Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
	}}
	exporter := &ClientGoLokiExporter{client: fake.NewSimpleClientset(service, pod)}
	if err := exporter.verifySource(context.Background(), namespace, service, pod); err != nil {
		t.Fatalf("stable source was rejected: %v", err)
	}
	replacement := pod.DeepCopy()
	replacement.UID = types.UID("replacement-uid")
	if _, err := exporter.client.CoreV1().Pods(namespace).Update(context.Background(), replacement, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := exporter.verifySource(context.Background(), namespace, service, pod); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement Loki source did not fail closed: %v", err)
	}
}

func TestLokiExporterRejectsInvalidScopeBeforeWriting(t *testing.T) {
	output := filepath.Join(t.TempDir(), "logs")
	exporter := &ClientGoLokiExporter{client: fake.NewSimpleClientset()}
	_, err := exporter.Export(context.Background(), "bad_namespace", "test", time.Now().Add(-time.Minute), time.Now(), output)
	if err == nil || !strings.Contains(err.Error(), "bounded Kubernetes names") {
		t.Fatalf("invalid scope did not fail closed: %v", err)
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid scope created output: %v", statErr)
	}
}
