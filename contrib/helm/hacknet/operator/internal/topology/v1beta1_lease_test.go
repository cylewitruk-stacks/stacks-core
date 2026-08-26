package topology

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestV1Beta1NetworkOwnsEnvironmentLease(t *testing.T) {
	scheme := betaLeaseScheme(t)
	network := betaNetworkFixture()
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(network).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	if err := reconciler.ensureEnvironmentLease(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	lease := &corev1.ConfigMap{}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: network.Namespace, Name: environmentLeaseName}, lease); err != nil {
		t.Fatal(err)
	}
	owner := metav1.GetControllerOf(lease)
	if owner == nil || owner.UID != network.UID || owner.Kind != "StacksNetwork" {
		t.Fatalf("environment lease owner = %#v", owner)
	}
	if lease.Data["network"] != network.Name || lease.Data["token"] != string(network.UID) {
		t.Fatalf("environment lease data = %#v", lease.Data)
	}
	if err := reconciler.ensureEnvironmentLease(context.Background(), network); err != nil {
		t.Fatalf("idempotent environment lease reconcile failed: %v", err)
	}
}

func TestV1Beta1NetworkRefusesForeignEnvironmentLease(t *testing.T) {
	scheme := betaLeaseScheme(t)
	network := betaNetworkFixture()
	lease := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: environmentLeaseName, Namespace: network.Namespace},
		Data:       map[string]string{"network": "other"},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(network, lease).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	err := reconciler.ensureEnvironmentLease(context.Background(), network)
	if err == nil || !strings.Contains(err.Error(), "held by network") {
		t.Fatalf("foreign lease error = %v", err)
	}
	current := &corev1.ConfigMap{}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: network.Namespace, Name: environmentLeaseName}, current); err != nil {
		t.Fatal(err)
	}
	if current.Data["network"] != "other" {
		t.Fatalf("foreign lease was mutated: %#v", current.Data)
	}
}

func betaLeaseScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, attacknetv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}
