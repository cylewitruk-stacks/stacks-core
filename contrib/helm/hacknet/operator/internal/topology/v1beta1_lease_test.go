package topology

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestV1Beta1SuspensionDoesNotWaitForActorDependentPolicyReadiness(t *testing.T) {
	scheme := testScheme(t)
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	network := betaNetworkFixture()
	network.Spec.Suspended = true
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(network).WithObjects(network).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	request := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: network.Namespace, Name: network.Name}}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	current := &attacknetv1beta1.StacksNetwork{}
	if err := kube.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Phase != "Suspended" || current.Status.InventoryReady || current.Status.InventoryDigest != "" {
		t.Fatalf("suspended status was overwritten by actor-dependent readiness: %#v", current.Status)
	}
}

func TestV1Beta1SuspensionWaitsForActorTerminationBeforeLeaseHandoff(t *testing.T) {
	scheme := testScheme(t)
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	network := betaNetworkFixture()
	network.Spec.Suspended = true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "terminating-actor", Namespace: network.Namespace,
		Labels: map[string]string{managedByLabel: managedByValue, networkLabel: network.Name},
	}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(network).WithObjects(network, pod).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	if err := reconciler.ensureEnvironmentLease(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	request := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: network.Namespace, Name: network.Name}}
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter == 0 {
		t.Fatal("suspension did not requeue while an actor Pod remained")
	}
	current := &attacknetv1beta1.StacksNetwork{}
	if err := kube.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Phase != "Suspending" {
		t.Fatalf("phase with remaining actor Pod = %q", current.Status.Phase)
	}
	if err := kube.Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Phase != "Suspended" {
		t.Fatalf("quiescent phase = %q", current.Status.Phase)
	}
	lease := &corev1.ConfigMap{}
	err = kube.Get(context.Background(), types.NamespacedName{Namespace: network.Namespace, Name: environmentLeaseName}, lease)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("environment lease remains after suspension: %v", err)
	}
}

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

func TestSuspendedNetworkReleasesOwnedEnvironmentLeaseOnlyAfterPodsTerminate(t *testing.T) {
	scheme := betaLeaseScheme(t)
	network := betaNetworkFixture()
	network.Spec.Suspended = true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "actor", Namespace: network.Namespace,
		Labels: map[string]string{managedByLabel: managedByValue, networkLabel: network.Name},
	}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(network, pod).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	if err := reconciler.ensureEnvironmentLease(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	released, err := reconciler.releaseEnvironmentLeaseWhenQuiescent(context.Background(), network)
	if err != nil || released {
		t.Fatalf("lease released while actor Pod remained: released=%v err=%v", released, err)
	}
	if err := kube.Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	released, err = reconciler.releaseEnvironmentLeaseWhenQuiescent(context.Background(), network)
	if err != nil || !released {
		t.Fatalf("quiescent lease release: released=%v err=%v", released, err)
	}
	lease := &corev1.ConfigMap{}
	err = kube.Get(context.Background(), types.NamespacedName{Namespace: network.Namespace, Name: environmentLeaseName}, lease)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("released environment lease remains: %v", err)
	}
}

func TestSuspendedNetworkRefusesToReleaseForeignLeaseWhileActorsRemain(t *testing.T) {
	scheme := betaLeaseScheme(t)
	network := betaNetworkFixture()
	network.Spec.Suspended = true
	foreign := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: environmentLeaseName, Namespace: network.Namespace},
		Data:       map[string]string{"network": "other"},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "actor", Namespace: network.Namespace,
		Labels: map[string]string{managedByLabel: managedByValue, networkLabel: network.Name},
	}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(network, foreign, pod).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	released, err := reconciler.releaseEnvironmentLeaseWhenQuiescent(context.Background(), network)
	if err == nil || released || !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("foreign-lease conflict: released=%v err=%v", released, err)
	}
	current := &corev1.ConfigMap{}
	if getErr := kube.Get(context.Background(), types.NamespacedName{Namespace: network.Namespace, Name: environmentLeaseName}, current); getErr != nil {
		t.Fatal(getErr)
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
