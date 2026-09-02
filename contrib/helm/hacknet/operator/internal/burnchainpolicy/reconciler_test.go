package burnchainpolicy

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

type fixedStatusReader struct {
	status burnchain.Status
	err    error
}

func (reader fixedStatusReader) Read(context.Context, string) (burnchain.Status, error) {
	return reader.status, reader.err
}

func TestReconcileAdmitsIdentityBeforeCreatingClock(t *testing.T) {
	reconciler, request := testReconciler(t)
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requeue {
		t.Fatal("first pass must persist admitted identity before mutating resources")
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.Phase != "Admitted" || policy.Status.AdmittedNetworkUID != "network-uid" || policy.Status.AdmittedBitcoinUID != "bitcoin-uid" || policy.Status.AdmittedBitcoinImageID != "containerd://sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("identity was not durably admitted: %#v", policy.Status)
	}
	deployments := &appsv1.DeploymentList{}
	if err := reconciler.List(context.Background(), deployments); err != nil {
		t.Fatal(err)
	}
	if len(deployments.Items) != 0 {
		t.Fatal("clock workload was created in the identity-admission pass")
	}
}

func TestReconcileAppliesClockThenReportsAcknowledgedPolicy(t *testing.T) {
	reconciler, request := testReconciler(t)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	configMap := &corev1.ConfigMap{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cadence-clock"}, configMap); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseRuntime(configMap)
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "cadence-clock-1", Namespace: "test", Labels: map[string]string{
		labelPolicy: "cadence", labelComponent: componentClock,
	}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}}}
	if err := reconciler.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	height := uint64(120)
	reconciler.StatusReader = fixedStatusReader{status: burnchain.Status{State: "running", BitcoinHeight: &height, PolicyGeneration: &parsed.Generation, PolicyMode: parsed.Mode}}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.Phase != "Ready" || policy.Status.AppliedPolicyDigest == "" || policy.Status.ObservedHeight != 120 {
		t.Fatalf("acknowledged clock was not reported Ready: %#v", policy.Status)
	}
	if len(policy.Status.Conditions) != 1 || policy.Status.Conditions[0].Type != "Ready" || policy.Status.Conditions[0].Status != metav1.ConditionTrue || policy.Status.Conditions[0].Reason != "PolicyApplied" {
		t.Fatalf("Ready phase has contradictory conditions: %#v", policy.Status.Conditions)
	}
	resourceVersion := policy.ResourceVersion
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.ResourceVersion != resourceVersion {
		t.Fatal("steady-state observation caused an unnecessary status write")
	}
}

func TestPausedPolicyIsNotReadyUntilClockReportsPaused(t *testing.T) {
	reconciler, request := testReconciler(t)
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Paused = true
	if err := reconciler.Update(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	configMap := &corev1.ConfigMap{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cadence-clock"}, configMap); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseRuntime(configMap)
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "cadence-clock-1", Namespace: "test", Labels: map[string]string{
		labelPolicy: "cadence", labelComponent: componentClock,
	}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}}}
	if err := reconciler.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	height := uint64(120)
	reconciler.StatusReader = fixedStatusReader{status: burnchain.Status{State: "running", BitcoinHeight: &height, PolicyGeneration: &parsed.Generation, PolicyMode: burnchain.ModePause}}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.Phase != "Applying" || policy.Status.Reason != "PolicyStateNotAcknowledged" {
		t.Fatalf("running paused generation reported Ready: %#v", policy.Status)
	}
	reconciler.StatusReader = fixedStatusReader{status: burnchain.Status{State: "paused", BitcoinHeight: &height, PolicyGeneration: &parsed.Generation, PolicyMode: burnchain.ModePause}}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.Phase != "Ready" {
		t.Fatalf("paused clock did not become Ready: %#v", policy.Status)
	}
}

func TestReconcileFailsClosedWhenAdmittedBitcoinIdentityChanges(t *testing.T) {
	reconciler, request := testReconciler(t)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "network"}, network); err != nil {
		t.Fatal(err)
	}
	network.Status.Actors[0].StatefulSetUID = "replacement-uid"
	if err := reconciler.Status().Update(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.Phase != "Degraded" || policy.Status.Reason != "NetworkIdentityChanged" {
		t.Fatalf("identity drift did not fail closed: %#v", policy.Status)
	}
}

func TestAdmitNetworkResolvesPolicyForTargetBitcoinNode(t *testing.T) {
	reconciler, _ := testReconciler(t)
	ctx := context.Background()
	network := &attacknetv1beta1.StacksNetwork{}
	key := types.NamespacedName{Namespace: "test", Name: "network"}
	if err := reconciler.Get(ctx, key, network); err != nil {
		t.Fatal(err)
	}
	network.Spec.Burnchain.Nodes = append(network.Spec.Burnchain.Nodes, attacknetv1beta1.BitcoinNodeSpec{
		Name: "bitcoin-2", PolicyRef: &attacknetv1beta1.NamedObjectReference{Name: "cadence-2"},
	})
	if err := reconciler.Update(ctx, network); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(ctx, key, network); err != nil {
		t.Fatal(err)
	}
	network.Status.ObservedGeneration = network.Generation
	network.Status.Actors = append(network.Status.Actors, attacknetv1beta1.ActorStatus{
		Name: "bitcoin-2", Role: "burnchain", IdentityReady: true, ServiceName: "bitcoin-2",
		StatefulSetUID: "bitcoin-2-uid", RuntimeImageID: "containerd://sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err := reconciler.Status().Update(ctx, network); err != nil {
		t.Fatal(err)
	}
	policy := validPolicy()
	policy.Name = "cadence-2"
	policy.Spec.BitcoinNodeRef = "bitcoin-2"
	if _, actor, err := reconciler.admitNetwork(ctx, policy); err != nil || actor.Name != "bitcoin-2" {
		t.Fatalf("target-specific policy was not admitted: actor=%#v err=%v", actor, err)
	}
	policy.Name = "cadence"
	if _, _, err := reconciler.admitNetwork(ctx, policy); err == nil {
		t.Fatal("shared default policy was accepted for a node with an explicit policy")
	}
}

func TestRepeatedFailureStatusEventDoesNotHotLoop(t *testing.T) {
	reconciler, request := testReconciler(t)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	reconciler.Now = func() time.Time { return now }
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.RPC.MinimumBackoff = metav1.Duration{Duration: 250 * time.Millisecond}
	if err := reconciler.Update(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	resourceVersion := policy.ResourceVersion
	if policy.Status.ConsecutiveFailures != 1 {
		t.Fatalf("failure count = %d", policy.Status.ConsecutiveFailures)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(context.Background(), request.NamespacedName, policy); err != nil {
		t.Fatal(err)
	}
	if policy.ResourceVersion != resourceVersion || policy.Status.ConsecutiveFailures != 1 {
		t.Fatalf("unchanged failure rewrote status: version %s -> %s, count %d", resourceVersion, policy.ResourceVersion, policy.Status.ConsecutiveFailures)
	}
}

func testReconciler(t *testing.T) (*Reconciler, reconcile.Request) {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, attacknetv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	policy := validPolicy()
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid"), Generation: 2},
		Spec: attacknetv1beta1.StacksNetworkSpec{Burnchain: attacknetv1beta1.BurnchainTopologySpec{
			PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "cadence"}, Nodes: []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin-1", RPCPort: 18443}},
		}},
		Status: attacknetv1beta1.StacksNetworkStatus{ObservedGeneration: 2, InventoryReady: false, Actors: []attacknetv1beta1.ActorStatus{{
			Name: "bitcoin-1", Role: "burnchain", IdentityReady: true, ServiceName: "bitcoin-1", StatefulSetUID: "bitcoin-uid", RuntimeImageID: "containerd://sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}},
	}
	cluster := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(policy, network).WithObjects(policy, network).Build()
	return &Reconciler{Client: cluster, APIReader: cluster, Scheme: scheme, ClockImage: "clock", ClockImagePull: corev1.PullIfNotPresent,
		StatusReader: fixedStatusReader{err: context.DeadlineExceeded}}, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test", Name: "cadence"}}
}
