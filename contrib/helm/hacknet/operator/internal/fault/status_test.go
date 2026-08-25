package fault

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

func TestStatusTransitionDoesNotMutateCachedStatus(t *testing.T) {
	original := attacknetv1alpha1.FaultCampaignStatus{Conditions: []metav1.Condition{{Type: "Succeeded", Status: metav1.ConditionFalse, Reason: "Injecting", Message: "injecting", LastTransitionTime: metav1.NewTime(time.Unix(1, 0))}}}
	next := statusTransition(original, 4, "Passed", "Complete", "done", time.Unix(2, 0))
	if original.Conditions[0].Status != metav1.ConditionFalse || original.Conditions[0].Reason != "Injecting" {
		t.Fatal("transition mutated the informer-owned status backing slice")
	}
	if next.Conditions[0].Status != metav1.ConditionTrue || next.Conditions[0].Reason != "Complete" {
		t.Fatalf("terminal condition was not updated: %#v", next.Conditions)
	}
}

func TestSerializedCampaignRequeuesUntilItOwnsTheTurn(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	created := metav1.NewTime(time.Unix(10, 0).UTC())
	active := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "active",
			Namespace:         "test",
			UID:               types.UID("active-uid"),
			CreationTimestamp: created,
			Finalizers:        []string{Finalizer},
		},
		Spec:   attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "network"},
		Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Active"},
	}
	waiting := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "waiting",
			Namespace:         "test",
			UID:               types.UID("waiting-uid"),
			CreationTimestamp: metav1.NewTime(created.Add(time.Second)),
			Finalizers:        []string{Finalizer},
		},
		Spec:   attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "network"},
		Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Pending"},
	}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}).
		WithObjects(active, waiting).
		Build()
	reconciler := &Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	key := types.NamespacedName{Namespace: "test", Name: "waiting"}
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("serialized campaign has no timed wake-up after the active campaign terminates")
	}
	observed := &attacknetv1alpha1.FaultCampaign{}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "Pending" || observed.Status.Reason != "SerializedBehindActiveFault" {
		t.Fatalf("serialized state was not recorded: %#v", observed.Status)
	}

	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(active), active); err != nil {
		t.Fatal(err)
	}
	active.Status.Phase = "Passed"
	if err := kube.Status().Update(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	turn, err := reconciler.isSerializedTurn(context.Background(), observed)
	if err != nil {
		t.Fatal(err)
	}
	if !turn {
		t.Fatal("waiting campaign did not become eligible after the active campaign terminated")
	}
}

func TestTerminalCampaignReleasesCleanupFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name: "complete", Namespace: "test", UID: types.UID("campaign-uid"),
			Finalizers: []string{Finalizer},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase: "Passed",
			Cleanup: &attacknetv1alpha1.CleanupEvidence{
				Absent: true, AllRecovered: true, Method: "Normal",
			},
		},
	}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}).
		WithObjects(campaign).
		Build()
	reconciler := &Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	key := types.NamespacedName{Namespace: "test", Name: "complete"}
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1alpha1.FaultCampaign{}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(observed, Finalizer) {
		t.Fatal("terminal campaign retained its cleanup finalizer after cleanup was proven")
	}
}

func TestPendingCampaignRequeuesWhileExternalMutationLeaseIsHeld(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	network := admittedNetwork(t, "network-miner-1-0", "pod-uid")
	pod := recoveredPod("network-miner-1-0", "pod-uid", "miner-1", "10.0.0.1")
	pod.Status.ContainerStatuses[0].ImageID = "docker-pullable://stacks@sha256:" + repeatHex("b")
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "waiting",
			Namespace:  "test",
			UID:        types.UID("campaign-uid"),
			Generation: 1,
			Finalizers: []string{Finalizer},
		},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Target:     attacknetv1alpha1.FaultTarget{Actors: []string{"miner-1"}},
			Fault:      attacknetv1alpha1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: "30s"},
			Safety:     attacknetv1alpha1.FaultSafety{MaxUnavailableMinerPercent: 100},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Pending"},
	}
	environment := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: environmentLease, Namespace: "test"}, Data: map[string]string{"network": "network"}}
	lease := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: mutationLease, Namespace: "test"}, Data: map[string]string{
		"network": "network", "owner": "human:operator", "token": "external-token",
	}}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}, &attacknetv1alpha1.StacksNetwork{}).
		WithObjects(network, &pod, campaign, environment, lease).
		Build()
	reconciler := &Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	key := types.NamespacedName{Namespace: "test", Name: "waiting"}
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("campaign waiting for an external mutation lease has no timed wake-up")
	}
	observed := &attacknetv1alpha1.FaultCampaign{}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Reason != "WaitingForMutationLease" {
		t.Fatalf("lease wait was not durably reported: %#v", observed.Status)
	}
}

func TestPendingCampaignReportsUnavailableEnvironmentLease(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		environment *corev1.ConfigMap
		message     string
	}{
		{name: "missing", message: "no active environment lease exists"},
		{
			name: "different-network",
			environment: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: environmentLease, Namespace: "test"},
				Data:       map[string]string{"network": "other-network"},
			},
			message: "belongs to network other-network",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			network := admittedNetwork(t, "network-miner-1-0", "pod-uid")
			pod := recoveredPod("network-miner-1-0", "pod-uid", "miner-1", "10.0.0.1")
			pod.Status.ContainerStatuses[0].ImageID = "docker-pullable://stacks@sha256:" + repeatHex("b")
			campaign := &attacknetv1alpha1.FaultCampaign{
				ObjectMeta: metav1.ObjectMeta{
					Name: "waiting", Namespace: "test", UID: types.UID("campaign-uid"),
					Generation: 1, Finalizers: []string{Finalizer},
				},
				Spec: attacknetv1alpha1.FaultCampaignSpec{
					NetworkRef: "network",
					Target:     attacknetv1alpha1.FaultTarget{Actors: []string{"miner-1"}},
					Fault:      attacknetv1alpha1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: "30s"},
					Safety:     attacknetv1alpha1.FaultSafety{MaxUnavailableMinerPercent: 100},
				},
				Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Pending"},
			}
			objects := []client.Object{network, &pod, campaign}
			if testCase.environment != nil {
				objects = append(objects, testCase.environment)
			}
			kube := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}, &attacknetv1alpha1.StacksNetwork{}).
				WithObjects(objects...).
				Build()
			reconciler := &Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
			key := types.NamespacedName{Namespace: "test", Name: "waiting"}
			result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key})
			if err != nil {
				t.Fatal(err)
			}
			if result.RequeueAfter <= 0 {
				t.Fatal("campaign waiting for an environment lease has no timed wake-up")
			}
			observed := &attacknetv1alpha1.FaultCampaign{}
			if err := kube.Get(context.Background(), key, observed); err != nil {
				t.Fatal(err)
			}
			if observed.Status.Phase != "Pending" || observed.Status.Reason != "WaitingForEnvironmentLease" || !strings.Contains(observed.Status.Message, testCase.message) {
				t.Fatalf("environment-lease wait was not durably reported: %#v", observed.Status)
			}
			if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: mutationLease}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
				t.Fatalf("mutation lease was created without the environment lease: %v", err)
			}
		})
	}
}

func TestAdmittedCampaignFailsClosedAfterEnvironmentLeaseLoss(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	network := admittedNetwork(t, "network-miner-1-0", "pod-uid")
	pod := recoveredPod("network-miner-1-0", "pod-uid", "miner-1", "10.0.0.1")
	pod.Status.ContainerStatuses[0].ImageID = "docker-pullable://stacks@sha256:" + repeatHex("b")
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name: "active", Namespace: "test", UID: types.UID("campaign-uid"),
			Generation: 1, Finalizers: []string{Finalizer},
		},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Target:     attacknetv1alpha1.FaultTarget{Actors: []string{"miner-1"}},
			Fault:      attacknetv1alpha1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: "30s"},
			Safety:     attacknetv1alpha1.FaultSafety{MaxUnavailableMinerPercent: 100},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Admitted"},
	}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}, &attacknetv1alpha1.StacksNetwork{}).
		WithObjects(network, &pod, campaign).
		Build()
	reconciler := &Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	key := types.NamespacedName{Namespace: "test", Name: "active"}
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1alpha1.FaultCampaign{}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "Failed" || observed.Status.Reason != "MutationLeaseLost" || !strings.Contains(observed.Status.Message, "no active environment lease") {
		t.Fatalf("environment-lease loss did not terminate fail-closed: %#v", observed.Status)
	}
	if observed.Status.Cleanup == nil || !observed.Status.Cleanup.Absent || !observed.Status.Cleanup.AllRecovered {
		t.Fatalf("environment-lease loss lacks cleanup proof: %#v", observed.Status.Cleanup)
	}
}

func TestReconcileUsesUncachedIdentityBeforeContinuingMutation(t *testing.T) {
	oldNetwork := admittedNetwork(t, "old-pod", "pod-old")
	expected, err := inventory.Published(oldNetwork)
	if err != nil {
		t.Fatal(err)
	}
	currentNetwork := admittedNetwork(t, "new-pod", "pod-new")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-pod",
			Namespace: "test",
			UID:       types.UID("pod-new"),
			Labels: map[string]string{
				NetworkLabel: "network",
				ActorLabel:   "miner-1",
			},
		},
		Spec: corev1.PodSpec{
			NodeName:   "worker",
			Containers: []corev1.Container{{Name: "actor", Image: "example.invalid/stacks:dev"}},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    "actor",
				Ready:   true,
				ImageID: "docker-pullable://stacks@sha256:" + repeatHex("b"),
			}},
		},
	}
	cachedPod := pod.DeepCopy()
	cachedPod.Name = "old-pod"
	cachedPod.UID = types.UID("pod-old")
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "campaign",
			Namespace:  "test",
			UID:        types.UID("campaign-uid"),
			Generation: 1,
			Finalizers: []string{Finalizer},
		},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "io-pressure", Action: "disk-pressure", Duration: "30s"},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase: "Active",
			Admission: &attacknetv1alpha1.CampaignAdmission{
				NetworkInventory: expected,
			},
		},
	}
	environment := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: environmentLease, Namespace: "test"}, Data: map[string]string{"network": "network"}}
	lease := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: mutationLease, Namespace: "test"}, Data: map[string]string{
		"network": "network",
		"owner":   "faultcampaign:campaign-uid",
		"token":   "campaign-uid",
	}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cachedClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}, &attacknetv1alpha1.StacksNetwork{}).
		WithObjects(oldNetwork, cachedPod, campaign, environment, lease).
		Build()
	directReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(currentNetwork, pod, campaign.DeepCopy(), environment, lease).Build()
	reconciler := &Reconciler{Client: cachedClient, APIReader: directReader, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test", Name: "campaign"}}); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1alpha1.FaultCampaign{}
	if err := cachedClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "campaign"}, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "Inconclusive" || observed.Status.Reason != "TargetIdentityDiverged" || observed.Status.IdentityDivergence == nil {
		t.Fatalf("identity divergence was not a terminal barrier: %#v", observed.Status)
	}
	pressure := &corev1.Pod{}
	if err := cachedClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: stableFaultName("io-pressure", "campaign")}, pressure); !apierrors.IsNotFound(err) {
		t.Fatalf("mutation processing continued or failed unexpectedly after identity divergence: %v", err)
	}
}

func TestPodRecoveryPreservesActionSpecificEffectEvidence(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Unix(20, 0).UTC())
	proven, err := rawJSON(map[string]any{"actor": "miner-1", "assertion": "PodDisappeared", "outcome": "Proven"})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := rawJSON(map[string]any{"actor": "miner-2", "assertion": "PodDisappeared", "outcome": "Failed"})
	if err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "campaign", Namespace: "test", UID: types.UID("campaign-uid"), Generation: 1},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault: attacknetv1alpha1.FaultSpec{
				Type: "pod", Action: "pod-kill", Mode: "all", Duration: "1s",
			},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase: "Recovering",
			ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{
				{Actor: "miner-1", PodUID: "old-pod-1"},
				{Actor: "miner-2", PodUID: "old-pod-2"},
			},
			EffectResults: []apixv1.JSON{proven, failed},
			Cleanup: &attacknetv1alpha1.CleanupEvidence{
				Absent: false, AllRecovered: false, ObservedAt: now,
			},
		},
	}
	network := &attacknetv1alpha1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test"},
		Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{
			{Name: "miner-1", Role: "miner"},
			{Name: "miner-2", Role: "miner"},
		}},
	}
	pods := []corev1.Pod{
		recoveredPod("network-miner-1-0", "new-pod-1", "miner-1", "10.0.0.1"),
		recoveredPod("network-miner-2-0", "new-pod-2", "miner-2", "10.0.0.2"),
	}
	objects := []client.Object{campaign, network, &pods[0], &pods[1]}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.FaultCampaign{}).
		WithObjects(objects...).
		Build()
	reconciler := &Reconciler{Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time }}
	stored := &attacknetv1alpha1.FaultCampaign{}
	key := types.NamespacedName{Namespace: "test", Name: "campaign"}
	if err := kube.Get(context.Background(), key, stored); err != nil {
		t.Fatal(err)
	}
	compiled := Compiled{Evidence: Evidence{SelectedActors: []string{"miner-1", "miner-2"}}}
	if err := reconciler.observeRecovery(context.Background(), stored, network, pods, compiled); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), key, stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.Phase != "Inconclusive" || stored.Status.Reason != "EffectNotProven" {
		t.Fatalf("aggregate all-mode result was not preserved: phase=%s reason=%s", stored.Status.Phase, stored.Status.Reason)
	}
	if len(stored.Status.EffectResults) != 2 || string(stored.Status.EffectResults[0].Raw) != string(proven.Raw) || string(stored.Status.EffectResults[1].Raw) != string(failed.Raw) {
		t.Fatalf("recovery replaced action-specific effect evidence: %#v", stored.Status.EffectResults)
	}
	if len(stored.Status.RecoveryResults) != 2 {
		t.Fatalf("recovery result count = %d, want 2", len(stored.Status.RecoveryResults))
	}
	if stored.Status.Cleanup == nil || !stored.Status.Cleanup.Absent || !stored.Status.Cleanup.AllRecovered {
		t.Fatalf("terminal result did not carry the observed cleanup barrier: %#v", stored.Status.Cleanup)
	}
}

func recoveredPod(name, uid, actor, ip string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "test", UID: types.UID(uid),
			Labels: map[string]string{NetworkLabel: "network", ActorLabel: actor, RoleLabel: "miner"},
		},
		Spec: corev1.PodSpec{
			NodeName:   "worker",
			Containers: []corev1.Container{{Name: "actor", Image: "example.invalid/stacks:dev"}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: ip,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "actor", Ready: true,
				ImageID: "docker-pullable://stacks@sha256:" + repeatHex("c"),
			}},
		},
	}
}

func admittedNetwork(t *testing.T, podName, podUID string) *attacknetv1alpha1.StacksNetwork {
	t.Helper()
	network := &attacknetv1alpha1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid"), Generation: 1},
		Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{{
			Name: "miner-1", Role: "miner", Image: "example.invalid/stacks:dev",
		}}},
		Status: attacknetv1alpha1.StacksNetworkStatus{
			ObservedGeneration: 1,
			Phase:              "Ready",
			InventoryReady:     true,
			Actors: []attacknetv1alpha1.ActorStatus{{
				Name: "miner-1", Role: "miner", ResourceName: "network-miner-1",
				Image: "example.invalid/stacks:dev", Ready: true, IdentityReady: true,
				ServiceName: "network-miner-1", StatefulSetUID: "statefulset-uid",
				CurrentRevision: "revision-1", PodName: podName, PodUID: podUID,
				RuntimeImageID: "docker-pullable://stacks@sha256:" + repeatHex("b"),
			}},
		},
	}
	payload, err := inventory.Build(network)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func repeatHex(value string) string {
	result := ""
	for range 64 {
		result += value
	}
	return result
}
