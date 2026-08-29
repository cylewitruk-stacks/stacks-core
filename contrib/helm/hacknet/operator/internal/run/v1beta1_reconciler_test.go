package run

import (
	"context"
	"errors"
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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
)

type staticObservationReader struct{ snapshot ObservationSnapshot }

func (r staticObservationReader) Read(context.Context, *attacknetv1beta1.AttacknetRun, *attacknetv1beta1.StacksNetwork) (ObservationSnapshot, error) {
	return r.snapshot, nil
}

type errorSignerResolver struct{ err error }

func (resolver errorSignerResolver) Resolve(context.Context, *attacknetv1alpha1.StacksNetwork, []corev1.Pod) (signerset.Result, error) {
	return signerset.Result{}, resolver.err
}

type staleCampaignListReader struct {
	client.Reader
	items []attacknetv1beta1.FaultCampaign
}

func (reader staleCampaignListReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if campaigns, ok := list.(*attacknetv1beta1.FaultCampaignList); ok {
		campaigns.Items = append([]attacknetv1beta1.FaultCampaign(nil), reader.items...)
		return nil
	}
	return reader.Reader.List(ctx, list, options...)
}

func TestBetaReconcilerResumesDAGFromDurableChildState(t *testing.T) {
	run, declaredNetwork, admitted, templates, manifest := betaScheduleFixture()
	run.Finalizers = []string{betaRunFinalizer}
	schedule, err := buildBetaSchedule(run, declaredNetwork, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	network, minerPod, bitcoinPod := betaLiveNetworkFixture(t)
	run.Spec.NetworkRef = network.Name
	schedule.Network.Name = network.Name
	schedule.Network.UID = string(network.UID)
	schedule.Network.Generation = network.Generation
	schedule.Network.Inventory = *networkInventory(network)
	legacyNetwork, err := topology.CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	schedule.Network.ManifestDigest, err = canonical.ArtifactDigest(canonicalManifest(legacyNetwork, map[string]float64{}))
	if err != nil {
		t.Fatal(err)
	}
	schedule.Integrity = scheduleIntegrity{}
	schedule, err = sealBetaSchedule(schedule)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = attacknetv1beta1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.AttacknetRun{}, &attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(run, network, minerPod, bitcoinPod).Build()
	store := betaScheduleStore{writer: kube, reader: kube}
	reference, err := store.persist(context.Background(), run, schedule)
	if err != nil {
		t.Fatal(err)
	}
	storedRun := &attacknetv1beta1.AttacknetRun{}
	key := types.NamespacedName{Namespace: run.Namespace, Name: run.Name}
	if err := kube.Get(context.Background(), key, storedRun); err != nil {
		t.Fatal(err)
	}
	started := metav1.NewTime(time.Unix(1, 0))
	storedRun.Status = attacknetv1beta1.AttacknetRunStatus{
		Phase: "Preparing", StartedAt: &started, ScheduleRef: &reference,
		ScheduleSummary: &attacknetv1beta1.ScheduleSummary{NetworkUID: string(network.UID), NetworkGeneration: network.Generation, NetworkInventory: schedule.Network.Inventory},
	}
	if err := kube.Status().Update(context.Background(), storedRun); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10, 0)
	firstController := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now }, Observations: staticObservationReader{}}
	if _, err := firstController.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	children := &attacknetv1beta1.FaultCampaignList{}
	if err := kube.List(context.Background(), children); err != nil {
		t.Fatal(err)
	}
	if len(children.Items) != 1 || children.Items[0].Annotations[betaExecutionAnnotation] != "first" {
		t.Fatalf("first eligible execution was not created deterministically: %#v", children.Items)
	}
	child := children.Items[0].DeepCopy()
	child.UID = "child-first-uid"
	if err := kube.Update(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: child.Namespace, Name: child.Name}, child); err != nil {
		t.Fatal(err)
	}
	completed := metav1.NewTime(time.Unix(20, 0))
	child.Status.Phase = "Passed"
	child.Status.CompletedAt = &completed
	child.Status.Cleanup = &attacknetv1beta1.CleanupEvidence{Absent: true, AllRecovered: true, ObservedAt: completed}
	if err := kube.Status().Update(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), key, storedRun); err != nil {
		t.Fatal(err)
	}
	// Simulate a controller crash after the child create reached the API server
	// but before the run-status receipt write. The owner-bound child annotation
	// is the durable recovery source.
	storedRun.Status.TriggerReceipts = nil
	if err := kube.Status().Update(context.Background(), storedRun); err != nil {
		t.Fatal(err)
	}

	// Constructing a fresh reconciler proves no in-memory queue is required to
	// resume from the sealed schedule and durable child status.
	now = time.Unix(30, 0)
	restarted := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now }, Observations: staticObservationReader{}}
	if _, err := restarted.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	children = &attacknetv1beta1.FaultCampaignList{}
	if err := kube.List(context.Background(), children); err != nil {
		t.Fatal(err)
	}
	if len(children.Items) != 2 {
		_ = kube.Get(context.Background(), key, storedRun)
		t.Fatalf("restart did not advance the completed dependency: status=%#v children=%#v", storedRun.Status, children.Items)
	}
	foundSecond := false
	for _, item := range children.Items {
		foundSecond = foundSecond || item.Annotations[betaExecutionAnnotation] == "second"
	}
	if !foundSecond {
		t.Fatal("second DAG execution was not created after the first became Terminal")
	}
	if err := kube.Get(context.Background(), key, storedRun); err != nil {
		t.Fatal(err)
	}
	if len(storedRun.Status.Decisions) != 1 || len(storedRun.Status.TriggerReceipts) != 2 || len(storedRun.Status.ActiveChildren) != 1 {
		t.Fatalf("durable decisions/receipts/active set are incomplete: %#v", storedRun.Status)
	}
}

func TestBetaReconcilerReportsTransientSignerSetObservationAsPending(t *testing.T) {
	run, _, _, templates, _ := betaScheduleFixture()
	run.Finalizers = []string{betaRunFinalizer}
	network, stacksPod, bitcoinPod := betaLiveNetworkFixture(t)
	run.Spec.NetworkRef = network.Name

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = attacknetv1beta1.AddToScheme(scheme)
	objects := []client.Object{run, network, stacksPod, bitcoinPod, templates["partition"]}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.AttacknetRun{}, &attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(objects...).Build()
	transient := &signerset.TransientError{Err: errors.New("HTTP 404: No such chain tip")}
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme, SignerSets: errorSignerResolver{err: transient}}
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: run.Namespace, Name: run.Name}})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != betaDependencyRequeue {
		t.Fatalf("transient observation requeue = %s, want %s", result.RequeueAfter, betaDependencyRequeue)
	}
	updated := &attacknetv1beta1.AttacknetRun{}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: run.Namespace, Name: run.Name}, updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Phase != "Pending" || updated.Status.Reason != "SignerSetObservationPending" || updated.Status.Message != transient.Error() {
		t.Fatalf("transient signer-set observation was not reported truthfully: %#v", updated.Status)
	}
}

func TestBetaRunDeletionWaitsForOwnedCampaignFinalizers(t *testing.T) {
	run, _, _, _, _ := betaScheduleFixture()
	run.Finalizers = []string{betaRunFinalizer}
	now := metav1.Now()
	run.DeletionTimestamp = &now
	child := &attacknetv1beta1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{
		Name: "child", Namespace: run.Namespace, Finalizers: []string{"testing.stacks.org/fault-cleanup"},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(run, attacknetv1beta1.GroupVersion.WithKind("AttacknetRun"))},
	}}
	scheme := runtime.NewScheme()
	_ = attacknetv1beta1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(run, child).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube}
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: clientKey(run)})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter == 0 {
		t.Fatal("run deletion did not wait for owned campaign cleanup")
	}
}

func TestBetaTerminalRunReleasesCleanupFinalizer(t *testing.T) {
	run, _, _, _, _ := betaScheduleFixture()
	run.Finalizers = []string{betaRunFinalizer}
	now := metav1.Now()
	run.Status.Phase = "Passed"
	run.Status.Cleanup = &attacknetv1beta1.RunCleanup{
		Required: true, Completed: true, CompletedAt: &now, Message: "all owned child campaigns proved cleanup",
	}
	scheme := runtime.NewScheme()
	_ = attacknetv1beta1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.AttacknetRun{}).
		WithObjects(run).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Now: func() time.Time { return now.Time }}
	key := clientKey(run)
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	current := &attacknetv1beta1.AttacknetRun{}
	if err := kube.Get(context.Background(), key, current); err != nil {
		t.Fatal(err)
	}
	if containsString(current.Finalizers, betaRunFinalizer) {
		t.Fatal("terminal v1beta1 run retained its cleanup finalizer")
	}
}

func TestBetaChildrenHydratesStaleListEntriesWithExactReads(t *testing.T) {
	run, _, _, _, _ := betaScheduleFixture()
	run.UID = "run-uid"
	child := &attacknetv1beta1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{
		Name: "child", Namespace: run.Namespace, UID: "child-uid", ResourceVersion: "20",
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(run, attacknetv1beta1.GroupVersion.WithKind("AttacknetRun"))},
	}}
	child.Status.Phase = "Running"
	stale := child.DeepCopy()
	stale.ResourceVersion = "10"
	stale.Status.Phase = "Admitted"
	run.Status.ActiveChildren = []attacknetv1beta1.ActiveRunChild{{Name: child.Name, UID: string(child.UID)}}
	scheme := runtime.NewScheme()
	_ = attacknetv1beta1.AddToScheme(scheme)
	direct := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(child).Build()
	reconciler := &V1Beta1Reconciler{APIReader: staleCampaignListReader{Reader: direct, items: []attacknetv1beta1.FaultCampaign{*stale}}}
	children, err := reconciler.children(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 1 || children[0].ResourceVersion != "20" || children[0].Status.Phase != "Running" {
		t.Fatalf("stale list snapshot was trusted instead of exact child GET: %#v", children)
	}
}

func TestBetaStopRequestsCleanupForQueuedCampaigns(t *testing.T) {
	run, _, _, _, _ := betaScheduleFixture()
	child := &attacknetv1beta1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{
		Name: "queued", Namespace: run.Namespace,
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(run, attacknetv1beta1.GroupVersion.WithKind("AttacknetRun"))},
	}}
	scheme := runtime.NewScheme()
	_ = attacknetv1beta1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(child).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube}
	if err := reconciler.requestChildCleanup(context.Background(), []attacknetv1beta1.FaultCampaign{*child}); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1beta1.FaultCampaign{}
	if err := kube.Get(context.Background(), clientKey(child), observed); !apierrors.IsNotFound(err) {
		t.Fatalf("queued campaign survived a terminal stop request: %v", err)
	}
}

func TestBetaRunAllowsOnlyDurablyActivePodKillIdentityTransitions(t *testing.T) {
	child := attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{betaExecutionAnnotation: "kill"}},
		Spec: attacknetv1beta1.FaultCampaignSpec{Stages: []attacknetv1beta1.FaultStageSpec{{
			ID: "stage", Faults: []attacknetv1beta1.FaultActionSpec{{
				ID: "action", Fault: attacknetv1beta1.FaultSpec{Type: "pod", Action: "pod-kill"},
			}},
		}}},
		Status: attacknetv1beta1.FaultCampaignStatus{
			Phase: "Running",
			Stages: []attacknetv1beta1.FaultStageStatus{{ID: "stage", Actions: []attacknetv1beta1.FaultActionStatus{{
				ID: "action", Phase: "Injecting", Mutation: &attacknetv1beta1.ChaosReference{Kind: "PodChaos", Name: "kill"},
				ResolvedTargets: []attacknetv1beta1.ResolvedTarget{{Actor: "miner-1"}},
			}}}},
		},
	}
	if _, ok := betaAllowedPodTransitions([]attacknetv1beta1.FaultCampaign{child}, map[string]bool{})["miner-1"]; !ok {
		t.Fatal("active run-owned pod-kill did not permit its target Pod identity transition")
	}

	withoutMutation := child.DeepCopy()
	withoutMutation.Status.Stages[0].Actions[0].Mutation = nil
	if len(betaAllowedPodTransitions([]attacknetv1beta1.FaultCampaign{*withoutMutation}, map[string]bool{})) != 0 {
		t.Fatal("Pod identity was relaxed before the mutation was durably recorded")
	}

	admitted := child.DeepCopy()
	admitted.Status.Phase = "Admitted"
	if len(betaAllowedPodTransitions([]attacknetv1beta1.FaultCampaign{*admitted}, map[string]bool{})) != 0 {
		t.Fatal("Pod identity was relaxed before the campaign entered its running phase")
	}

	if len(betaAllowedPodTransitions([]attacknetv1beta1.FaultCampaign{child}, map[string]bool{"kill": true})) != 0 {
		t.Fatal("completed run decision retained a Pod identity transition allowance")
	}
}

func TestBetaDependencyEffectiveAcceptsProvenControllerEvidence(t *testing.T) {
	observed := time.Unix(50, 0).UTC()
	raw, err := betaJSON(map[string]any{"outcome": "Proven", "observedAt": observed})
	if err != nil {
		t.Fatal(err)
	}
	child := &attacknetv1beta1.FaultCampaign{Status: attacknetv1beta1.FaultCampaignStatus{
		Stages: []attacknetv1beta1.FaultStageStatus{{EffectResults: []apixv1.JSON{raw}}},
	}}
	got, ok := childEffectiveAt(child)
	if !ok || !got.Equal(observed) {
		t.Fatalf("Proven effect evidence was not recognized: at=%v ok=%t", got, ok)
	}
}

func betaLiveNetworkFixture(t *testing.T) (*attacknetv1beta1.StacksNetwork, *corev1.Pod, *corev1.Pod) {
	t.Helper()
	imageID := "containerd://sha256:" + repeat("a", 64)
	bitcoinImageID := "containerd://sha256:" + repeat("b", 64)
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: "network-uid", Generation: 3, ResourceVersion: "1"},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Defaults: attacknetv1beta1.NetworkDefaults{NodeImage: "stacks:test", BitcoinImage: "bitcoin:test"},
			Burnchain: attacknetv1beta1.BurnchainTopologySpec{
				PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "burnchain-policy"},
				Nodes: []attacknetv1beta1.BitcoinNodeSpec{{
					Name: "bitcoin-1", Config: attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "bitcoin-regtest/v1"}},
				}},
			},
			Nodes: []attacknetv1beta1.StacksNodeSpec{{
				Name: "miner-1", Role: attacknetv1beta1.StacksNodeFollower, BurnchainNodeRef: "bitcoin-1",
				Config: attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "nakamoto-regtest-node/v1"}},
			}},
		},
		Status: attacknetv1beta1.StacksNetworkStatus{
			Phase: "Ready", ObservedGeneration: 3, InventoryReady: true,
			Actors: []attacknetv1beta1.ActorStatus{{
				Name: "bitcoin-1", Role: "burnchain", ResourceName: "demo-bitcoin-1", Image: "bitcoin:test",
				Ready: true, ReadyReplicas: 1, UpdatedReplicas: 1, Generation: 1, ObservedGeneration: 1,
				CurrentRevision: "btc-rev-1", UpdateRevision: "btc-rev-1", ServiceName: "demo-bitcoin-1", StatefulSetUID: "btc-sts-1",
				PodName: "demo-bitcoin-1-0", PodUID: "btc-pod-1", RuntimeImageID: bitcoinImageID, IdentityReady: true,
			}, {
				Name: "miner-1", Role: "follower", ResourceName: "demo-miner-1", Image: "stacks:test",
				Ready: true, ReadyReplicas: 1, UpdatedReplicas: 1, Generation: 1, ObservedGeneration: 1,
				CurrentRevision: "rev-1", UpdateRevision: "rev-1", ServiceName: "demo-miner-1", StatefulSetUID: "sts-1",
				PodName: "demo-miner-1-0", PodUID: "pod-1", RuntimeImageID: imageID, IdentityReady: true,
			}},
		},
	}
	legacy := &attacknetv1alpha1.StacksNetwork{
		ObjectMeta: *network.ObjectMeta.DeepCopy(),
		Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{
			{Name: "bitcoin-1", Role: "burnchain"}, {Name: "miner-1", Role: "follower"},
		}},
		Status: attacknetv1alpha1.StacksNetworkStatus{ObservedGeneration: 3, InventoryReady: true, Actors: []attacknetv1alpha1.ActorStatus{
			{Name: "bitcoin-1", Role: "burnchain", ResourceName: "demo-bitcoin-1", Image: "bitcoin:test", ServiceName: "demo-bitcoin-1", StatefulSetUID: "btc-sts-1", CurrentRevision: "btc-rev-1", PodName: "demo-bitcoin-1-0", PodUID: "btc-pod-1", RuntimeImageID: bitcoinImageID, IdentityReady: true},
			{Name: "miner-1", Role: "follower", ResourceName: "demo-miner-1", Image: "stacks:test", ServiceName: "demo-miner-1", StatefulSetUID: "sts-1", CurrentRevision: "rev-1", PodName: "demo-miner-1-0", PodUID: "pod-1", RuntimeImageID: imageID, IdentityReady: true},
		}},
	}
	payload, err := inventory.Build(legacy)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.BurnchainTopology, err = burnchaintopology.Build(network, map[string]string{"burnchain-policy": "clock-uid"})
	if err != nil {
		t.Fatal(err)
	}
	minerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-miner-1-0", Namespace: "test", UID: "pod-1", Labels: map[string]string{"testing.stacks.org/network": "network", "testing.stacks.org/actor": "miner-1"}},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", ImageID: imageID}}},
	}
	bitcoinPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-bitcoin-1-0", Namespace: "test", UID: "btc-pod-1", Labels: map[string]string{"testing.stacks.org/network": "network", "testing.stacks.org/actor": "bitcoin-1"}},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", ImageID: bitcoinImageID}}},
	}
	return network, minerPod, bitcoinPod
}

func networkInventory(network *attacknetv1beta1.StacksNetwork) *attacknetv1beta1.NetworkInventory {
	result, err := inventory.BetaPublished(network)
	if err != nil {
		panic(err)
	}
	return &result
}
