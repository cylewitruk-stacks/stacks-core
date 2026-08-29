package fault

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchainworker"
)

func TestBurnchainReorgWorkerContractIgnoresOnlySchedulerPlacement(t *testing.T) {
	t.Parallel()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "test", UID: types.UID("worker-uid"), Labels: map[string]string{"testing.stacks.org/action": "replace"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Image: "worker@sha256:" + strings.Repeat("a", 64)}}},
	}
	before, err := burnchainReorgPodContract(pod)
	if err != nil {
		t.Fatal(err)
	}
	scheduled := pod.DeepCopy()
	scheduled.Spec.NodeName = "worker-node-2"
	after, err := burnchainReorgPodContract(scheduled)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("scheduler placement changed the immutable worker contract")
	}
	tampered := scheduled.DeepCopy()
	tampered.Spec.Containers[0].Image = "worker@sha256:" + strings.Repeat("b", 64)
	changed, err := burnchainReorgPodContract(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, changed) {
		t.Fatal("worker image tampering was excluded from the immutable contract")
	}
}

func TestBurnchainReorgWorkerPausesAndRestoresExactPolicy(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &attacknetv1beta1.BurnchainPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "clock", Namespace: "test", UID: types.UID("policy-uid"), Generation: 1},
		Spec: attacknetv1beta1.BurnchainPolicySpec{
			NetworkRef: "network", BitcoinNodeRef: "bitcoin-1", Cadence: metav1.Duration{Duration: time.Minute},
			Destinations:     []attacknetv1beta1.BurnchainDestinationSpec{{WalletName: "miner", Address: "bcrt1qattacknet"}},
			ProtocolSchedule: &attacknetv1beta1.BurnchainProtocolSchedule{Epochs: []attacknetv1beta1.BurnchainEpochBoundary{{Name: "nakamoto", StartHeight: 225}}},
		},
		Status: attacknetv1beta1.BurnchainPolicyStatus{ObservedGeneration: 1, Phase: "Ready", ObservedHeight: 300},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).WithStatusSubresource(policy).Build()
	reconciler := &V1Beta1Reconciler{Client: client, APIReader: client, Scheme: scheme, ReorgWorkerImage: "run-operator@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReorgWorkerPull: corev1.PullIfNotPresent}
	campaign := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "campaign", Namespace: "test", UID: types.UID("campaign-uid")},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{
				ID: "reorg",
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "replace", Target: attacknetv1beta1.FaultTarget{Actors: []string{"bitcoin-1"}, Mode: "one"},
					Fault: attacknetv1beta1.FaultSpec{Type: "burnchain-reorg", Mode: "one", Duration: metav1.Duration{Duration: time.Second}, BurnchainReorg: &attacknetv1beta1.BurnchainReorgFaultSpec{Depth: 2, ReplacementBlocks: 3}},
				}},
			}},
			Safety: attacknetv1beta1.FaultSafety{AllowBurnchain: true, MaxBurnchainReorgDepth: 2, MaxBurnchainReplacementBlocks: 3},
		},
	}
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test"},
		Spec:       attacknetv1beta1.StacksNetworkSpec{Defaults: attacknetv1beta1.NetworkDefaults{}, Burnchain: attacknetv1beta1.BurnchainTopologySpec{PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "clock"}, Nodes: []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin-1", RPCPort: 18443}}}},
		Status: attacknetv1beta1.StacksNetworkStatus{Actors: []attacknetv1beta1.ActorStatus{{
			Name: "bitcoin-1", Role: "burnchain", ServiceName: "network-bitcoin-1", IdentityReady: true,
		}}},
	}
	graph, err := burnchaintopology.Build(network, map[string]string{"clock": "policy-uid"})
	if err != nil {
		t.Fatal(err)
	}
	network.Status.BurnchainTopology = graph
	resource := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "testing.stacks.org/internal", "kind": "BurnchainReorgWorker",
		"metadata": map[string]any{"name": "campaign-reorg-replace", "namespace": "test", "labels": map[string]any{"testing.stacks.org/stage": "reorg"}},
		"spec":     map[string]any{"actor": "bitcoin-1"},
	}}
	status := &attacknetv1beta1.FaultActionStatus{ID: "replace"}
	podObject, err := reconciler.createBurnchainReorgMutation(context.Background(), campaign, network, CompiledAction{ID: "replace", Resource: resource}, status)
	if err != nil {
		t.Fatal(err)
	}
	pod := podObject.(*corev1.Pod)
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken || pod.Spec.Containers[0].SecurityContext == nil || pod.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation == nil || *pod.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("worker security boundary is incomplete: %#v", pod.Spec)
	}
	adopted, err := reconciler.createBurnchainReorgMutation(context.Background(), campaign, network, CompiledAction{ID: "replace", Resource: resource}, status)
	if err != nil || adopted.GetName() != pod.Name {
		t.Fatalf("owned worker was not adopted after a status-persistence restart window: %v %#v", err, adopted)
	}
	current := &attacknetv1beta1.BurnchainPolicy{}
	tampered := &corev1.Pod{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Spec.Containers[0].Image = "untrusted@sha256:" + strings.Repeat("b", 64)
	if err := client.Update(context.Background(), tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.createBurnchainReorgMutation(context.Background(), campaign, network, CompiledAction{ID: "replace", Resource: resource}, status); err == nil || !strings.Contains(err.Error(), "different owner or execution contract") {
		t.Fatalf("tampered existing worker was adopted: %v", err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil || current.Spec.Paused {
		t.Fatalf("worker creation mutated policy before its status was durable: %#v %v", current.Spec, err)
	}
	tampered.Spec.Containers[0].Image = reconciler.ReorgWorkerImage
	if err := client.Update(context.Background(), tampered); err != nil {
		t.Fatal(err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil || current.Spec.Paused {
		t.Fatalf("inert worker unexpectedly paused policy: %#v %v", current.Spec, err)
	}
	recovery, err := betaRecoveryContract("BurnchainReorgWorker", pod)
	if err != nil {
		t.Fatal(err)
	}
	status.Mutation = &attacknetv1beta1.ChaosReference{Kind: "BurnchainReorgWorker", RecoveryContract: recovery}
	if err := reconciler.approveReorgPreparation(context.Background(), campaign, status, pod); err != nil {
		t.Fatal(err)
	}
	unprepared := &corev1.Pod{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, unprepared); err != nil {
		t.Fatal(err)
	}
	if unprepared.Annotations[reorgPreparationAnnotation] != "" {
		t.Fatal("worker preparation was approved before the paused policy was acknowledged")
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil {
		t.Fatal(err)
	}
	if !current.Spec.Paused {
		t.Fatal("preparation handshake did not pause the burnchain policy")
	}
	// The fake client does not increment metadata.generation on a spec update;
	// model the API server's generation barrier explicitly.
	current.Generation++
	if err := client.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil {
		t.Fatal(err)
	}
	current.Status.ObservedGeneration = current.Generation
	current.Status.Phase = "Ready"
	current.Status.AppliedPolicyDigest = "sha256:" + strings.Repeat("b", 64)
	if err := client.Status().Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.approveReorgPreparation(context.Background(), campaign, status, pod); err != nil {
		t.Fatal(err)
	}
	preparedPod := &corev1.Pod{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, preparedPod); err != nil {
		t.Fatal(err)
	}
	if preparedPod.Annotations[reorgPreparationAnnotation] != current.Status.AppliedPolicyDigest {
		t.Fatalf("worker preparation was not gated by the applied paused policy: %#v", preparedPod.Annotations)
	}
	prepared := &burnchain.PreparedReorg{
		Digest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Original: burnchain.ChainInfo{Blocks: 300},
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Cadence = metav1.Duration{Duration: 2 * time.Minute}
	if err := client.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.approvePreparedReorg(context.Background(), campaign, &campaign.Spec.Stages[0].Faults[0], status, preparedPod, prepared); err == nil || !strings.Contains(err.Error(), "execution contract changed") {
		t.Fatalf("changed burnchain policy was approved: %v", err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Cadence = metav1.Duration{Duration: time.Minute}
	if err := client.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.approvePreparedReorg(context.Background(), campaign, &campaign.Spec.Stages[0].Faults[0], status, preparedPod, prepared); err != nil {
		t.Fatal(err)
	}
	approved := &corev1.Pod{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, approved); err != nil {
		t.Fatal(err)
	}
	if approved.Annotations[reorgApprovalAnnotation] != prepared.Digest || approved.Annotations[reorgBoundaryAnnotation] == "" {
		t.Fatalf("worker approval did not bind its boundary assessment: %#v", approved.Annotations)
	}
	approved.Status.PodIP = "127.0.0.1"
	reconciler.ReorgHTTPClient = &http.Client{Transport: reorgRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"phase":"Executing"}`))}, nil
	})}
	if err := reconciler.removeBurnchainReorgWorker(context.Background(), campaign, status, approved); !errors.Is(err, errBurnchainReorgWorkerRemovalPending) || !strings.Contains(err.Error(), "worker phase is Executing") {
		t.Fatalf("executing reorg worker was not preserved: %v", err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: approved.Namespace, Name: approved.Name}, &corev1.Pod{}); err != nil {
		t.Fatalf("executing reorg worker was deleted: %v", err)
	}
	reconciler.ReorgHTTPClient = &http.Client{Transport: reorgRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"phase":"Succeeded"}`))}, nil
	})}
	if err := reconciler.removeBurnchainReorgWorker(context.Background(), campaign, status, approved); err != nil {
		t.Fatal(err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "clock"}, current); err != nil || current.Spec.Paused {
		t.Fatalf("policy was not restored: %#v %v", current.Spec, err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: approved.Namespace, Name: approved.Name}, &corev1.Pod{}); err == nil {
		t.Fatal("terminal reorg worker was not deleted before policy restoration")
	}
}

type reorgRoundTripFunc func(*http.Request) (*http.Response, error)

func (function reorgRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestBurnchainReorgFailureRetainsPartialBranchEvidence(t *testing.T) {
	t.Parallel()
	status := &attacknetv1beta1.FaultActionStatus{
		ResolvedTargets: []attacknetv1beta1.ResolvedTarget{{Actor: "bitcoin-1"}},
	}
	workerStatus := burnchainworker.Status{
		SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "Failed", Failure: "injected RPC failure",
		Result: &burnchain.ReorgResult{
			PreparedDigest: "sha256:prepared", Original: burnchain.ChainInfo{BestBlockHash: "original"},
			Receipts: []burnchain.RPCReceipt{{Sequence: 1, Method: "invalidateblock", Outcome: "acknowledged"}},
		},
	}
	reconciler := &V1Beta1Reconciler{Now: func() time.Time { return time.Unix(1, 0).UTC() }}
	if err := reconciler.recordBurnchainReorgFailure(status, workerStatus); err != nil {
		t.Fatal(err)
	}
	if status.ActualInjection == nil || len(status.EffectResults) != 1 ||
		!strings.Contains(string(status.EffectResults[0].Raw), "invalidateblock") ||
		!strings.Contains(string(status.EffectResults[0].Raw), "injected RPC failure") {
		t.Fatalf("partial worker evidence was not retained: %#v", status)
	}
}
