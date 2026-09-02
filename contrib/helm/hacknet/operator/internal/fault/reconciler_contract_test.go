package fault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestPodEffectResultsRequireActionSpecificEvidence(t *testing.T) {
	ready := effectPod("pod-uid", true, 2)
	unready := effectPod("pod-uid", false, 2)
	restarted := effectPod("pod-uid", true, 3)
	replacement := effectPod("replacement-uid", true, 0)

	tests := []struct {
		name, action, want string
		pods               []corev1.Pod
	}{
		{name: "pod kill requires admitted uid disappearance", action: "pod-kill", pods: []corev1.Pod{replacement}, want: "Proven"},
		{name: "pod failure requires same admitted uid to be unready", action: "pod-failure", pods: []corev1.Pod{unready}, want: "Proven"},
		{name: "pod failure cannot use replacement as proof", action: "pod-failure", pods: []corev1.Pod{replacement}, want: "Inconclusive"},
		{name: "container kill requires restart count", action: "container-kill", pods: []corev1.Pod{restarted}, want: "Proven"},
		{name: "container kill cannot use pod replacement", action: "container-kill", pods: []corev1.Pod{replacement}, want: "Inconclusive"},
		{name: "unchanged ready pod is not evidence", action: "pod-kill", pods: []corev1.Pod{ready}, want: "Failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			campaign := effectCampaign(test.action)
			results := podEffectResults(campaign, test.pods, time.Unix(10, 0))
			if len(results) != 1 {
				t.Fatalf("result count = %d, want 1", len(results))
			}
			value := map[string]any{}
			if err := json.Unmarshal(results[0].Raw, &value); err != nil {
				t.Fatal(err)
			}
			if value["outcome"] != test.want {
				t.Fatalf("outcome = %v, want %s; result=%s", value["outcome"], test.want, results[0].Raw)
			}
		})
	}
}

func TestAssertionTimeoutUsesExplicitBoundAndFallsBackOnlyWhenAbsent(t *testing.T) {
	assertions := []attacknetv1alpha1.CampaignAssertion{
		{Type: "First", TimeoutSeconds: 20},
		{Type: "Second", TimeoutSeconds: 45},
	}
	if got := assertionTimeout(assertions, 5*time.Minute); got != 45*time.Second {
		t.Fatalf("explicit assertion timeout = %s, want 45s", got)
	}
	if got := assertionTimeout(nil, 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("fallback assertion timeout = %s, want 5m", got)
	}
}

func TestZeroInjectionFinalizerAbortRequiresExactFailedRecords(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	deleting := metav1.NewTime(now.Add(-31 * time.Second))
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "io", Namespace: "test", UID: types.UID("campaign-uid")},
		Spec: attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "network", Fault: attacknetv1alpha1.FaultSpec{
			Type: "io", Parameters: apixv1.JSON{Raw: []byte(`{"containerNames":["actor"]}`)},
		}},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase: "Failed", Reason: "InjectionFailed",
			ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{{Pod: "network-miner-1-0"}},
		},
	}
	resource := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"experiment": map[string]any{
				"containerRecords": []any{map[string]any{
					"id": "test/network-miner-1-0/actor", "phase": "Not Injected/Wait",
					"injectedCount": float64(0), "recoveredCount": float64(0),
					"events": []any{map[string]any{"type": "Failed", "operation": "Apply"}},
				}},
			},
		},
	}}
	resource.SetDeletionTimestamp(&deleting)
	if !zeroInjectionFinalizerAbortSafe(campaign, resource, now) {
		t.Fatal("exact zero-injection failure was not recognized as safe finalizer cleanup")
	}
	if err := unstructured.SetNestedField(resource.Object, int64(1), "status", "experiment", "containerRecords", "0", "injectedCount"); err == nil {
		// SetNestedField cannot index slices; mutate the record directly below.
	}
	records, _, _ := unstructured.NestedSlice(resource.Object, "status", "experiment", "containerRecords")
	records[0].(map[string]any)["injectedCount"] = float64(1)
	_ = unstructured.SetNestedSlice(resource.Object, records, "status", "experiment", "containerRecords")
	if zeroInjectionFinalizerAbortSafe(campaign, resource, now) {
		t.Fatal("cleanup was allowed after a record reported an injected target")
	}
}

func TestMutationContractRejectsForeignOwnershipAndAcceptsAPIDefaults(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{UID: types.UID("campaign-uid")}}
	desired := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "chaos-mesh.org/v1alpha1", "kind": "NetworkChaos",
		"metadata": map[string]any{"name": "fault", "namespace": "test", "labels": map[string]any{"testing.stacks.org/network": "network"}},
		"spec":     map[string]any{"action": "partition", "mode": "one"},
	}}
	desired.SetOwnerReferences([]metav1.OwnerReference{{UID: campaign.UID, Controller: ptr(true)}})
	observed := desired.DeepCopy()
	observed.SetUID(types.UID("mutation-uid"))
	_ = unstructured.SetNestedField(observed.Object, "defaulted", "spec", "direction")
	if err := requireCampaignOwner(campaign, observed); err != nil {
		t.Fatalf("campaign-owned mutation was rejected: %v", err)
	}
	if !mutationDesiredMatches("NetworkChaos", desired, observed) {
		t.Fatal("API-defaulted mutation no longer satisfies the desired execution contract")
	}
	observed.SetOwnerReferences([]metav1.OwnerReference{{UID: types.UID("foreign"), Controller: ptr(true)}})
	if err := requireCampaignOwner(campaign, observed); err == nil {
		t.Fatal("foreign mutation ownership was accepted")
	}
	_ = unstructured.SetNestedField(observed.Object, "delay", "spec", "action")
	if mutationDesiredMatches("NetworkChaos", desired, observed) {
		t.Fatal("mutation with a changed requested action was accepted")
	}
}

func TestMutationContractAndLeaseChecksBypassStaleCache(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "campaign", Namespace: "test", UID: types.UID("campaign-uid")},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition"},
		},
	}
	gvk := schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"}
	oldMutation := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "chaos-mesh.org/v1alpha1", "kind": "NetworkChaos",
		"metadata": map[string]any{"name": "campaign", "namespace": "test"},
		"spec":     map[string]any{"action": "partition", "mode": "one"},
	}}
	oldMutation.SetGroupVersionKind(gvk)
	oldMutation.SetUID(types.UID("mutation-uid"))
	contract, err := mutationContract("NetworkChaos", oldMutation)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonical.ArtifactDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	campaign.Status.Chaos = &attacknetv1alpha1.ChaosReference{UID: "mutation-uid", ResourceDigest: digest}
	liveMutation := oldMutation.DeepCopy()
	if err := unstructured.SetNestedField(liveMutation.Object, "delay", "spec", "action"); err != nil {
		t.Fatal(err)
	}
	environment := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: environmentLease, Namespace: "test"},
		Data:       map[string]string{"network": "network"},
	}
	ownedLease := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: mutationLease, Namespace: "test"},
		Data: map[string]string{
			"network": "network", "owner": "faultcampaign:campaign-uid", "token": "campaign-uid",
		},
	}
	foreignLease := ownedLease.DeepCopy()
	foreignLease.Data = map[string]string{
		"network": "network", "owner": "faultcampaign:other", "token": "other",
	}
	cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(oldMutation, environment, ownedLease).Build()
	direct := fake.NewClientBuilder().WithScheme(scheme).WithObjects(liveMutation, environment.DeepCopy(), foreignLease).Build()
	reconciler := &Reconciler{Client: cached, APIReader: direct, Scheme: scheme}
	if _, _, err := reconciler.getMutation(context.Background(), campaign); err == nil || !strings.Contains(err.Error(), "execution contract changed") {
		t.Fatalf("live mutation-contract divergence was not detected: %v", err)
	}
	lease, err := reconciler.holdMutationLease(context.Background(), campaign, false)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Held {
		t.Fatal("stale cached ownership hid a live mutation-lease change")
	}
}

func TestCampaignFreshnessBarrierRejectsInformerDelayedState(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cachedCampaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name: "campaign", Namespace: "test", ResourceVersion: "1",
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Recovering"},
	}
	liveCampaign := cachedCampaign.DeepCopy()
	liveCampaign.ResourceVersion = "2"
	liveCampaign.Status.Phase = "Passed"
	direct := fake.NewClientBuilder().WithScheme(scheme).WithObjects(liveCampaign).Build()
	reconciler := &Reconciler{APIReader: direct}

	current, err := reconciler.campaignIsCurrent(context.Background(), cachedCampaign)
	if err != nil {
		t.Fatal(err)
	}
	if current {
		t.Fatal("an informer-delayed campaign could reverse a newer terminal phase")
	}
	current, err = reconciler.campaignIsCurrent(context.Background(), liveCampaign)
	if err != nil {
		t.Fatal(err)
	}
	if !current {
		t.Fatal("the live campaign version was rejected")
	}
}

func TestPodChaosContractNormalizesDefaultGracePeriod(t *testing.T) {
	withDefault := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "chaos-mesh.org/v1alpha1", "kind": "PodChaos",
		"metadata": map[string]any{"name": "campaign", "namespace": "test"},
		"spec": map[string]any{
			"action": "pod-kill", "mode": "all", "duration": "5s",
			"gracePeriod": int64(0), "selector": map[string]any{"namespaces": []any{"test"}},
		},
	}}
	omitted := withDefault.DeepCopy()
	delete(omitted.Object["spec"].(map[string]any), "gracePeriod")
	first, err := mutationContract("PodChaos", withDefault)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mutationContract("PodChaos", omitted)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := canonical.ArtifactDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := canonical.ArtifactDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("default grace period changed the execution contract: %s != %s", firstDigest, secondDigest)
	}
}

func TestClockPolicyAcceptsOnlyItsExpectedRecoveringReset(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "clock", Namespace: "test", UID: types.UID("campaign-uid")},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "clock-skew", Parameters: apixv1.JSON{Raw: []byte(`{"timeOffset":"-30s"}`)}},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase:           "Recovering",
			ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{{Actor: "follower-1"}},
			Chaos:           &attacknetv1alpha1.ChaosReference{UID: "policy-uid", ResourceDigest: "sha256:" + strings.Repeat("a", 64)},
			Cleanup:         &attacknetv1alpha1.CleanupEvidence{Method: "ClockPolicyReset"},
		},
	}
	policy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-clock-policy", Namespace: "test", UID: types.UID("policy-uid"),
			Labels: map[string]string{NetworkLabel: "network", "testing.stacks.org/clock-policy": "true"},
		},
		Data: map[string]string{"follower-1": clockPolicyZero, "miner-1": clockPolicyZero},
	}
	reconciler := &Reconciler{APIReader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()}
	if _, _, err := reconciler.getMutation(context.Background(), campaign); err != nil {
		t.Fatalf("expected recovering reset was rejected: %v", err)
	}

	policy.Data["follower-1"] = "+1s\n"
	reconciler.APIReader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	if _, _, err := reconciler.getMutation(context.Background(), campaign); err == nil || !strings.Contains(err.Error(), "execution contract changed") {
		t.Fatalf("unexpected recovering policy state was accepted: %v", err)
	}
}

func TestTerminalClockCampaignDoesNotResetACompletedSharedPolicyAgain(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "old-clock", Namespace: "test", UID: types.UID("old-campaign")},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "clock-skew", Parameters: apixv1.JSON{Raw: []byte(`{"timeOffset":"-30s"}`)}},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase:           "Inconclusive",
			ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{{Actor: "follower-1"}},
			Cleanup:         &attacknetv1alpha1.CleanupEvidence{Absent: true, AllRecovered: true, Method: "ClockPolicyReset"},
		},
	}
	policy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "network-clock-policy", Namespace: "test", UID: types.UID("policy-uid")},
		Data:       map[string]string{"follower-1": "-15s\n"},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(campaign).WithObjects(campaign, policy).Build()
	reconciler := &Reconciler{Client: kubeClient, APIReader: kubeClient}
	if err := reconciler.reconcileTerminal(t.Context(), campaign); err != nil {
		t.Fatal(err)
	}
	current := &corev1.ConfigMap{}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(policy), current); err != nil {
		t.Fatal(err)
	}
	if current.Data["follower-1"] != "-15s\n" {
		t.Fatalf("terminal campaign rewrote a newer policy: %#v", current.Data)
	}
}

func TestAdmissionBindsTheEntireCampaignSpec(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Generation: 4},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition", Mode: "one", Duration: "30s"},
			Safety:     attacknetv1alpha1.FaultSafety{MaxUnavailableSignerPercent: 30},
		},
	}
	network := &attacknetv1alpha1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{UID: types.UID("network-uid"), Generation: 3}}
	specDigest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		t.Fatal(err)
	}
	admission := &attacknetv1alpha1.CampaignAdmission{
		NetworkUID: "network-uid", NetworkGeneration: 3,
		CampaignGeneration: 4, CampaignSpecDigest: specDigest,
		CompiledDigest: "sha256:compiled",
	}
	if !admissionMatches(admission, campaign, network, "sha256:compiled", specDigest) {
		t.Fatal("exact admission inputs did not match")
	}
	campaign.Spec.Safety.MaxUnavailableSignerPercent = 40
	changedDigest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if admissionMatches(admission, campaign, network, "sha256:compiled", changedDigest) {
		t.Fatal("a safety-policy edit escaped the post-admission barrier")
	}
}

func TestIOPressurePodRetainsTrustedExecutionContract(t *testing.T) {
	fsGroup := int64(1000)
	image := "example.invalid/stacks@sha256:" + strings.Repeat("a", 64)
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "pressure", Namespace: "test", UID: types.UID("campaign-uid")},
		Spec:       attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "network", Fault: attacknetv1alpha1.FaultSpec{Duration: "30s"}},
		Status:     attacknetv1alpha1.FaultCampaignStatus{ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{{Actor: "miner-1", Pod: "network-miner-1-0", PodUID: "pod-uid", Node: "worker"}}},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "network-miner-1-0", Namespace: "test", UID: types.UID("pod-uid")},
		Spec: corev1.PodSpec{
			NodeName: "worker", SecurityContext: &corev1.PodSecurityContext{FSGroup: &fsGroup},
			Containers: []corev1.Container{{Name: "actor", Image: image, VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}},
			Volumes:    []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "network-miner-1-data"}}}},
		},
	}
	compiled := Compiled{Evidence: Evidence{IOPressure: map[string]any{"severity": "medium", "workers": float64(2), "bytesMiB": float64(64), "writeSizeKiB": float64(256)}}}
	reconciler := &Reconciler{IOPressureImage: "example.invalid/io-pressure@sha256:" + strings.Repeat("b", 64)}
	pressure, err := reconciler.buildIOPressurePod(campaign, []corev1.Pod{pod}, compiled)
	if err != nil {
		t.Fatal(err)
	}
	container := pressure.Spec.Containers[0]
	if pressure.Spec.SecurityContext.FSGroupChangePolicy == nil || *pressure.Spec.SecurityContext.FSGroupChangePolicy != corev1.FSGroupChangeOnRootMismatch {
		t.Fatal("fsGroupChangePolicy is not pinned to OnRootMismatch")
	}
	if container.Resources.Requests.Cpu().String() != "50m" || container.Resources.Limits.Memory().String() != "64Mi" {
		t.Fatalf("unexpected medium-severity resources: %#v", container.Resources)
	}
	if pressure.Annotations["testing.stacks.org/target-pod-uid"] != "pod-uid" || pressure.Annotations["testing.stacks.org/target-pvc"] != "network-miner-1-data" {
		t.Fatalf("trusted target identity was not embedded: %#v", pressure.Annotations)
	}
	if !mutationDesiredMatches("IOPressurePod", pressure, pressure.DeepCopy()) {
		t.Fatal("identical I/O-pressure execution contracts did not match")
	}
}

func effectCampaign(action string) *attacknetv1alpha1.FaultCampaign {
	return &attacknetv1alpha1.FaultCampaign{
		Spec:   attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "network", Fault: attacknetv1alpha1.FaultSpec{Type: "pod", Action: action, Mode: "one"}},
		Status: attacknetv1alpha1.FaultCampaignStatus{ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{{Actor: "miner-1", Pod: "network-miner-1-0", PodUID: "pod-uid", RestartCount: 2}}},
	}
}

func effectPod(uid string, ready bool, restartCount int32) corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "network-miner-1-0", Namespace: "test", UID: types.UID(uid), Labels: map[string]string{NetworkLabel: "network", ActorLabel: "miner-1"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", Ready: ready, RestartCount: restartCount}}},
	}
}
