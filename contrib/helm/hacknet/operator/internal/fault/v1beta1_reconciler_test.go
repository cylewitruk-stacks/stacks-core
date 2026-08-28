package fault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

var sharedBetaProbe = &betaProbeClient{calls: map[string]int{}}

type betaProbeClient struct {
	mu           sync.Mutex
	calls        map[string]int
	effectAtCall int
}

func (probe *betaProbeClient) Probe(_ context.Context, target attacknetv1alpha1.ResolvedTarget, request map[string]any) (map[string]any, error) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	kind, _ := request["kind"].(string)
	key := target.Actor + "/" + kind
	call := probe.calls[key]
	probe.calls[key] = call + 1
	effectAtCall := probe.effectAtCall
	if effectAtCall == 0 {
		effectAtCall = 1
	}
	var observation map[string]any
	switch kind {
	case "network":
		latency := float64(10)
		if call == effectAtCall {
			latency = 100
		}
		observation = map[string]any{"actor": target.Actor, "probe": "network", "status": "ok", "probeName": "peer", "peerActor": request["peer"], "attempts": float64(5), "successes": float64(5), "latencyMsP50": latency, "latencyMsP95": latency, "protocolErrors": float64(0)}
	case "dns":
		succeeded := call != effectAtCall
		answers := []any{"10.0.0.2"}
		if !succeeded {
			answers = []any{}
		}
		observation = map[string]any{"actor": target.Actor, "probe": "dns", "status": "ok", "probeName": "dns", "query": "network-bitcoin-1.test.svc.cluster.local", "controlQuery": "kubernetes.default.svc.cluster.local", "querySucceeded": succeeded, "controlSucceeded": true, "answers": answers, "controlAnswers": []any{"10.0.0.10"}}
	case "system":
		observation = map[string]any{"platform": "linux", "architecture": "x64"}
	default:
		return nil, fmt.Errorf("unsupported test probe kind %q", kind)
	}
	return map[string]any{"schemaVersion": "stacks-attacknet-probe-response/v1", "actor": target.Actor, "kind": kind, "observation": observation}, nil
}

func resetBetaProbe() {
	sharedBetaProbe.mu.Lock()
	defer sharedBetaProbe.mu.Unlock()
	sharedBetaProbe.calls = map[string]int{}
}

func TestV1Beta1CampaignInjectsDistinctMechanismsConcurrentlyAndResumes(t *testing.T) {
	resetBetaProbe()
	scheme := betaFaultScheme(t)
	now := time.Date(2026, 8, 25, 22, 0, 0, 0, time.UTC)
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("multi", []attacknetv1beta1.FaultActionSpec{
		betaChaosAction("network", "network", "delay"),
		betaChaosAction("dns", "dns", "error"),
	})
	campaign.Spec.Stages = []attacknetv1beta1.FaultStageSpec{
		{ID: "network-stage", Faults: []attacknetv1beta1.FaultActionSpec{betaChaosAction("network", "network", "delay")}},
		{ID: "dns-stage", Faults: []attacknetv1beta1.FaultActionSpec{betaChaosAction("dns", "dns", "error")}},
	}
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject()).Build()
	request := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: campaign.Namespace, Name: campaign.Name}}
	if err := base.Create(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}

	reconcileBetaUntil(t, base, scheme, request, &now, 3)
	assertBetaPhase(t, base, request.NamespacedName, "Running")
	for _, kind := range []string{"NetworkChaos", "DNSChaos"} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: kind + "List"})
		if err := base.List(context.Background(), list, client.InNamespace("test")); err != nil || len(list.Items) != 1 {
			t.Fatalf("%s was not injected concurrently: count=%d err=%v", kind, len(list.Items), err)
		}
		resource := list.Items[0].DeepCopy()
		resource.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "AllInjected", "status": "True"}}}
		if err := base.Update(context.Background(), resource); err != nil {
			t.Fatal(err)
		}
	}

	// Recreate the reconciler on every pass to prove status is the sole resume state.
	reconcileBetaUntil(t, base, scheme, request, &now, 1)
	now = now.Add(2 * time.Minute)
	reconcileBetaUntil(t, base, scheme, request, &now, 3)
	assertBetaPhase(t, base, request.NamespacedName, "Passed")
}

func TestV1Beta1EffectAssertionRetriesUntilObserved(t *testing.T) {
	scheme := betaFaultScheme(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("delayed-effect", []attacknetv1beta1.FaultActionSpec{
		betaChaosAction("dns", "dns", "error"),
	})
	campaign.Spec.EffectAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "DNSDegraded", Action: "dns", TimeoutSeconds: 30}}
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	probe := &betaProbeClient{calls: map[string]int{}, effectAtCall: 2}
	reconcile := func() {
		t.Helper()
		controller := betaFaultReconciler(base, base, scheme, &now)
		controller.Probes = probe
		if _, err := controller.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		reconcile()
	}
	resource := &unstructured.Unstructured{}
	resource.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "DNSChaos"})
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName(campaign.Name, "stage", "dns")}, resource); err != nil {
		t.Fatal(err)
	}
	resource.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "AllInjected", "status": "True"}}}
	if err := base.Update(context.Background(), resource); err != nil {
		t.Fatal(err)
	}

	reconcile()
	current := &attacknetv1beta1.FaultCampaign{}
	if err := base.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	action := current.Status.Stages[0].Actions[0]
	if action.Phase != "Injecting" || action.Reason != "WaitingForEffectEvidence" {
		t.Fatalf("action after pre-effect sample = %#v", action)
	}
	reconcile()
	if err := base.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if got := current.Status.Stages[0].Actions[0].Phase; got != "Active" {
		t.Fatalf("action phase after effect sample = %q, want Active", got)
	}
}

func TestV1Beta1EffectAssertionBecomesInconclusiveAtDeadline(t *testing.T) {
	scheme := betaFaultScheme(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("missing-effect", []attacknetv1beta1.FaultActionSpec{
		betaChaosAction("dns", "dns", "error"),
	})
	campaign.Spec.EffectAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "DNSDegraded", Action: "dns", TimeoutSeconds: 1}}
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	probe := &betaProbeClient{calls: map[string]int{}, effectAtCall: 999}
	reconcile := func() {
		t.Helper()
		controller := betaFaultReconciler(base, base, scheme, &now)
		controller.Probes = probe
		if _, err := controller.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		reconcile()
	}
	resource := &unstructured.Unstructured{}
	resource.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "DNSChaos"})
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName(campaign.Name, "stage", "dns")}, resource); err != nil {
		t.Fatal(err)
	}
	resource.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "AllInjected", "status": "True"}}}
	if err := base.Update(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
	reconcile()
	now = now.Add(2 * time.Second)
	reconcile()

	current := &attacknetv1beta1.FaultCampaign{}
	if err := base.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	action := current.Status.Stages[0].Actions[0]
	if action.Phase != "Inconclusive" || action.Reason != "EffectEvidenceTimeout" {
		t.Fatalf("action after evidence deadline = %#v", action)
	}
}

func TestV1Beta1UnsafeAggregateFailsBeforeMutation(t *testing.T) {
	resetBetaProbe()
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("unsafe", []attacknetv1beta1.FaultActionSpec{
		betaChaosAction("one", "network", "delay"), betaChaosAction("two", "dns", "error"),
	})
	campaign.Spec.Safety.MaxConcurrentFaults = 1
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	reconcileBetaUntil(t, base, scheme, request, &now, 2)
	assertBetaPhase(t, base, request.NamespacedName, "Failed")
	for _, kind := range []string{"NetworkChaos", "DNSChaos"} {
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: kind})
		if err := base.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName("unsafe", "stage", map[string]string{"NetworkChaos": "one", "DNSChaos": "two"}[kind])}, object); !apierrors.IsNotFound(err) {
			t.Fatalf("unsafe campaign mutation %s lookup = %v, want NotFound", kind, err)
		}
	}
}

func TestV1Beta1PartialInjectionRollsBackCreatedMutations(t *testing.T) {
	resetBetaProbe()
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("rollback", []attacknetv1beta1.FaultActionSpec{
		betaChaosAction("network", "network", "delay"), betaChaosAction("dns", "dns", "error"),
	})
	underlying := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	failing := &failKindClient{Client: underlying, kind: "DNSChaos"}
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	for index := 0; index < 3; index++ {
		r := betaFaultReconciler(failing, underlying, scheme, &now)
		_, _ = r.Reconcile(context.Background(), request)
	}
	assertBetaPhase(t, underlying, request.NamespacedName, "Failed")
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"})
	err := underlying.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName("rollback", "stage", "network")}, object)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("first mutation was not rolled back: %v", err)
	}
}

func TestV1Beta1AdmissionChangeCleansMutationFromDurableStatus(t *testing.T) {
	resetBetaProbe()
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("spec-change", []attacknetv1beta1.FaultActionSpec{betaChaosAction("network", "network", "delay")})
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	reconcileBetaUntil(t, base, scheme, request, &now, 3)

	current := &attacknetv1beta1.FaultCampaign{}
	if err := base.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Stages[0].Faults[0].ID = "replacement"
	current.Generation++
	if err := base.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	reconcileBetaUntil(t, base, scheme, request, &now, 1)
	assertBetaPhase(t, base, request.NamespacedName, "Failed")

	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"})
	err := base.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName("spec-change", "stage", "network")}, object)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("mutation from the admitted status survived a spec edit: %v", err)
	}
}

func TestV1Beta1FinalizerCleansMutationBeforeCampaignDeletion(t *testing.T) {
	resetBetaProbe()
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("delete", []attacknetv1beta1.FaultActionSpec{betaChaosAction("network", "network", "delay")})
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	reconcileBetaUntil(t, base, scheme, request, &now, 3)

	current := &attacknetv1beta1.FaultCampaign{}
	if err := base.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if err := base.Delete(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	reconcileBetaUntil(t, base, scheme, request, &now, 1)

	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"})
	err := base.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName("delete", "stage", "network")}, object)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("mutation survived campaign finalization: %v", err)
	}
	err = base.Get(context.Background(), request.NamespacedName, &attacknetv1beta1.FaultCampaign{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("campaign remained after finalizer cleanup: %v", err)
	}
}

func TestV1Beta1TerminalCampaignReleasesCleanupFinalizer(t *testing.T) {
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	campaign := betaFaultCampaign("complete", nil)
	campaign.Finalizers = []string{betaFinalizer}
	campaign.Status.Phase = "Passed"
	campaign.Status.Cleanup = &attacknetv1beta1.CleanupEvidence{
		Absent: true, AllRecovered: true, Method: "TerminalCleanup", ObservedAt: metav1.NewTime(now),
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(campaign).Build()
	reconciler := &V1Beta1Reconciler{
		Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now },
	}
	key := client.ObjectKeyFromObject(campaign)
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	current := &attacknetv1beta1.FaultCampaign{}
	if err := kube.Get(context.Background(), key, current); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(current, betaFinalizer) {
		t.Fatal("terminal v1beta1 campaign retained its cleanup finalizer")
	}
}

func TestV1Beta1DeletionUsesDurableTerminalCleanupProof(t *testing.T) {
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	campaign := betaFaultCampaign("clean-delete", nil)
	campaign.Finalizers = []string{betaFinalizer}
	campaign.Status.Phase = "Passed"
	campaign.Status.Cleanup = &attacknetv1beta1.CleanupEvidence{
		Absent: true, AllRecovered: true, Method: "TerminalCleanup", ObservedAt: metav1.NewTime(now),
	}
	campaign.Status.Stages = []attacknetv1beta1.FaultStageStatus{{
		ID: "replace-tip", Actions: []attacknetv1beta1.FaultActionStatus{{
			ID: "replace", Mutation: &attacknetv1beta1.ChaosReference{
				Kind: "BurnchainReorgWorker", RecoveryContract: &apixv1.JSON{Raw: []byte(
					`{"policyName":"already-removed","policyUid":"policy-uid","stableSpecDigest":"sha256:missing"}`,
				)},
			},
		}},
	}}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(campaign).Build()
	key := client.ObjectKeyFromObject(campaign)
	if err := kube.Delete(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatalf("deletion repeated cleanup against an already-removed policy: %v", err)
	}
	if err := kube.Get(context.Background(), key, &attacknetv1beta1.FaultCampaign{}); !apierrors.IsNotFound(err) {
		t.Fatalf("campaign remained after its proven cleanup finalizer was released: %v", err)
	}
}

func TestV1Beta1TemplateNeverRetainsCleanupFinalizer(t *testing.T) {
	scheme := betaFaultScheme(t)
	campaign := betaFaultCampaign("template", nil)
	campaign.Spec.Template = true
	campaign.Finalizers = []string{betaFinalizer}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(campaign).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	key := client.ObjectKeyFromObject(campaign)
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	current := &attacknetv1beta1.FaultCampaign{}
	if err := kube.Get(context.Background(), key, current); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(current, betaFinalizer) {
		t.Fatal("v1beta1 campaign template retained an unnecessary cleanup finalizer")
	}
}

func TestV1Beta1StatusPatchRejectsAStaleAdmissionWriter(t *testing.T) {
	scheme := betaFaultScheme(t)
	stale := betaFaultCampaign("status-race", nil)
	stale.ResourceVersion = "10"
	stale.Status.Phase = "Admitted"
	current := stale.DeepCopy()
	current.ResourceVersion = "11"
	current.Status.Phase = "Running"
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(current).Build()
	reconciler := &V1Beta1Reconciler{Client: reader, APIReader: reader, Scheme: scheme}
	next := *stale.Status.DeepCopy()
	next.Reason = "AdmissionComplete"
	err := reconciler.patchBetaStatus(context.Background(), stale, next)
	if !apierrors.IsConflict(err) {
		t.Fatalf("stale admission status writer was not rejected as a conflict: %v", err)
	}
	observed := &attacknetv1beta1.FaultCampaign{}
	if getErr := reader.Get(context.Background(), client.ObjectKeyFromObject(current), observed); getErr != nil {
		t.Fatal(getErr)
	}
	if observed.Status.Phase != "Running" {
		t.Fatalf("newer running status was overwritten: %#v", observed.Status)
	}
}

func TestV1Beta1StatusPatchUsesAnAPIServerVersionPrecondition(t *testing.T) {
	scheme := betaFaultScheme(t)
	stale := betaFaultCampaign("status-toctou", nil)
	stale.ResourceVersion = "10"
	stale.Status.Phase = "Admitted"
	readerObject := stale.DeepCopy()
	writerObject := stale.DeepCopy()
	writerObject.ResourceVersion = "11"
	writerObject.Status.Phase = "Running"
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(readerObject).Build()
	writer := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(writerObject).Build()
	reconciler := &V1Beta1Reconciler{Client: writer, APIReader: reader, Scheme: scheme}
	next := *stale.Status.DeepCopy()
	next.Reason = "AdmissionComplete"
	err := reconciler.patchBetaStatus(context.Background(), stale, next)
	if !apierrors.IsConflict(err) {
		t.Fatalf("API-server resource-version race was not rejected as a conflict: %v", err)
	}
	observed := &attacknetv1beta1.FaultCampaign{}
	if getErr := writer.Get(context.Background(), client.ObjectKeyFromObject(writerObject), observed); getErr != nil {
		t.Fatal(getErr)
	}
	if observed.Status.Phase != "Running" {
		t.Fatalf("newer status was overwritten after the pre-write read: %#v", observed.Status)
	}
}

func TestV1Beta1ObservationSourceFailureDoesNotLosePriorInjection(t *testing.T) {
	resetBetaProbe()
	scheme := betaFaultScheme(t)
	now := time.Now().UTC()
	network, pods := betaFaultNetwork(t)
	campaign := betaFaultCampaign("source-error", nil)
	campaign.Spec.Stages = []attacknetv1beta1.FaultStageSpec{{
		ID: "immediate", Faults: []attacknetv1beta1.FaultActionSpec{betaChaosAction("network", "network", "delay")},
	}, {
		ID: "observed", Trigger: attacknetv1beta1.StageTriggerSpec{Observation: &attacknetv1beta1.ObservationTriggerSpec{Type: "invariant", TimeoutSeconds: 60}},
		Faults: []attacknetv1beta1.FaultActionSpec{betaChaosAction("dns", "dns", "error")},
	}}
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}, &attacknetv1beta1.StacksNetwork{}).
		WithObjects(network, pods[0], pods[1], environmentLeaseObject(), campaign).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(campaign)}
	for index := 0; index < 3; index++ {
		reconciler := betaFaultReconciler(base, base, scheme, &now)
		reconciler.Observations = failingTriggerReader{}
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatalf("reconcile %d: %v", index, err)
		}
	}
	current := &attacknetv1beta1.FaultCampaign{}
	if err := base.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Stages[0].Phase != "Injecting" || current.Status.Stages[1].Reason != "TriggerObservationUnavailable" {
		t.Fatalf("stage status did not preserve injection and observation retry: %#v", current.Status.Stages)
	}
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"})
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: mutationName("source-error", "immediate", "network")}, object); err != nil {
		t.Fatalf("prior stage mutation was lost: %v", err)
	}
}

type failingTriggerReader struct{}

func (failingTriggerReader) ReadTriggerSnapshot(context.Context, *attacknetv1beta1.FaultCampaign, *attacknetv1beta1.StacksNetwork) (trigger.Snapshot, error) {
	return trigger.Snapshot{}, errors.New("observation backend unavailable")
}

func TestV1Beta1DependencyMilestonesRequireObservedInjection(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())
	campaign := &attacknetv1beta1.FaultCampaign{Status: attacknetv1beta1.FaultCampaignStatus{Stages: []attacknetv1beta1.FaultStageStatus{{
		ID: "first", StartedAt: &now, Phase: "Injecting", Actions: []attacknetv1beta1.FaultActionStatus{{
			ID: "one", Mutation: &attacknetv1beta1.ChaosReference{CreatedAt: &now},
		}},
	}}}}
	observations := betaDependencyObservations(campaign)
	if len(observations) != 1 || len(observations[0].Transitions) != 0 {
		t.Fatalf("created mutation was reported as injected: %#v", observations)
	}
	campaign.Status.Stages[0].Actions[0].Mutation.InjectedAt = &now
	observations = betaDependencyObservations(campaign)
	if len(observations[0].Transitions) != 1 || observations[0].Transitions[0].State != "Injected" {
		t.Fatalf("observed injection milestones = %#v", observations[0].Transitions)
	}
	campaign.Status.Stages[0].Phase = "Active"
	observations = betaDependencyObservations(campaign)
	if len(observations[0].Transitions) != 2 || observations[0].Transitions[1].State != "Effective" {
		t.Fatalf("effect milestone preceded effect evidence: %#v", observations[0].Transitions)
	}
}

func TestV1Beta1AssertionsAreScopedToNamedAction(t *testing.T) {
	campaign := betaFaultCampaign("assertions", []attacknetv1beta1.FaultActionSpec{
		betaChaosAction("network", "network", "delay"), betaChaosAction("dns", "dns", "error"),
	})
	campaign.Spec.EffectAssertions = []attacknetv1beta1.CampaignAssertion{
		{Type: "NetworkDegraded", Action: "network", TimeoutSeconds: 10},
		{Type: "DNSDegraded", Action: "dns", TimeoutSeconds: 20},
	}
	networkAssertions := betaAssertions(campaign, "stage", "network", true)
	if len(networkAssertions) != 1 || networkAssertions[0].Type != "NetworkDegraded" {
		t.Fatalf("network assertions = %#v", networkAssertions)
	}
	if timeout := betaAssertionTimeout(campaign, "stage", "network", true, time.Second); timeout != 10*time.Second {
		t.Fatalf("network assertion timeout = %s", timeout)
	}
}

func TestV1Beta1RecoveryEvidenceTimeoutIsBounded(t *testing.T) {
	now := time.Now().UTC()
	injected := metav1.NewTime(now.Add(-61 * time.Second))
	campaign := betaFaultCampaign("timeout", []attacknetv1beta1.FaultActionSpec{betaChaosAction("network", "network", "delay")})
	campaign.Spec.RecoveryAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "NetworkRecovered", Action: "network", TimeoutSeconds: 30}}
	spec := &campaign.Spec.Stages[0].Faults[0]
	spec.Fault.Duration = metav1.Duration{Duration: 30 * time.Second}
	status := &attacknetv1beta1.FaultActionStatus{ID: "network", Mutation: &attacknetv1beta1.ChaosReference{InjectedAt: &injected}}
	if !betaRecoveryTimedOut(campaign, "stage", spec, status, now) {
		t.Fatal("recovery evidence remained unbounded past duration plus assertion timeout")
	}
	notYet := metav1.NewTime(now.Add(-59 * time.Second))
	status.Mutation.InjectedAt = &notYet
	if betaRecoveryTimedOut(campaign, "stage", spec, status, now) {
		t.Fatal("recovery evidence was classified before its assertion deadline")
	}
}

func TestV1Beta1InjectionEvidenceTimeoutIsBounded(t *testing.T) {
	now := time.Now().UTC()
	created := metav1.NewTime(now.Add(-31 * time.Second))
	campaign := betaFaultCampaign("timeout", []attacknetv1beta1.FaultActionSpec{betaChaosAction("network", "network", "delay")})
	campaign.Spec.EffectAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "NetworkDegraded", Action: "network", TimeoutSeconds: 30}}
	status := &attacknetv1beta1.FaultActionStatus{ID: "network", Mutation: &attacknetv1beta1.ChaosReference{CreatedAt: &created}}
	if !betaInjectionTimedOut(campaign, "stage", status, now) {
		t.Fatal("unobserved injection remained active past its effect-evidence deadline")
	}
	created = metav1.NewTime(now.Add(-29 * time.Second))
	status.Mutation.CreatedAt = &created
	if betaInjectionTimedOut(campaign, "stage", status, now) {
		t.Fatal("injection timed out before its effect-evidence deadline")
	}
}

type failKindClient struct {
	client.Client
	kind string
}

func (value *failKindClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	if object.GetObjectKind().GroupVersionKind().Kind == value.kind {
		return errors.New("injected create failure")
	}
	return value.Client.Create(ctx, object, options...)
}

func reconcileBetaUntil(t *testing.T, base client.Client, scheme *runtime.Scheme, request reconcile.Request, now *time.Time, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		r := betaFaultReconciler(base, base, scheme, now)
		if _, err := r.Reconcile(context.Background(), request); err != nil {
			t.Fatalf("reconcile %d: %v", index, err)
		}
	}
}

func betaFaultReconciler(base client.Client, reader client.Reader, scheme *runtime.Scheme, now *time.Time) *V1Beta1Reconciler {
	return &V1Beta1Reconciler{Client: base, APIReader: reader, Scheme: scheme, Probes: sharedBetaProbe, Now: func() time.Time { return *now }, IOPressureImage: "pressure:test"}
}

func betaFaultScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func betaFaultNetwork(t *testing.T) (*attacknetv1beta1.StacksNetwork, []*corev1.Pod) {
	t.Helper()
	imageID := "containerd://sha256:" + strings.Repeat("a", 64)
	bitcoinImageID := "containerd://sha256:" + strings.Repeat("b", 64)
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: "network-uid", Generation: 1, ResourceVersion: "1"},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Defaults: attacknetv1beta1.NetworkDefaults{NodeImage: "node:test", SignerImage: "signer:test", BitcoinImage: "bitcoin:test"},
			Burnchain: attacknetv1beta1.BurnchainTopologySpec{
				PolicyRef: corev1.LocalObjectReference{Name: "clock"},
				Nodes:     []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin-1", Config: betaConfig("bitcoin")}},
			},
			Nodes: []attacknetv1beta1.StacksNodeSpec{{Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner, BurnchainNodeRef: "bitcoin-1", Config: betaConfig("miner")}},
		},
		Status: attacknetv1beta1.StacksNetworkStatus{ObservedGeneration: 1, Phase: "Ready", InventoryReady: true, Actors: []attacknetv1beta1.ActorStatus{{
			Name: "bitcoin-1", Role: "burnchain", ResourceName: "network-bitcoin-1", Image: "bitcoin:test", Ready: true,
			ServiceName: "network-bitcoin-1", StatefulSetUID: "bitcoin-stateful-uid", CurrentRevision: "bitcoin-revision",
			PodName: "network-bitcoin-1-0", PodUID: "bitcoin-pod-uid", RuntimeImageID: bitcoinImageID, IdentityReady: true,
		}, {
			Name: "miner-1", Role: "miner", ResourceName: "network-miner-1", Image: "node:test", Ready: true,
			ServiceName: "network-miner-1", StatefulSetUID: "stateful-uid", CurrentRevision: "revision",
			PodName: "network-miner-1-0", PodUID: "pod-uid", RuntimeImageID: imageID, IdentityReady: true,
		}}},
	}
	legacy := &attacknetv1alpha1.StacksNetwork{
		ObjectMeta: *network.ObjectMeta.DeepCopy(),
		Spec:       attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{{Name: "bitcoin-1", Role: "burnchain"}, {Name: "miner-1", Role: "miner"}}},
		Status: attacknetv1alpha1.StacksNetworkStatus{ObservedGeneration: 1, InventoryReady: true, Actors: []attacknetv1alpha1.ActorStatus{{
			Name: "bitcoin-1", Role: "burnchain", ResourceName: "network-bitcoin-1", Image: "bitcoin:test", Ready: true,
			ServiceName: "network-bitcoin-1", StatefulSetUID: "bitcoin-stateful-uid", CurrentRevision: "bitcoin-revision",
			PodName: "network-bitcoin-1-0", PodUID: "bitcoin-pod-uid", RuntimeImageID: bitcoinImageID, IdentityReady: true,
		}, {
			Name: "miner-1", Role: "miner", ResourceName: "network-miner-1", Image: "node:test", Ready: true,
			ServiceName: "network-miner-1", StatefulSetUID: "stateful-uid", CurrentRevision: "revision",
			PodName: "network-miner-1-0", PodUID: "pod-uid", RuntimeImageID: imageID, IdentityReady: true,
		}}},
	}
	payload, err := inventory.Build(legacy)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "network-miner-1-0", Namespace: "test", UID: "pod-uid", Labels: map[string]string{NetworkLabel: "network", ActorLabel: "miner-1", RoleLabel: "miner"}},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "actor", Image: "node:test"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", Ready: true, ImageID: imageID}}},
	}
	bitcoinPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "network-bitcoin-1-0", Namespace: "test", UID: "bitcoin-pod-uid", Labels: map[string]string{NetworkLabel: "network", ActorLabel: "bitcoin-1", RoleLabel: "burnchain"}},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "actor", Image: "bitcoin:test"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.2", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", Ready: true, ImageID: bitcoinImageID}}},
	}
	return network, []*corev1.Pod{pod, bitcoinPod}
}

func betaConfig(name string) attacknetv1beta1.ConfigSource {
	return attacknetv1beta1.ConfigSource{ConfigMapRef: &attacknetv1beta1.ConfigObjectRef{Name: name + "-config", Key: "config.toml"}}
}

func betaFaultCampaign(name string, actions []attacknetv1beta1.FaultActionSpec) *attacknetv1beta1.FaultCampaign {
	return &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test", UID: types.UID(name + "-uid"), Generation: 1},
		Spec: attacknetv1beta1.FaultCampaignSpec{NetworkRef: "network", Stages: []attacknetv1beta1.FaultStageSpec{{ID: "stage", Faults: actions}}, Safety: attacknetv1beta1.FaultSafety{
			MaxUnavailableSignerBasisPoints: 10_000, MaxUnavailableMinerBasisPoints: 10_000,
			MaxConcurrentFaults: 8, AllowQuorumLoss: true, AllowMinerMajorityOutage: true,
		}},
	}
}

func TestCompletedPodKillRetainsNarrowPodIdentityAllowance(t *testing.T) {
	campaign := betaFaultCampaign("replacement", []attacknetv1beta1.FaultActionSpec{{
		ID: "kill", Fault: attacknetv1beta1.FaultSpec{Type: "pod", Action: "pod-kill"},
	}})
	campaign.Status.Stages = []attacknetv1beta1.FaultStageStatus{{
		ID: "stage", Actions: []attacknetv1beta1.FaultActionStatus{{
			ID: "kill", Phase: "Completed",
			Mutation:        &attacknetv1beta1.ChaosReference{Kind: "PodChaos", Name: "replacement"},
			ResolvedTargets: []attacknetv1beta1.ResolvedTarget{{Actor: "miner-1"}},
		}},
	}}
	allowed := betaAllowedPodChanges(campaign)
	if _, ok := allowed["miner-1"]; !ok {
		t.Fatal("completed admitted pod-kill lost its Pod identity allowance")
	}
	campaign.Status.Stages[0].Actions[0].Mutation = nil
	if _, ok := betaAllowedPodChanges(campaign)["miner-1"]; ok {
		t.Fatal("pod identity was relaxed before a mutation existed")
	}
}

func TestRunOwnedCampaignsShareOneMutationLeaseUntilAllAreTerminal(t *testing.T) {
	scheme := betaFaultScheme(t)
	controller := true
	owner := metav1.OwnerReference{
		APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun",
		Name: "run", UID: types.UID("run-uid"), Controller: &controller,
	}
	first := betaFaultCampaign("first", nil)
	first.OwnerReferences = []metav1.OwnerReference{owner}
	first.Status.Phase = "Passed"
	second := betaFaultCampaign("second", nil)
	second.OwnerReferences = []metav1.OwnerReference{owner}
	second.Status.Phase = "Running"
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.FaultCampaign{}).
		WithObjects(environmentLeaseObject(), first, second).Build()
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube, Scheme: scheme}
	ctx := context.Background()

	firstLease, err := reconciler.legacyRuntime().holdMutationLease(ctx, betaLeaseCampaign(first), true)
	if err != nil || !firstLease.Held {
		t.Fatalf("first run child did not acquire the shared lease: state=%#v err=%v", firstLease, err)
	}
	secondLease, err := reconciler.legacyRuntime().holdMutationLease(ctx, betaLeaseCampaign(second), true)
	if err != nil || !secondLease.Held {
		t.Fatalf("second run child could not join the shared lease: state=%#v err=%v", secondLease, err)
	}
	lease := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: "test", Name: mutationLease}
	if err := kube.Get(ctx, key, lease); err != nil {
		t.Fatal(err)
	}
	if lease.Data["owner"] != "attacknetrun:run-uid" || lease.Data["token"] != "run-uid" {
		t.Fatalf("lease is not bound to the owning run: %#v", lease.Data)
	}

	if err := reconciler.releaseBetaMutationLease(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, key, lease); err != nil {
		t.Fatalf("first terminal child released a lease still used by its sibling: %v", err)
	}
	storedSecond := &attacknetv1beta1.FaultCampaign{}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(second), storedSecond); err != nil {
		t.Fatal(err)
	}
	storedSecond.Status.Phase = "Passed"
	if err := kube.Status().Update(ctx, storedSecond); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.releaseBetaMutationLease(ctx, storedSecond); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, key, lease); !apierrors.IsNotFound(err) {
		t.Fatalf("last terminal child did not release the shared lease: %v", err)
	}
}

func TestStandaloneCampaignsRetainExclusiveLeasePrincipals(t *testing.T) {
	first := betaFaultCampaign("first", nil)
	second := betaFaultCampaign("second", nil)
	if mutationLeaseOwner(betaLeaseCampaign(first)) == mutationLeaseOwner(betaLeaseCampaign(second)) {
		t.Fatal("unrelated standalone campaigns unexpectedly share a mutation lease principal")
	}
}

func betaChaosAction(id, faultType, action string) attacknetv1beta1.FaultActionSpec {
	parameters := map[string]any{}
	if faultType == "network" {
		parameters["delay"] = map[string]any{"latency": "100ms"}
	}
	if faultType == "dns" {
		parameters["patterns"] = []string{"network-bitcoin-1.test.svc.cluster.local"}
	}
	encoded, _ := json.Marshal(parameters)
	return attacknetv1beta1.FaultActionSpec{ID: id, Target: attacknetv1beta1.FaultTarget{Actors: []string{"miner-1"}}, Fault: attacknetv1beta1.FaultSpec{Type: faultType, Action: action, Mode: "all", Duration: metav1.Duration{Duration: time.Minute}, Parameters: apixv1.JSON{Raw: encoded}}}
}

func environmentLeaseObject() *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: environmentLease, Namespace: "test"}, Data: map[string]string{"network": "network"}}
}

func assertBetaPhase(t *testing.T, base client.Client, key client.ObjectKey, want string) {
	t.Helper()
	campaign := &attacknetv1beta1.FaultCampaign{}
	if err := base.Get(context.Background(), key, campaign); err != nil {
		t.Fatal(err)
	}
	if campaign.Status.Phase != want {
		t.Fatalf("campaign phase = %q (%s: %s), want %q; stages=%#v", campaign.Status.Phase, campaign.Status.Reason, campaign.Status.Message, want, campaign.Status.Stages)
	}
}
