package run

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
)

func TestRunTransitionDoesNotMutateCachedStatus(t *testing.T) {
	original := attacknetv1alpha1.AttacknetRunStatus{Conditions: []metav1.Condition{{Type: "Succeeded", Status: metav1.ConditionFalse, Reason: "Running", Message: "running", LastTransitionTime: metav1.NewTime(time.Unix(1, 0))}}}
	next := runTransition(original, 3, "Passed", "Complete", "done", time.Unix(2, 0))
	if original.Conditions[0].Status != metav1.ConditionFalse || original.Conditions[0].Reason != "Running" {
		t.Fatal("transition mutated the informer-owned status backing slice")
	}
	if next.Conditions[0].Status != metav1.ConditionTrue || next.Conditions[0].Reason != "Complete" {
		t.Fatalf("terminal condition was not updated: %#v", next.Conditions)
	}
}

func TestRunFailurePreservesItsDiagnostic(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", Generation: 1},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&attacknetv1alpha1.AttacknetRun{}).WithObjects(run).Build()
	reconciler := &Reconciler{Client: client, APIReader: client, Now: func() time.Time { return time.Unix(10, 0) }}
	if err := reconciler.fail(context.Background(), run, "ScheduleAdmissionFailed", errors.New("source schedule no longer matches")); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1alpha1.AttacknetRun{}
	if err := client.Get(context.Background(), clientKey(run), observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "Failed" || observed.Status.Message != "source schedule no longer matches" || observed.Status.Conditions[0].Message != observed.Status.Message {
		t.Fatalf("terminal diagnostic was lost: %#v", observed.Status)
	}
}

func TestTerminalRunDoesNotClaimCleanupWhileOwnedCampaignIsActive(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{
			Name: "run", Namespace: "test", UID: types.UID("run-uid"), Generation: 1,
		},
		Status: attacknetv1alpha1.AttacknetRunStatus{
			ActiveCampaign: ptr("run-child"),
			ActiveChild: &attacknetv1alpha1.ActiveRunChild{
				Name: "run-child", UID: "child-uid", InstructionID: "child",
			},
			BudgetUsage: &attacknetv1alpha1.BudgetUsage{ActiveFaults: 1},
		},
	}
	child := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name: "run-child", Namespace: "test", UID: types.UID("child-uid"),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				run, attacknetv1alpha1.GroupVersion.WithKind("AttacknetRun"),
			)},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{Phase: "Injecting"},
	}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.AttacknetRun{}, &attacknetv1alpha1.FaultCampaign{}).
		WithObjects(run, child).
		Build()
	reconciler := &Reconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		Now: func() time.Time { return time.Unix(10, 0) },
	}
	if err := reconciler.fail(context.Background(), run, "ScheduleIntegrityFailed", errors.New("schedule changed")); err != nil {
		t.Fatal(err)
	}
	key := types.NamespacedName{Namespace: run.Namespace, Name: run.Name}
	observed := &attacknetv1alpha1.AttacknetRun{}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "Failed" || observed.Status.Cleanup == nil ||
		observed.Status.Cleanup.Completed || observed.Status.FinishedAt != nil ||
		observed.Status.ActiveCampaign == nil || observed.Status.BudgetUsage.ActiveFaults != 1 {
		t.Fatalf("terminal outcome falsely claimed child cleanup: %#v", observed.Status)
	}

	storedChild := &attacknetv1alpha1.FaultCampaign{}
	if err := kube.Get(context.Background(), clientKey(child), storedChild); err != nil {
		t.Fatal(err)
	}
	storedChild.Status.Phase = "Passed"
	storedChild.Status.Cleanup = &attacknetv1alpha1.CleanupEvidence{
		Absent: true, AllRecovered: true, Method: "Normal",
	}
	if err := kube.Status().Update(context.Background(), storedChild); err != nil {
		t.Fatal(err)
	}
	reconciler.Now = func() time.Time { return time.Unix(20, 0) }
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Cleanup == nil || !observed.Status.Cleanup.Completed ||
		observed.Status.Cleanup.CompletedAt == nil || observed.Status.FinishedAt == nil ||
		observed.Status.ActiveCampaign != nil || observed.Status.ActiveChild != nil ||
		observed.Status.BudgetUsage.ActiveFaults != 0 {
		t.Fatalf("terminal cleanup was not completed after the child proved recovery: %#v", observed.Status)
	}
	completedAt := observed.Status.Cleanup.CompletedAt.DeepCopy()
	reconciler.Now = func() time.Time { return time.Unix(30, 0) }
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Cleanup.CompletedAt == nil || !observed.Status.Cleanup.CompletedAt.Time.Equal(completedAt.Time) {
		t.Fatalf("completed terminal cleanup timestamp churned on an idempotent reconcile: %#v", observed.Status.Cleanup)
	}
}

func TestDurableDecisionsFailClosedOnMalformedOrDuplicateState(t *testing.T) {
	decision := func(index int, execution, instruction string) apixv1.JSON {
		value, err := jsonValue(map[string]any{
			"index": index, "execution": execution, "instructionId": instruction,
			"phase": "Passed", "completedAt": "2026-08-25T00:00:00Z", "source": "template",
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if _, completed, err := validatedDecisions([]apixv1.JSON{decision(0, "run-1", "first")}); err != nil || !completed["run-1"] {
		t.Fatalf("valid decision was rejected: %v, %#v", err, completed)
	}
	for name, values := range map[string][]apixv1.JSON{
		"malformed":       {{Raw: []byte(`{"index":0}`)}},
		"wrong index":     {decision(1, "run-1", "first")},
		"duplicate child": {decision(0, "run-1", "first"), decision(1, "run-1", "second")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validatedDecisions(values); err == nil {
				t.Fatal("invalid durable decision state was accepted")
			}
		})
	}
}

func TestPrepareUsesUncachedNetworkInventory(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", Generation: 1},
		Spec:       attacknetv1alpha1.AttacknetRunSpec{NetworkRef: "network"},
	}
	cachedNetwork := &attacknetv1alpha1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid"), Generation: 1},
		Status:     attacknetv1alpha1.StacksNetworkStatus{Phase: "Ready", ObservedGeneration: 1, InventoryReady: true, InventoryDigest: "sha256:cached"},
	}
	directNetwork := cachedNetwork.DeepCopy()
	directNetwork.Status.InventoryReady = false
	directNetwork.Status.InventoryDigest = ""
	cachedClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.AttacknetRun{}).
		WithObjects(run, cachedNetwork).
		Build()
	directReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(run.DeepCopy(), directNetwork).Build()
	reconciler := &Reconciler{Client: cachedClient, APIReader: directReader, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test", Name: "run"}}); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1alpha1.AttacknetRun{}
	if err := cachedClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "run"}, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Reason != "NetworkInventoryNotReady" || !strings.Contains(observed.Status.Message, "no published digest") {
		t.Fatalf("uncached incomplete inventory did not block preparation: %#v", observed.Status)
	}
}

func TestReconcileRefusesInformerDelayedRunState(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", Generation: 1},
		Spec:       attacknetv1alpha1.AttacknetRunSpec{NetworkRef: "network"},
	}
	cachedClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.AttacknetRun{}).
		WithObjects(run).
		Build()
	directReader := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&attacknetv1alpha1.AttacknetRun{}).
		WithObjects(run.DeepCopy()).
		Build()
	live := &attacknetv1alpha1.AttacknetRun{}
	key := types.NamespacedName{Namespace: "test", Name: "run"}
	if err := directReader.Get(context.Background(), key, live); err != nil {
		t.Fatal(err)
	}
	live.Status.Phase = "Passed"
	live.Status.Reason = "SequenceCompleted"
	if err := directReader.Status().Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}

	reconciler := &Reconciler{Client: cachedClient, APIReader: directReader, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requeue {
		t.Fatal("informer-delayed run was not requeued for a fresh snapshot")
	}
	observed := &attacknetv1alpha1.AttacknetRun{}
	if err := cachedClient.Get(context.Background(), key, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "" || observed.Status.Reason != "" {
		t.Fatalf("stale reconcile overwrote durable run state: %#v", observed.Status)
	}
}

func TestExecutionCampaignRequiresExactRunOwnershipAndInputs(t *testing.T) {
	run := &attacknetv1alpha1.AttacknetRun{ObjectMeta: metav1.ObjectMeta{
		Name: "run", Namespace: "test", UID: types.UID("run-uid"),
	}}
	desired := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name: "run-1-fault", Namespace: "test",
			Labels:      map[string]string{"testing.stacks.org/network": "network", "testing.stacks.org/run": "run"},
			Annotations: map[string]string{"testing.stacks.org/schedule-digest": "sha256:schedule", "testing.stacks.org/instruction-id": "fault"},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				run, attacknetv1alpha1.GroupVersion.WithKind("AttacknetRun"),
			)},
		},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition", Mode: "one", Duration: "30s"},
		},
	}
	if !executionCampaignMatches(run, desired, desired.DeepCopy()) {
		t.Fatal("exact admitted execution no longer matches its immutable schedule input")
	}
	foreign := desired.DeepCopy()
	foreign.OwnerReferences[0].UID = types.UID("foreign-run")
	if executionCampaignMatches(run, desired, foreign) {
		t.Fatal("foreign-owned execution was accepted")
	}
	changed := desired.DeepCopy()
	changed.Spec.Fault.Action = "delay"
	if executionCampaignMatches(run, desired, changed) {
		t.Fatal("execution with changed campaign spec was accepted")
	}
	changed = desired.DeepCopy()
	changed.Annotations["testing.stacks.org/schedule-digest"] = "sha256:other"
	if executionCampaignMatches(run, desired, changed) {
		t.Fatal("execution from another immutable schedule was accepted")
	}
}

func TestScheduleReadUsesUncachedImmutableArtifact(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run, network, admitted, templates := scheduleFixture()
	schedule, err := buildSchedule(run, network, admitted, templates, fault.ManifestFromNetwork(network))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeSchedule(schedule)
	if err != nil {
		t.Fatal(err)
	}
	specDigest, err := canonical.ArtifactDigest(run.Spec)
	if err != nil {
		t.Fatal(err)
	}
	configMap := scheduleConfigMapFixture(run, schedule, specDigest, payload)
	reference := attacknetv1alpha1.ScheduleReference{
		Name: configMap.Name, UID: string(configMap.UID), Digest: schedule.Integrity.Digest,
		RunGeneration: run.Generation, RunSpecDigest: specDigest,
	}
	corrupt := configMap.DeepCopy()
	corrupt.BinaryData["schedule.json.gz"] = append([]byte(nil), payload...)
	corrupt.BinaryData["schedule.json.gz"][len(payload)/2] ^= 0xff
	cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(configMap).Build()
	directReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(corrupt).Build()
	reconciler := &Reconciler{Client: cachedClient, APIReader: directReader, Scheme: scheme}
	if _, err := reconciler.readSchedule(context.Background(), run, reference); err == nil {
		t.Fatal("uncached schedule corruption was hidden by the informer cache")
	}
}

func TestPersistedScheduleRejectsDifferentRunGeneration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run, network, admitted, templates := scheduleFixture()
	schedule, err := buildSchedule(run, network, admitted, templates, fault.ManifestFromNetwork(network))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeSchedule(schedule)
	if err != nil {
		t.Fatal(err)
	}
	specDigest, err := canonical.ArtifactDigest(run.Spec)
	if err != nil {
		t.Fatal(err)
	}
	configMap := scheduleConfigMapFixture(run, schedule, specDigest, payload)
	run.Generation++
	cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(configMap).Build()
	directReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(configMap.DeepCopy()).Build()
	reconciler := &Reconciler{Client: cachedClient, APIReader: directReader, Scheme: scheme}
	if _, err := reconciler.persistSchedule(context.Background(), run, schedule); err == nil || !strings.Contains(err.Error(), "different run inputs") {
		t.Fatalf("persisted schedule from another generation was accepted: %v", err)
	}
}

func TestStartingActionChargesExecutedCampaignBudget(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", UID: types.UID("run-uid"), Generation: 1},
		Spec: attacknetv1alpha1.AttacknetRunSpec{
			NetworkRef: "network",
			Budgets: attacknetv1alpha1.RunBudgets{
				MaxCampaigns: 2, MaxCumulativeFaultSeconds: 60,
				MaxSignerImpactPercent: 30, MaxBurnchainFaults: 1,
			},
		},
		Status: attacknetv1alpha1.AttacknetRunStatus{
			ScheduleRef: &attacknetv1alpha1.ScheduleReference{Digest: "sha256:" + repeat("a", 64)},
		},
	}
	spec := attacknetv1alpha1.FaultCampaignSpec{
		NetworkRef: "network",
		Fault: attacknetv1alpha1.FaultSpec{
			Type: "network", Action: "partition", Mode: "one", Duration: "10s",
		},
	}
	digest, err := canonical.ArtifactDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	action := action{
		InstructionID: "partition", CampaignAlias: "partition", Source: sourceIdentity{Name: "template"},
		Resolved:     resolvedAction{CampaignSpec: spec, CampaignSpecDigest: digest},
		BudgetCharge: budgetCharge{Campaigns: 1, FaultSeconds: 10},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&attacknetv1alpha1.AttacknetRun{}).WithObjects(run).Build()
	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme, Now: func() time.Time { return time.Unix(10, 0) }}
	usage := &attacknetv1alpha1.BudgetUsage{}
	if err := reconciler.startAction(context.Background(), run, run.Status, action, usage); err != nil {
		t.Fatal(err)
	}
	observed := &attacknetv1alpha1.AttacknetRun{}
	if err := client.Get(context.Background(), clientKey(run), observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.BudgetUsage == nil || observed.Status.BudgetUsage.Campaigns != 1 || observed.Status.BudgetUsage.CampaignsStarted != 1 {
		t.Fatalf("execution budget did not charge the started campaign: %#v", observed.Status.BudgetUsage)
	}
}

func TestBudgetUsageIsReconstructedFromImmutableOwnedChildren(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", UID: types.UID("run-uid")},
		Spec: attacknetv1alpha1.AttacknetRunSpec{
			NetworkRef: "network", Minimization: attacknetv1alpha1.MinimizationSpec{Enabled: true},
		},
		Status: attacknetv1alpha1.AttacknetRunStatus{
			ScheduleRef: &attacknetv1alpha1.ScheduleReference{Digest: "sha256:" + repeat("a", 64)},
		},
	}
	spec := attacknetv1alpha1.FaultCampaignSpec{
		NetworkRef: "network",
		Fault:      attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition", Mode: "one", Duration: "10s"},
	}
	digest, err := canonical.ArtifactDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	item := action{
		Order: 1, InstructionID: "partition", CampaignAlias: "partition",
		Source:   sourceIdentity{Name: "template", UID: "template-uid", Generation: 2, SpecDigest: "sha256:template"},
		Resolved: resolvedAction{CampaignSpec: spec, CampaignSpecDigest: digest},
		BudgetCharge: budgetCharge{
			Campaigns: 1, FaultSeconds: 10, SignerImpactPercent: 23, BurnchainFaults: 1,
		},
	}
	child := desiredExecutionCampaign(run, item)
	child.UID = types.UID("child-uid")
	child.Status.Phase = "Inconclusive"
	// A label selector must not be able to hide an owned execution from budget
	// reconstruction. The immutable comparison below will then reject the edit.
	withoutRunLabel := child.DeepCopy()
	delete(withoutRunLabel.Labels, "testing.stacks.org/run")
	// Model an informer that has not observed the successfully created child.
	// Budget reconstruction must use the authoritative API reader or the child
	// can disappear from accounting during exactly the create/status-patch gap.
	cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(run).Build()
	directReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(run.DeepCopy(), withoutRunLabel).Build()
	reconciler := &Reconciler{Client: cachedClient, APIReader: directReader, Scheme: scheme}
	children, err := reconciler.children(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 1 {
		t.Fatalf("owned child count = %d, want 1", len(children))
	}
	if _, err := budgetUsageFromChildren(run, children, resolvedSchedule{Actions: []action{item}}); err == nil {
		t.Fatal("an owned child with altered immutable metadata was accepted")
	}
	usage, err := budgetUsageFromChildren(run, []attacknetv1alpha1.FaultCampaign{*child}, resolvedSchedule{Actions: []action{item}})
	if err != nil {
		t.Fatal(err)
	}
	if usage.Campaigns != 1 || usage.CampaignsStarted != 1 || usage.CampaignsCompleted != 1 || usage.InconclusiveCampaigns != 1 || usage.CumulativeFaultSeconds != 10 || usage.MaximumSignerImpactPercent != 23 || usage.BurnchainFaults != 1 || usage.MinimizationAttempts != 1 {
		t.Fatalf("usage was not reconstructed from the durable child: %#v", usage)
	}
}

func scheduleConfigMapFixture(run *attacknetv1alpha1.AttacknetRun, schedule resolvedSchedule, specDigest string, payload []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: stableName(run.Name, "resolved-schedule"), Namespace: run.Namespace,
			UID: types.UID("schedule-uid"),
			Labels: map[string]string{
				fault.NetworkLabel: run.Spec.NetworkRef, "testing.stacks.org/run": run.Name,
			},
			Annotations: map[string]string{
				"testing.stacks.org/schedule-format": scheduleFormat,
				"testing.stacks.org/schedule-digest": schedule.Integrity.Digest,
				"testing.stacks.org/run-generation":  "1",
				"testing.stacks.org/run-spec-digest": specDigest,
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(run, attacknetv1alpha1.GroupVersion.WithKind("AttacknetRun"))},
		},
		BinaryData: map[string][]byte{"schedule.json.gz": append([]byte(nil), payload...)},
	}
}

func clientKey(object metav1.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: object.GetNamespace(), Name: object.GetName()}
}
