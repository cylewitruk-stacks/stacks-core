package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

const (
	betaRunFinalizer        = "testing.stacks.org/attacknet-run-v1beta1-cleanup"
	betaExecutionAnnotation = "testing.stacks.org/execution-id"
	betaScheduleAnnotation  = "testing.stacks.org/schedule-digest"
	betaTemplateAnnotation  = "testing.stacks.org/source-template"
	betaTriggerAnnotation   = "testing.stacks.org/trigger-receipt"
)

// V1Beta1Reconciler executes immutable dependency-triggered run schedules and
// permits only explicitly budgeted child-campaign concurrency.
type V1Beta1Reconciler struct {
	client.Client
	APIReader    client.Reader
	Scheme       *runtime.Scheme
	Now          func() time.Time
	SignerSets   signerset.Resolver
	Observations ObservationReader
}

type betaDecision struct {
	ExecutionID string    `json:"executionId"`
	Child       string    `json:"child"`
	ChildUID    string    `json:"childUid"`
	Phase       string    `json:"phase"`
	CompletedAt time.Time `json:"completedAt"`
	Source      string    `json:"source"`
}

// Reconcile advances one v1beta1 run through at most one durable status write.
func (r *V1Beta1Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	run := &attacknetv1beta1.AttacknetRun{}
	if err := r.Get(ctx, request.NamespacedName, run); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	current, err := r.runIsCurrent(ctx, run)
	if err != nil || !current {
		return reconcile.Result{Requeue: err == nil}, err
	}
	if !run.DeletionTimestamp.IsZero() {
		return r.reconcileDeletion(ctx, run)
	}
	if !containsString(run.Finalizers, betaRunFinalizer) {
		base := run.DeepCopy()
		run.Finalizers = append(run.Finalizers, betaRunFinalizer)
		return reconcile.Result{Requeue: true}, r.Patch(ctx, run, client.MergeFrom(base))
	}
	if run.Status.Phase == "Paused" {
		return reconcile.Result{}, nil
	}
	if betaTerminal(run.Status.Phase) {
		return r.reconcileTerminal(ctx, run)
	}

	network := &attacknetv1beta1.StacksNetwork{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef}, network); err != nil {
		return reconcile.Result{}, err
	}
	children, err := r.children(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	}
	if network.Status.Phase != "Ready" && len(activeBetaChildren(children)) == 0 {
		phase, reason := "Pending", "NetworkNotReady"
		if run.Status.ScheduleRef != nil {
			phase, reason = "Running", "WaitingForNetworkRecovery"
		}
		return reconcile.Result{RequeueAfter: 5 * time.Second}, r.transition(ctx, run, phase, reason, "")
	}
	if run.Status.ScheduleRef == nil {
		return reconcile.Result{}, r.prepare(ctx, run)
	}
	schedule, err := r.store().read(ctx, run, *run.Status.ScheduleRef)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "ScheduleIntegrityFailed", err)
	}
	if run.Status.ScheduleRef.RunGeneration != run.Generation {
		return reconcile.Result{}, r.fail(ctx, run, "AdmittedRunChanged", errors.New("run generation changed after schedule admission"))
	}
	decisions, completed, err := betaDecisions(run.Status.Decisions)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", err)
	}
	if err := validateBetaDecisionBindings(decisions, children, schedule); err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", err)
	}
	live, err := inventory.ReadBetaLiveView(ctx, r.APIReader, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef})
	if err != nil {
		return reconcile.Result{}, err
	}
	if schedule.Network.UID != string(live.Network.UID) || schedule.Network.Generation != live.Network.Generation || schedule.Network.Name != live.Network.Name {
		return reconcile.Result{}, r.fail(ctx, run, "AdmittedNetworkChanged", errors.New("network identity changed after schedule admission"))
	}
	identityChanged, err := r.enforceIdentity(ctx, run, live.Network, live.Pods, children, completed)
	if err != nil || identityChanged {
		return reconcile.Result{RequeueAfter: time.Second}, err
	}

	next := *run.Status.DeepCopy()
	if err := r.recordCompletedChildren(&next, children, schedule, completed); err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", err)
	}
	next.TriggerReceipts, err = betaTriggerReceipts(children, schedule)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "TriggerReceiptIntegrityFailed", err)
	}
	decisions, completed, _ = betaDecisions(next.Decisions)
	usage, err := betaBudgetUsage(children, schedule, completed)
	if err != nil {
		return reconcile.Result{}, r.pause(ctx, run, "ChildCampaignIntegrityFailed", err.Error())
	}
	if run.Status.BudgetUsage != nil {
		usage.MaximumSignerImpactBasisPoints = max(
			usage.MaximumSignerImpactBasisPoints,
			run.Status.BudgetUsage.MaximumSignerImpactBasisPoints,
		)
	}
	if run.Status.StartedAt != nil {
		usage.WallTimeMillis = r.now().Sub(run.Status.StartedAt.Time).Milliseconds()
	}
	next.BudgetUsage = usage
	reservedFaults, reservedSignerImpact, err := betaReservedImpact(children, schedule, completed)
	if err != nil {
		return reconcile.Result{}, r.pause(ctx, run, "ChildCampaignIntegrityFailed", err.Error())
	}
	next.ActiveChildren = betaActiveStatus(children)
	if usage.WallTimeMillis > int64(schedule.Budgets.MaxWallTimeSeconds)*1000 {
		return reconcile.Result{}, r.budgetTerminal(ctx, run, next, "WallTimeBudgetExhausted")
	}
	if terminalPhase, terminalReason, attribution := betaStopDecision(run, decisions, usage); terminalPhase != "" {
		if terminalPhase == "Paused" {
			next.Attribution = attribution
			return reconcile.Result{}, r.pauseWithCleanup(ctx, run, next, terminalReason, "")
		}
		return reconcile.Result{}, r.finish(ctx, run, next, terminalPhase, terminalReason, attribution)
	}
	if int(usage.CampaignsCompleted) == len(schedule.Executions) {
		return reconcile.Result{}, r.finish(ctx, run, next, "Passed", "ScheduleCompleted", "NotRequired")
	}

	started := betaStartedExecutions(children)
	external, err := r.observationReader().Read(ctx, run, live.Network)
	if err != nil {
		return reconcile.Result{}, err
	}
	snapshot := trigger.Snapshot{
		Now: r.now(), StartedAt: run.Status.StartedAt.Time.UTC(), Dependencies: childDependencyObservations(children),
		BurnHeight: external.BurnHeight, StacksHeight: external.StacksHeight, Observations: external.Observations,
	}
	startedThisPass := 0
	for _, execution := range schedule.Executions {
		if started[execution.ID] || completed[execution.ID] {
			continue
		}
		spec, err := betaExecutionTrigger(execution)
		if err != nil {
			return reconcile.Result{}, r.fail(ctx, run, "ScheduleIntegrityFailed", err)
		}
		decision, err := trigger.Evaluate(spec, snapshot)
		if err != nil {
			return reconcile.Result{}, r.fail(ctx, run, "TriggerEvaluationFailed", err)
		}
		if decision.Expired {
			return reconcile.Result{}, r.finish(ctx, run, next, "Inconclusive", decision.Reason, "Inconclusive")
		}
		if !decision.Eligible {
			continue
		}
		if decision.Receipt == nil {
			return reconcile.Result{}, r.fail(ctx, run, "TriggerEvaluationFailed", errors.New("eligible trigger lacks a receipt"))
		}
		matches, parityErr := r.signerSetMatchesSchedule(ctx, live.Network, live.Pods, schedule)
		if parityErr != nil {
			var transient *signerset.TransientError
			if errors.As(parityErr, &transient) {
				return reconcile.Result{}, parityErr
			}
			return reconcile.Result{}, r.finish(ctx, run, next, "Failed", "SignerSetParityFailed", "Inconclusive")
		}
		if !matches {
			return reconcile.Result{}, r.finish(ctx, run, next, "Failed", "SignerSetChangedBeforeCampaign", "Inconclusive")
		}
		if usage.CampaignsStarted >= schedule.Budgets.MaxCampaigns ||
			reservedFaults+execution.MaximumActiveFaults > schedule.Budgets.MaxActiveFaults ||
			reservedSignerImpact+execution.SignerImpactBasisPoints > schedule.Budgets.MaxSignerImpactPercent*100 ||
			usage.CumulativeFaultMillis+execution.FaultDurationMillis > int64(schedule.Budgets.MaxCumulativeFaultSeconds)*1000 ||
			usage.BurnchainFaults+execution.BurnchainFaults > schedule.Budgets.MaxBurnchainFaults {
			continue
		}
		receipt, receiptErr := betaJSON(*decision.Receipt)
		if receiptErr != nil {
			return reconcile.Result{}, receiptErr
		}
		child, createErr := r.createExecution(ctx, run, execution, schedule.Integrity.Digest, receipt)
		if createErr != nil {
			return reconcile.Result{}, createErr
		}
		usage.Campaigns++
		usage.CampaignsStarted++
		usage.ActiveCampaigns++
		usage.CumulativeFaultMillis += execution.FaultDurationMillis
		usage.BurnchainFaults += execution.BurnchainFaults
		usage.MaximumSignerImpactBasisPoints = max(usage.MaximumSignerImpactBasisPoints, execution.SignerImpactBasisPoints)
		reservedFaults += execution.MaximumActiveFaults
		reservedSignerImpact += execution.SignerImpactBasisPoints
		usage.MaximumSignerImpactBasisPoints = max(usage.MaximumSignerImpactBasisPoints, reservedSignerImpact)
		next.ActiveChildren = append(next.ActiveChildren, attacknetv1beta1.ActiveRunChild{ExecutionID: execution.ID, Name: child.Name, UID: string(child.UID), StartedAt: ptr(metav1.NewTime(r.now()))})
		next.ResolvedCampaigns = upsertBetaResolved(next.ResolvedCampaigns, execution)
		next.TriggerReceipts = append(next.TriggerReceipts, receipt)
		started[execution.ID] = true
		startedThisPass++
		break
	}
	next.BudgetUsage = usage
	reason := "WaitingForTrigger"
	if startedThisPass > 0 {
		reason = "CampaignsCreated"
	} else if usage.ActiveCampaigns > 0 {
		reason = "CampaignsActive"
	}
	return reconcile.Result{RequeueAfter: betaNextRequeue(schedule, started, snapshot)}, r.patchStatus(ctx, run, betaRunTransition(next, run.Generation, "Running", reason, "", r.now()))
}

func (r *V1Beta1Reconciler) prepare(ctx context.Context, run *attacknetv1beta1.AttacknetRun) error {
	live, err := inventory.ReadBetaLiveView(ctx, r.APIReader, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef})
	if err != nil {
		return err
	}
	published, err := inventory.BetaPublished(live.Network)
	if err != nil || len(inventory.BetaCompareLive(published, live.Network, live.Pods, nil)) > 0 {
		message := "published inventory differs from live Pods"
		if err != nil {
			message = err.Error()
		}
		return r.transition(ctx, run, "Pending", "NetworkInventoryNotReady", message)
	}
	legacyNetwork, err := topology.CompileV1Beta1(live.Network)
	if err != nil {
		return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
	}
	signerSet, err := r.signerResolver().Resolve(ctx, legacyNetwork, live.Pods)
	if err != nil {
		var transient *signerset.TransientError
		if errors.As(err, &transient) {
			return err
		}
		return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
	}
	manifest := canonicalManifest(legacyNetwork, signerSet.WeightsByActor)
	templates := make(map[string]*attacknetv1beta1.FaultCampaign, len(run.Spec.CampaignCatalog))
	for _, entry := range run.Spec.CampaignCatalog {
		source := &attacknetv1beta1.FaultCampaign{}
		if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: entry.CampaignRef}, source); err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
		templates[source.Name] = source
	}
	schedule, err := buildBetaSchedule(run, live.Network, published, templates, manifest)
	if err != nil {
		return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
	}
	if run.Spec.Replay.Enabled || run.Spec.Minimization.Enabled || run.Spec.Resume.Enabled {
		schedule, err = r.deriveBetaSchedule(ctx, run, schedule, manifest)
		if err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
	}
	reference, err := r.store().persist(ctx, run, schedule)
	if err != nil {
		return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
	}
	now := metav1.NewTime(r.now())
	next := *run.Status.DeepCopy()
	next.StartedAt = &now
	next.ScheduleRef = &reference
	next.ScheduleSummary = &attacknetv1beta1.ScheduleSummary{
		SchemaVersion: schedule.SchemaVersion, Executions: int32(len(schedule.Executions)),
		Replay:     run.Spec.Replay.Enabled || run.Spec.Minimization.Enabled,
		NetworkUID: string(live.Network.UID), NetworkGeneration: live.Network.Generation,
		ManifestDigest:  schedule.Network.ManifestDigest,
		SignerSetDigest: signerSet.SignerSetDigest, SignerSetObservedFrom: signerSet.ObservedFrom,
		NetworkInventory: published,
	}
	if signerSet.HasSigners {
		next.ScheduleSummary.SignerSetRewardCycle = ptr(signerSet.RewardCycle)
		next.ScheduleSummary.SignerSetTotalWeight = ptr(int64(signerSet.ObservedTotalWeight))
	}
	next.BudgetUsage = &attacknetv1beta1.BudgetUsage{MinimizationAttempts: ternary(run.Spec.Minimization.Enabled, int32(1), int32(0))}
	return r.patchStatus(ctx, run, betaRunTransition(next, run.Generation, "Preparing", "ResolvedSchedulePersisted", "", r.now()))
}

func (r *V1Beta1Reconciler) signerSetMatchesSchedule(
	ctx context.Context,
	network *attacknetv1beta1.StacksNetwork,
	pods []corev1.Pod,
	schedule betaSchedule,
) (bool, error) {
	legacyNetwork, err := topology.CompileV1Beta1(network)
	if err != nil {
		return false, err
	}
	resolved, err := r.signerResolver().Resolve(ctx, legacyNetwork, pods)
	if err != nil {
		return false, err
	}
	digest, err := canonical.ArtifactDigest(canonicalManifest(legacyNetwork, resolved.WeightsByActor))
	if err != nil {
		return false, err
	}
	return digest == schedule.Network.ManifestDigest, nil
}

func (r *V1Beta1Reconciler) createExecution(
	ctx context.Context,
	run *attacknetv1beta1.AttacknetRun,
	execution betaExecution,
	scheduleDigest string,
	receipt apixv1.JSON,
) (*attacknetv1beta1.FaultCampaign, error) {
	desired := &attacknetv1beta1.FaultCampaign{
		TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "FaultCampaign"},
		ObjectMeta: metav1.ObjectMeta{
			Name: betaChildName(run.Name, execution.ID), Namespace: run.Namespace,
			Labels: map[string]string{fault.NetworkLabel: run.Spec.NetworkRef, "testing.stacks.org/run": run.Name},
			Annotations: map[string]string{
				betaExecutionAnnotation: execution.ID, betaScheduleAnnotation: scheduleDigest,
				betaTemplateAnnotation: execution.Source.Name, betaTriggerAnnotation: string(receipt.Raw),
				"testing.stacks.org/source-template-uid":        execution.Source.UID,
				"testing.stacks.org/source-template-generation": fmt.Sprint(execution.Source.Generation),
				"testing.stacks.org/source-template-digest":     execution.Source.SpecDigest,
			},
			OwnerReferences: []metav1.OwnerReference{ownership.Reference(run, attacknetv1beta1.GroupVersion.WithKind("AttacknetRun"))},
		},
		Spec: *execution.CampaignSpec.DeepCopy(),
	}
	if err := r.Create(ctx, desired); err == nil {
		return desired, nil
	} else if !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	observed := &attacknetv1beta1.FaultCampaign{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(desired), observed); err != nil {
		return nil, err
	}
	if !betaExecutionMatches(run, desired, observed) {
		return nil, fmt.Errorf("refusing to adopt FaultCampaign %s with different ownership or execution inputs", desired.Name)
	}
	return observed, nil
}

func betaTriggerReceipts(children []attacknetv1beta1.FaultCampaign, schedule betaSchedule) ([]apixv1.JSON, error) {
	byExecution := make(map[string]attacknetv1beta1.FaultCampaign, len(children))
	for _, child := range children {
		id := child.Annotations[betaExecutionAnnotation]
		if id == "" || byExecution[id].Name != "" {
			return nil, fmt.Errorf("child %s has an absent or duplicate execution binding", child.Name)
		}
		byExecution[id] = child
	}
	result := make([]apixv1.JSON, 0, len(children))
	for _, execution := range schedule.Executions {
		child, found := byExecution[execution.ID]
		if !found {
			continue
		}
		raw := []byte(child.Annotations[betaTriggerAnnotation])
		var receipt trigger.Receipt
		if len(raw) == 0 || json.Unmarshal(raw, &receipt) != nil ||
			receipt.SchemaVersion != "stacks-attacknet-trigger-receipt/v1" || receipt.Subject != execution.ID {
			return nil, fmt.Errorf("child %s has an invalid trigger receipt", child.Name)
		}
		result = append(result, apixv1.JSON{Raw: append([]byte(nil), raw...)})
	}
	return result, nil
}

func betaExecutionMatches(run *attacknetv1beta1.AttacknetRun, desired, observed *attacknetv1beta1.FaultCampaign) bool {
	if desired.Name != observed.Name || !reflect.DeepEqual(desired.Spec, observed.Spec) {
		return false
	}
	owner := metav1.GetControllerOf(observed)
	if owner == nil || owner.UID != run.UID || owner.APIVersion != attacknetv1beta1.GroupVersion.String() || owner.Kind != "AttacknetRun" {
		return false
	}
	for key, value := range desired.Labels {
		if observed.Labels[key] != value {
			return false
		}
	}
	for key, value := range desired.Annotations {
		if observed.Annotations[key] != value {
			return false
		}
	}
	return true
}

func (r *V1Beta1Reconciler) recordCompletedChildren(next *attacknetv1beta1.AttacknetRunStatus, children []attacknetv1beta1.FaultCampaign, schedule betaSchedule, completed map[string]bool) error {
	known := make(map[string]betaExecution, len(schedule.Executions))
	for _, execution := range schedule.Executions {
		known[execution.ID] = execution
	}
	sort.Slice(children, func(left, right int) bool { return children[left].Name < children[right].Name })
	for index := range children {
		child := &children[index]
		id := child.Annotations[betaExecutionAnnotation]
		if _, ok := known[id]; !ok {
			return fmt.Errorf("child %s has unknown execution binding %q", child.Name, id)
		}
		if !betaTerminal(child.Status.Phase) || completed[id] {
			continue
		}
		at := r.now()
		if child.Status.CompletedAt != nil {
			at = child.Status.CompletedAt.Time.UTC()
		}
		decision := betaDecision{ExecutionID: id, Child: child.Name, ChildUID: string(child.UID), Phase: child.Status.Phase, CompletedAt: at, Source: child.Annotations[betaTemplateAnnotation]}
		value, err := betaJSON(decision)
		if err != nil {
			return err
		}
		next.Decisions = append(next.Decisions, value)
		completed[id] = true
	}
	return nil
}

func betaBudgetUsage(children []attacknetv1beta1.FaultCampaign, schedule betaSchedule, completed map[string]bool) (*attacknetv1beta1.BudgetUsage, error) {
	usage := &attacknetv1beta1.BudgetUsage{}
	seen := map[string]bool{}
	for index := range children {
		child := &children[index]
		id := child.Annotations[betaExecutionAnnotation]
		execution, ok := executionByID(schedule, id)
		if !ok || seen[id] {
			return nil, fmt.Errorf("owned campaign %s has unknown or duplicate execution binding", child.Name)
		}
		seen[id] = true
		digest, err := canonical.ArtifactDigest(child.Spec)
		if err != nil || digest != execution.CampaignSpecDigest || child.Annotations[betaScheduleAnnotation] != schedule.Integrity.Digest {
			return nil, fmt.Errorf("owned campaign %s differs from immutable schedule", child.Name)
		}
		usage.Campaigns++
		usage.CampaignsStarted++
		usage.CumulativeFaultMillis += execution.FaultDurationMillis
		usage.MaximumSignerImpactBasisPoints = max(usage.MaximumSignerImpactBasisPoints, execution.SignerImpactBasisPoints)
		usage.BurnchainFaults += execution.BurnchainFaults
		if completed[id] || betaTerminal(child.Status.Phase) {
			usage.CampaignsCompleted++
		} else {
			usage.ActiveCampaigns++
			if betaChildMutating(child.Status.Phase) {
				usage.ActiveFaults += execution.MaximumActiveFaults
			}
		}
		if child.Status.Phase == "Inconclusive" {
			usage.InconclusiveCampaigns++
		}
	}
	return usage, nil
}

func betaReservedImpact(children []attacknetv1beta1.FaultCampaign, schedule betaSchedule, completed map[string]bool) (int32, int32, error) {
	var faults, signerImpact int32
	seen := map[string]bool{}
	for index := range children {
		child := &children[index]
		id := child.Annotations[betaExecutionAnnotation]
		execution, ok := executionByID(schedule, id)
		if !ok || seen[id] {
			return 0, 0, fmt.Errorf("owned campaign %s has unknown or duplicate execution binding", child.Name)
		}
		seen[id] = true
		if completed[id] || betaTerminal(child.Status.Phase) {
			continue
		}
		faults += execution.MaximumActiveFaults
		signerImpact += execution.SignerImpactBasisPoints
	}
	return faults, signerImpact, nil
}

func betaDecisions(values []apixv1.JSON) ([]betaDecision, map[string]bool, error) {
	decisions := make([]betaDecision, 0, len(values))
	completed := map[string]bool{}
	for index, value := range values {
		var decision betaDecision
		if err := json.Unmarshal(value.Raw, &decision); err != nil || decision.ExecutionID == "" || !betaTerminal(decision.Phase) {
			return nil, nil, fmt.Errorf("decision %d is malformed", index)
		}
		if completed[decision.ExecutionID] {
			return nil, nil, fmt.Errorf("duplicate decision for execution %s", decision.ExecutionID)
		}
		completed[decision.ExecutionID] = true
		decisions = append(decisions, decision)
	}
	return decisions, completed, nil
}

func validateBetaDecisionBindings(decisions []betaDecision, children []attacknetv1beta1.FaultCampaign, schedule betaSchedule) error {
	byExecution := make(map[string]*attacknetv1beta1.FaultCampaign, len(children))
	for index := range children {
		id := children[index].Annotations[betaExecutionAnnotation]
		if id == "" || byExecution[id] != nil {
			return fmt.Errorf("owned child %s has an absent or duplicate execution binding", children[index].Name)
		}
		byExecution[id] = &children[index]
	}
	for _, decision := range decisions {
		if _, found := executionByID(schedule, decision.ExecutionID); !found {
			return fmt.Errorf("decision references unknown execution %s", decision.ExecutionID)
		}
		child := byExecution[decision.ExecutionID]
		if child == nil || child.Name != decision.Child || string(child.UID) != decision.ChildUID ||
			child.Annotations[betaTemplateAnnotation] != decision.Source || !betaTerminal(child.Status.Phase) || child.Status.Phase != decision.Phase {
			return fmt.Errorf("decision for execution %s does not match its terminal child", decision.ExecutionID)
		}
		if child.Status.CompletedAt == nil || !child.Status.CompletedAt.Time.Equal(decision.CompletedAt) {
			return fmt.Errorf("decision for execution %s has a different completion boundary", decision.ExecutionID)
		}
	}
	return nil
}

func betaExecutionTrigger(execution betaExecution) (trigger.Spec, error) {
	return trigger.ForRunExecution(attacknetv1beta1.RunExecutionSpec{
		ID: execution.ID, Trigger: *execution.Trigger.DeepCopy(),
		DependsOn: append([]attacknetv1beta1.RunExecutionDependency(nil), execution.Dependencies...),
	})
}

func (r *V1Beta1Reconciler) enforceIdentity(ctx context.Context, run *attacknetv1beta1.AttacknetRun, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, children []attacknetv1beta1.FaultCampaign, completed map[string]bool) (bool, error) {
	if run.Status.ScheduleSummary == nil {
		return false, r.fail(ctx, run, "ScheduleIntegrityFailed", errors.New("schedule summary is absent"))
	}
	expected := run.Status.ScheduleSummary.NetworkInventory
	allowed := betaAllowedPodTransitions(children, completed)
	differences := inventory.BetaCompareLive(expected, network, pods, allowed)
	if len(differences) > 0 {
		freshNetwork, freshChildren, freshDifferences, stable, err := r.recheckIdentitySnapshot(ctx, run, expected, completed)
		if err != nil {
			return false, err
		}
		if !stable || len(freshDifferences) == 0 {
			// Child status and Pod identity are separate API objects. A mutation
			// transition concurrent with the Pod read is not evidence of
			// divergence; retry until the authorization view brackets the Pod
			// snapshot instead of terminating from a mixed-time observation.
			return true, nil
		}
		network, children, differences = freshNetwork, freshChildren, freshDifferences
		context := betaIdentityContext(children, completed)
		for index := range differences {
			if differences[index].Message == "" {
				differences[index].Message = context
			}
		}
		now := metav1.NewTime(r.now())
		next := *run.Status.DeepCopy()
		next.IdentityDivergence = &attacknetv1beta1.IdentityDivergence{ExpectedDigest: expected.Digest, CurrentDigest: network.Status.InventoryDigest, ObservedAt: now, Differences: differences}
		return true, r.finish(ctx, run, next, "Inconclusive", "TargetIdentityDiverged", "Inconclusive")
	}
	if len(allowed) > 0 && network.Status.InventoryReady && network.Status.InventoryDigest != expected.Digest {
		current, err := inventory.BetaPublished(network)
		if err != nil {
			return false, err
		}
		now := metav1.NewTime(r.now())
		next := *run.Status.DeepCopy()
		next.ScheduleSummary.NetworkInventory = current
		actors := make([]string, 0, len(allowed))
		for actor := range allowed {
			actors = append(actors, actor)
		}
		sort.Strings(actors)
		next.IdentityTransitions = append(next.IdentityTransitions, attacknetv1beta1.IdentityTransition{Campaign: "concurrent-pod-transition", Actors: actors, PreviousDigest: expected.Digest, CurrentDigest: current.Digest, ObservedAt: now})
		return true, r.patchStatus(ctx, run, betaRunTransition(next, run.Generation, "Running", "ExpectedTargetIdentityTransition", "", r.now()))
	}
	return false, nil
}

func (r *V1Beta1Reconciler) recheckIdentitySnapshot(
	ctx context.Context,
	run *attacknetv1beta1.AttacknetRun,
	expected attacknetv1beta1.NetworkInventory,
	completed map[string]bool,
) (*attacknetv1beta1.StacksNetwork, []attacknetv1beta1.FaultCampaign, []attacknetv1beta1.IdentityDifference, bool, error) {
	before, err := r.children(ctx, run)
	if err != nil {
		return nil, nil, nil, false, err
	}
	beforeAllowed := betaAllowedPodTransitions(before, completed)
	live, err := inventory.ReadBetaLiveView(ctx, r.APIReader, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef})
	if err != nil {
		return nil, nil, nil, false, err
	}
	after, err := r.children(ctx, run)
	if err != nil {
		return nil, nil, nil, false, err
	}
	afterAllowed := betaAllowedPodTransitions(after, completed)
	if !reflect.DeepEqual(beforeAllowed, afterAllowed) {
		return live.Network, after, nil, false, nil
	}
	differences := inventory.BetaCompareLive(expected, live.Network, live.Pods, afterAllowed)
	return live.Network, after, differences, true, nil
}

func betaIdentityContext(children []attacknetv1beta1.FaultCampaign, completed map[string]bool) string {
	states := make([]string, 0, len(children))
	for index := range children {
		child := &children[index]
		execution := child.Annotations[betaExecutionAnnotation]
		actions := make([]string, 0)
		for _, stage := range child.Status.Stages {
			for _, action := range stage.Actions {
				actions = append(actions, fmt.Sprintf("%s:%s:mutation=%t:targets=%d", action.ID, action.Phase, action.Mutation != nil, len(action.ResolvedTargets)))
			}
		}
		sort.Strings(actions)
		states = append(states, fmt.Sprintf("%s:uid=%s:rv=%s:%s:execution=%s:completed=%t:actions=[%s]", child.Name, child.UID, child.ResourceVersion, child.Status.Phase, execution, completed[execution], strings.Join(actions, ",")))
	}
	sort.Strings(states)
	if len(states) == 0 {
		return "no owned child campaign was observed"
	}
	return strings.Join(states, ";")
}

func betaAllowedPodTransitions(children []attacknetv1beta1.FaultCampaign, completed map[string]bool) map[string]struct{} {
	allowed := map[string]struct{}{}
	for index := range children {
		child := &children[index]
		if completed[child.Annotations[betaExecutionAnnotation]] {
			continue
		}
		if child.Status.Phase != "Running" && !betaTerminal(child.Status.Phase) {
			continue
		}
		for _, stage := range child.Status.Stages {
			for _, action := range stage.Actions {
				if action.Mutation == nil || !betaPodIdentityTransitionPhase(action.Phase) {
					continue
				}
				for _, configured := range child.Spec.Stages {
					for _, declared := range configured.Faults {
						if declared.ID == action.ID && declared.Fault.Type == "pod" && declared.Fault.Action == "pod-kill" {
							for _, target := range action.ResolvedTargets {
								allowed[target.Actor] = struct{}{}
							}
						}
					}
				}
			}
		}
	}
	return allowed
}

func betaPodIdentityTransitionPhase(phase string) bool {
	switch phase {
	case "Injecting", "Active", "Recovering", "Completed":
		return true
	default:
		return false
	}
}

func (r *V1Beta1Reconciler) reconcileDeletion(ctx context.Context, run *attacknetv1beta1.AttacknetRun) (reconcile.Result, error) {
	if !containsString(run.Finalizers, betaRunFinalizer) {
		return reconcile.Result{}, nil
	}
	children, err := r.children(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	}
	if len(children) > 0 {
		for index := range children {
			if children[index].DeletionTimestamp.IsZero() {
				if err := r.Delete(ctx, &children[index]); err != nil && !apierrors.IsNotFound(err) {
					return reconcile.Result{}, err
				}
			}
		}
		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	}
	base := run.DeepCopy()
	run.Finalizers = removeString(run.Finalizers, betaRunFinalizer)
	return reconcile.Result{}, r.Patch(ctx, run, client.MergeFrom(base))
}

func (r *V1Beta1Reconciler) reconcileTerminal(ctx context.Context, run *attacknetv1beta1.AttacknetRun) (reconcile.Result, error) {
	children, err := r.children(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	}
	if err := r.requestChildCleanup(ctx, children); err != nil {
		return reconcile.Result{}, err
	}
	next := *run.Status.DeepCopy()
	now := metav1.NewTime(r.now())
	next.Cleanup = betaRunCleanup(children, next.Cleanup, now)
	if next.Cleanup.Completed {
		next.ActiveChildren = nil
		if next.FinishedAt == nil {
			next.FinishedAt = &now
		}
		next.TerminalClassification = classifyBeta(run, children)
	} else {
		next.FinishedAt = nil
		next.TerminalClassification = nil
	}
	if err := r.patchStatus(ctx, run, next); err != nil {
		return reconcile.Result{}, err
	}
	if !next.Cleanup.Completed {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	}
	return reconcile.Result{}, r.releaseTerminalFinalizer(ctx, run)
}

func (r *V1Beta1Reconciler) releaseTerminalFinalizer(ctx context.Context, run *attacknetv1beta1.AttacknetRun) error {
	if !containsString(run.Finalizers, betaRunFinalizer) {
		return nil
	}
	base := run.DeepCopy()
	run.Finalizers = removeString(run.Finalizers, betaRunFinalizer)
	return r.Patch(ctx, run, client.MergeFrom(base))
}

func betaRunCleanup(children []attacknetv1beta1.FaultCampaign, existing *attacknetv1beta1.RunCleanup, now metav1.Time) *attacknetv1beta1.RunCleanup {
	pending := 0
	for index := range children {
		child := &children[index]
		if !betaTerminal(child.Status.Phase) || child.Status.Cleanup == nil || !child.Status.Cleanup.Absent || !child.Status.Cleanup.AllRecovered {
			pending++
		}
	}
	if pending > 0 {
		return &attacknetv1beta1.RunCleanup{Required: true, Message: fmt.Sprintf("waiting for %d owned child campaign(s) to prove cleanup", pending)}
	}
	at := &now
	if existing != nil && existing.CompletedAt != nil {
		at = existing.CompletedAt.DeepCopy()
	}
	return &attacknetv1beta1.RunCleanup{Required: true, Completed: true, CompletedAt: at, Message: "all owned child campaigns proved cleanup"}
}

func classifyBeta(run *attacknetv1beta1.AttacknetRun, children []attacknetv1beta1.FaultCampaign) *attacknetv1beta1.TerminalClassification {
	expectedAssertion, expectedStatus, attempt, candidateDigest := "", "", "", ""
	if run.Spec.Minimization.Enabled {
		expectedAssertion, expectedStatus, attempt, candidateDigest = run.Spec.Minimization.ExpectedAssertion, run.Spec.Minimization.ExpectedStatus, run.Spec.Minimization.AttemptID, run.Spec.Minimization.CandidateScheduleDigest
	} else if run.Spec.Replay.Enabled && run.Spec.Replay.VerifyExpectedFailure {
		expectedAssertion, expectedStatus, attempt, candidateDigest = run.Spec.Replay.ExpectedAssertion, run.Spec.Replay.ExpectedStatus, run.Spec.Replay.AttemptID, run.Spec.Replay.DescriptorDigest
	} else {
		return nil
	}
	sort.Slice(children, func(left, right int) bool { return children[left].Name < children[right].Name })
	evidence := make([]map[string]any, 0, len(children))
	matching := []map[string]any{}
	for _, child := range children {
		effect, recovery := []map[string]any{}, []map[string]any{}
		for _, stage := range child.Status.Stages {
			stageEffect, stageRecovery := betaStageAssertionResults(stage)
			effect = append(effect, stageEffect...)
			recovery = append(recovery, stageRecovery...)
		}
		evidence = append(evidence, map[string]any{"name": child.Name, "uid": string(child.UID), "phase": defaultString(child.Status.Phase, "Pending"), "reason": child.Status.Reason, "effectResults": effect, "recoveryResults": recovery})
		for _, result := range append(tagResults(effect, child.Name, "effect"), tagResults(recovery, child.Name, "recovery")...) {
			if result["assertion"] == expectedAssertion {
				matching = append(matching, result)
			}
		}
	}
	outcome, reason := "Inconclusive", "ExpectedAssertionNotEvaluated"
	if len(matching) > 256 {
		reason = "AssertionEvidenceLimitExceeded"
	} else if len(matching) > 0 {
		allExpected, anyExpected, allDefinite := true, false, true
		for _, result := range matching {
			status := fmt.Sprint(result["outcome"])
			allExpected = allExpected && status == expectedStatus
			anyExpected = anyExpected || status == expectedStatus
			allDefinite = allDefinite && (status == "Proven" || status == "Failed")
		}
		switch {
		case allExpected:
			outcome, reason = "FailureReproduced", "ExpectedAssertionObserved"
		case anyExpected:
			outcome, reason = "Inconclusive", "ConflictingExpectedAssertionEvidence"
		case allDefinite:
			outcome, reason = "FailureAbsent", "ExpectedAssertionEvaluatedWithoutExpectedStatus"
		default:
			outcome, reason = "Inconclusive", "ExpectedAssertionInconclusive"
		}
	}
	stored := make([]apixv1.JSON, 0, min(len(matching), 256))
	for _, result := range matching[:min(len(matching), 256)] {
		value := map[string]any{"child": result["child"], "source": result["source"], "outcome": result["outcome"]}
		if actor, ok := result["actor"]; ok {
			value["actor"] = actor
		}
		raw, _ := betaJSON(value)
		stored = append(stored, raw)
	}
	scheduleDigest := ""
	if run.Status.ScheduleRef != nil {
		scheduleDigest = run.Status.ScheduleRef.Digest
	}
	digest, _ := canonical.ArtifactDigest(map[string]any{"runUID": string(run.UID), "scheduleDigest": scheduleDigest, "attemptId": attempt, "expectedAssertion": expectedAssertion, "expectedStatus": expectedStatus, "evidence": evidence})
	return &attacknetv1beta1.TerminalClassification{AttemptID: attempt, CandidateScheduleDigest: candidateDigest, ExpectedAssertion: expectedAssertion, ExpectedStatus: expectedStatus, Outcome: outcome, Reason: reason, ObservationCount: int32(len(matching)), Observations: stored, EvidenceDigest: digest, EvidenceURI: fmt.Sprintf("k8s://attacknetruns/%s/terminal-assertion-evidence", run.Name), CausalMinimalityClaimed: false}
}

// betaStageAssertionResults reads action-owned evidence once. Stage results are
// aggregates for operators and are only a fallback for pre-action status data.
func betaStageAssertionResults(stage attacknetv1beta1.FaultStageStatus) ([]map[string]any, []map[string]any) {
	if len(stage.Actions) == 0 {
		return decodeJSONValues(stage.EffectResults), decodeJSONValues(stage.RecoveryResults)
	}
	effect, recovery := []map[string]any{}, []map[string]any{}
	for _, action := range stage.Actions {
		effect = append(effect, decodeJSONValues(action.EffectResults)...)
		recovery = append(recovery, decodeJSONValues(action.RecoveryResults)...)
	}
	return effect, recovery
}

func (r *V1Beta1Reconciler) finish(ctx context.Context, run *attacknetv1beta1.AttacknetRun, next attacknetv1beta1.AttacknetRunStatus, phase, reason, attribution string) error {
	children, err := r.children(ctx, run)
	if err != nil {
		return err
	}
	if err := r.requestChildCleanup(ctx, children); err != nil {
		return err
	}
	now := metav1.NewTime(r.now())
	if next.CompletedAt == nil {
		next.CompletedAt = &now
	}
	next.Attribution = attribution
	next.Cleanup = betaRunCleanup(children, next.Cleanup, now)
	if next.Cleanup.Completed {
		next.ActiveChildren = nil
		next.FinishedAt = &now
		next.TerminalClassification = classifyBeta(run, children)
	} else {
		next.FinishedAt = nil
		next.TerminalClassification = nil
	}
	return r.patchStatus(ctx, run, betaRunTransition(next, run.Generation, phase, reason, next.Message, r.now()))
}

func betaStopDecision(run *attacknetv1beta1.AttacknetRun, decisions []betaDecision, usage *attacknetv1beta1.BudgetUsage) (string, string, string) {
	for _, decision := range decisions {
		switch decision.Phase {
		case "Failed":
			if run.Spec.StopPolicy.OnCampaignFailure == "Continue" {
				continue
			}
			if run.Spec.StopPolicy.OnCampaignFailure == "PauseForTriage" {
				return "Paused", "ChildCampaignFailed", "Untriaged"
			}
			return "Failed", "ChildCampaignFailed", "Untriaged"
		case "Inconclusive":
			if run.Spec.StopPolicy.OnInconclusive == "Continue" && usage.InconclusiveCampaigns <= run.Spec.Budgets.MaxInconclusiveCampaigns {
				continue
			}
			if run.Spec.StopPolicy.OnInconclusive == "PauseForTriage" {
				return "Paused", "ChildCampaignInconclusive", "Untriaged"
			}
			return "Inconclusive", "ChildCampaignInconclusive", "Untriaged"
		case "Passed":
			if run.Spec.StopPolicy.OnSuccess == "Stop" {
				return "Passed", "StoppedAfterSuccessfulCampaign", "NotRequired"
			}
		}
	}
	return "", "", ""
}

func (r *V1Beta1Reconciler) budgetTerminal(ctx context.Context, run *attacknetv1beta1.AttacknetRun, next attacknetv1beta1.AttacknetRunStatus, reason string) error {
	if run.Spec.StopPolicy.OnBudgetExhausted == "Pause" {
		return r.pauseWithCleanup(ctx, run, next, reason, "")
	}
	return r.finish(ctx, run, next, "Failed", reason, "Inconclusive")
}

func (r *V1Beta1Reconciler) fail(ctx context.Context, run *attacknetv1beta1.AttacknetRun, reason string, cause error) error {
	next := *run.Status.DeepCopy()
	next.Message = truncate(cause.Error(), 1000)
	return r.finish(ctx, run, next, "Failed", reason, "Inconclusive")
}
func (r *V1Beta1Reconciler) pause(ctx context.Context, run *attacknetv1beta1.AttacknetRun, reason, message string) error {
	return r.pauseWithCleanup(ctx, run, run.Status, reason, message)
}

func (r *V1Beta1Reconciler) pauseWithCleanup(
	ctx context.Context,
	run *attacknetv1beta1.AttacknetRun,
	next attacknetv1beta1.AttacknetRunStatus,
	reason string,
	message string,
) error {
	children, err := r.children(ctx, run)
	if err != nil {
		return err
	}
	if err := r.requestChildCleanup(ctx, children); err != nil {
		return err
	}
	return r.patchStatus(ctx, run, betaRunTransition(next, run.Generation, "Paused", reason, truncate(message, 1000), r.now()))
}

func (r *V1Beta1Reconciler) requestChildCleanup(ctx context.Context, children []attacknetv1beta1.FaultCampaign) error {
	for index := range children {
		child := &children[index]
		if betaTerminal(child.Status.Phase) || !child.DeletionTimestamp.IsZero() {
			continue
		}
		if err := r.Delete(ctx, child); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
func (r *V1Beta1Reconciler) transition(ctx context.Context, run *attacknetv1beta1.AttacknetRun, phase, reason, message string) error {
	return r.patchStatus(ctx, run, betaRunTransition(run.Status, run.Generation, phase, reason, message, r.now()))
}
func (r *V1Beta1Reconciler) patchStatus(ctx context.Context, run *attacknetv1beta1.AttacknetRun, next attacknetv1beta1.AttacknetRunStatus) error {
	if reflect.DeepEqual(run.Status, next) {
		return nil
	}
	base := run.DeepCopy()
	run.Status = next
	return r.Status().Patch(ctx, run, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func betaRunTransition(status attacknetv1beta1.AttacknetRunStatus, generation int64, phase, reason, message string, now time.Time) attacknetv1beta1.AttacknetRunStatus {
	status = *status.DeepCopy()
	changed := status.Phase != phase || status.Reason != reason
	status.ObservedGeneration, status.Phase, status.Reason, status.Message = generation, phase, reason, message
	if changed || status.LastTransitionTime == nil {
		at := metav1.NewTime(now)
		status.LastTransitionTime = &at
	}
	condition := metav1.ConditionFalse
	if phase == "Passed" {
		condition = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Succeeded", Status: condition, ObservedGeneration: generation, Reason: reason, Message: message})
	return status
}

func (r *V1Beta1Reconciler) children(ctx context.Context, run *attacknetv1beta1.AttacknetRun) ([]attacknetv1beta1.FaultCampaign, error) {
	list := &attacknetv1beta1.FaultCampaignList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(run.Namespace)); err != nil {
		return nil, err
	}
	result := []attacknetv1beta1.FaultCampaign{}
	seen := make(map[string]struct{}, len(list.Items))
	for _, item := range list.Items {
		if !betaOwnedByRun(&item, run) {
			continue
		}
		current := &attacknetv1beta1.FaultCampaign{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(&item), current); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		if betaOwnedByRun(current, run) {
			result = append(result, *current)
			seen[current.Name] = struct{}{}
		}
	}
	if run.DeletionTimestamp.IsZero() {
		for _, active := range run.Status.ActiveChildren {
			if _, ok := seen[active.Name]; ok {
				continue
			}
			current := &attacknetv1beta1.FaultCampaign{}
			key := types.NamespacedName{Namespace: run.Namespace, Name: active.Name}
			if err := r.APIReader.Get(ctx, key, current); err != nil {
				return nil, fmt.Errorf("read active child %s: %w", active.Name, err)
			}
			if string(current.UID) != active.UID || !betaOwnedByRun(current, run) {
				return nil, fmt.Errorf("active child %s no longer matches its run-owned identity", active.Name)
			}
			result = append(result, *current)
			seen[current.Name] = struct{}{}
		}
	}
	return result, nil
}

func betaOwnedByRun(child *attacknetv1beta1.FaultCampaign, run *attacknetv1beta1.AttacknetRun) bool {
	owner := metav1.GetControllerOf(child)
	return owner != nil && owner.UID == run.UID && owner.APIVersion == attacknetv1beta1.GroupVersion.String() && owner.Kind == "AttacknetRun"
}

func (r *V1Beta1Reconciler) runIsCurrent(ctx context.Context, cached *attacknetv1beta1.AttacknetRun) (bool, error) {
	if r.APIReader == nil {
		return false, errors.New("v1beta1 run reconciler requires an uncached Kubernetes API reader")
	}
	live := &attacknetv1beta1.AttacknetRun{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(cached), live); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return cached.ResourceVersion == live.ResourceVersion, nil
}
func (r *V1Beta1Reconciler) store() betaScheduleStore {
	return betaScheduleStore{writer: r.Client, reader: r.APIReader}
}
func (r *V1Beta1Reconciler) signerResolver() signerset.Resolver {
	if r.SignerSets != nil {
		return r.SignerSets
	}
	return &signerset.HTTPResolver{}
}
func (r *V1Beta1Reconciler) observationReader() ObservationReader {
	if r.Observations != nil {
		return r.Observations
	}
	return &KubernetesObservationReader{Reader: r.APIReader}
}
func (r *V1Beta1Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func betaTerminal(phase string) bool {
	return phase == "Passed" || phase == "Failed" || phase == "Inconclusive"
}
func betaChildMutating(phase string) bool {
	return phase == "Injecting" || phase == "Active" || phase == "Recovering"
}
func activeBetaChildren(children []attacknetv1beta1.FaultCampaign) []attacknetv1beta1.FaultCampaign {
	result := []attacknetv1beta1.FaultCampaign{}
	for _, child := range children {
		if !betaTerminal(child.Status.Phase) {
			result = append(result, child)
		}
	}
	return result
}
func betaStartedExecutions(children []attacknetv1beta1.FaultCampaign) map[string]bool {
	result := map[string]bool{}
	for _, child := range children {
		if id := child.Annotations[betaExecutionAnnotation]; id != "" {
			result[id] = true
		}
	}
	return result
}
func betaActiveStatus(children []attacknetv1beta1.FaultCampaign) []attacknetv1beta1.ActiveRunChild {
	result := []attacknetv1beta1.ActiveRunChild{}
	for index := range children {
		child := &children[index]
		if betaTerminal(child.Status.Phase) {
			continue
		}
		result = append(result, attacknetv1beta1.ActiveRunChild{ExecutionID: child.Annotations[betaExecutionAnnotation], Name: child.Name, UID: string(child.UID), StartedAt: child.Status.LastTransitionTime})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ExecutionID < result[j].ExecutionID })
	return result
}
func upsertBetaResolved(values []attacknetv1beta1.ResolvedCampaign, execution betaExecution) []attacknetv1beta1.ResolvedCampaign {
	value := attacknetv1beta1.ResolvedCampaign{Name: execution.CampaignAlias, SourceName: execution.Source.Name, SourceUID: execution.Source.UID, SourceGeneration: execution.Source.Generation, SpecDigest: execution.Source.SpecDigest}
	for i := range values {
		if values[i].Name == value.Name {
			values[i] = value
			return values
		}
	}
	return append(values, value)
}
func betaJSON(value any) (apixv1.JSON, error) {
	encoded, err := json.Marshal(value)
	return apixv1.JSON{Raw: encoded}, err
}
func betaNextRequeue(schedule betaSchedule, started map[string]bool, snapshot trigger.Snapshot) time.Duration {
	next := 5 * time.Second
	for _, execution := range schedule.Executions {
		if started[execution.ID] {
			continue
		}
		spec, err := betaExecutionTrigger(execution)
		if err != nil {
			continue
		}
		decision, err := trigger.Evaluate(spec, snapshot)
		if err == nil && decision.RequeueAt != nil {
			delay := decision.RequeueAt.Sub(snapshot.Now)
			if delay < 0 {
				delay = time.Second
			}
			if delay < next {
				next = delay
			}
		}
	}
	return next
}
func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func removeString(values []string, value string) []string {
	result := values[:0]
	for _, item := range values {
		if item != value {
			result = append(result, item)
		}
	}
	return result
}

// SetupWithManager registers v1beta1 run, child campaign, and network watches.
func (r *V1Beta1Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if r.APIReader == nil {
		return errors.New("v1beta1 AttacknetRun reconciler requires an uncached Kubernetes API reader")
	}
	mapNetwork := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
		list := &attacknetv1beta1.AttacknetRunList{}
		if err := r.List(ctx, list, client.InNamespace(object.GetNamespace()), client.MatchingFields{"spec.networkRef": object.GetName()}); err != nil {
			return nil
		}
		result := make([]reconcile.Request, len(list.Items))
		for i := range list.Items {
			result[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
		}
		return result
	})
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &attacknetv1beta1.AttacknetRun{}, "spec.networkRef", func(object client.Object) []string {
		return []string{object.(*attacknetv1beta1.AttacknetRun).Spec.NetworkRef}
	}); err != nil {
		return err
	}
	return builder.ControllerManagedBy(mgr).For(&attacknetv1beta1.AttacknetRun{}).Owns(&corev1.ConfigMap{}).Owns(&attacknetv1beta1.FaultCampaign{}).Watches(&attacknetv1beta1.StacksNetwork{}, mapNetwork).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).Complete(r)
}
