package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
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

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
)

// Reconciler executes immutable AttacknetRun schedules one campaign at a time.
type Reconciler struct {
	client.Client
	APIReader  client.Reader
	Scheme     *runtime.Scheme
	Now        func() time.Time
	SignerSets signerset.Resolver
}

// Reconcile advances one run by at most one durable transition.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	run := &attacknetv1alpha1.AttacknetRun{}
	if err := r.Get(ctx, request.NamespacedName, run); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	current, err := r.runIsCurrent(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !current {
		return reconcile.Result{Requeue: true}, nil
	}
	if !run.DeletionTimestamp.IsZero() || run.Status.Phase == "Paused" {
		return reconcile.Result{}, nil
	}
	if terminal(run.Status.Phase) {
		return r.reconcileTerminal(ctx, run)
	}
	network := &attacknetv1alpha1.StacksNetwork{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef}, network); err != nil {
		return reconcile.Result{}, err
	}
	children, err := r.children(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	}
	active := activeChild(children)
	if network.Status.Phase != "Ready" && active == nil {
		reason := "NetworkNotReady"
		phase := "Pending"
		if run.Status.ScheduleRef != nil {
			reason = "WaitingForNetworkRecovery"
			phase = "Running"
		}
		return reconcile.Result{RequeueAfter: 5 * time.Second}, r.transition(ctx, run, phase, reason, "")
	}
	if run.Status.ScheduleRef == nil {
		return reconcile.Result{}, r.prepare(ctx, run)
	}
	schedule, err := r.readSchedule(ctx, run, *run.Status.ScheduleRef)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "ScheduleIntegrityFailed", err)
	}
	decisionMaps, completed, err := validatedDecisions(run.Status.Decisions)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", err)
	}
	if len(decisionMaps) > len(schedule.Actions) {
		return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", errors.New("recorded decisions exceed the immutable schedule"))
	}
	if run.Status.ScheduleRef.RunGeneration != run.Generation {
		return reconcile.Result{}, r.fail(ctx, run, "AdmittedRunChanged", errors.New("run generation changed after schedule admission"))
	}
	live, err := inventory.ReadLiveView(ctx, r.APIReader, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef})
	if err != nil {
		return reconcile.Result{}, err
	}
	network, pods := live.Network, live.Pods
	if schedule.Network.UID != string(network.UID) || schedule.Network.Generation != network.Generation || schedule.Network.Name != run.Spec.NetworkRef {
		return reconcile.Result{}, r.fail(ctx, run, "AdmittedNetworkChanged", errors.New("network identity changed after schedule admission"))
	}
	if run.Status.ScheduleSummary == nil || run.Status.ScheduleSummary.NetworkInventory.Digest == "" {
		return reconcile.Result{}, r.fail(ctx, run, "ScheduleIntegrityFailed", errors.New("persisted schedule lacks its admitted network inventory summary"))
	}
	identityChanged, err := r.enforceIdentity(ctx, run, network, pods, children, active, completed)
	if err != nil {
		return reconcile.Result{}, err
	}
	if identityChanged {
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	if terminal(run.Status.Phase) {
		return reconcile.Result{}, nil
	}
	usage, err := budgetUsageFromChildren(run, children, schedule)
	if err != nil {
		return reconcile.Result{}, r.transition(ctx, run, "Paused", "ChildCampaignIntegrityFailed", truncate(err.Error(), 1000))
	}
	if run.Status.StartedAt != nil {
		usage.WallTimeSeconds = r.now().Sub(run.Status.StartedAt.Time).Seconds()
	}
	if usage.WallTimeSeconds > float64(run.Spec.Budgets.MaxWallTimeSeconds) {
		return reconcile.Result{}, r.budgetTerminal(ctx, run, "WallTimeBudgetExhausted", usage)
	}
	if active != nil {
		next := *run.Status.DeepCopy()
		next.ActiveCampaign = ptr(active.Name)
		next.ActiveChild = &attacknetv1alpha1.ActiveRunChild{Name: active.Name, UID: string(active.UID), InstructionID: active.Annotations["testing.stacks.org/instruction-id"]}
		usage.ActiveFaults = 1
		next.BudgetUsage = usage
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Running", "CampaignActive", "", r.now()))
	}
	decisions := append([]apixv1.JSON(nil), run.Status.Decisions...)
	sort.Slice(children, func(i, j int) bool { return children[i].CreationTimestamp.Before(&children[j].CreationTimestamp) })
	for _, child := range children {
		if !terminal(child.Status.Phase) || completed[child.Name] {
			continue
		}
		decisionMap := map[string]any{"index": len(decisions), "execution": child.Name, "instructionId": child.Annotations["testing.stacks.org/instruction-id"], "phase": child.Status.Phase, "completedAt": timeValue(child.Status.CompletedAt, r.now()), "source": child.Annotations["testing.stacks.org/source-template"]}
		decision, err := jsonValue(decisionMap)
		if err != nil {
			return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", err)
		}
		decisions = append(decisions, decision)
		decisionMaps = append(decisionMaps, decisionMap)
		completed[child.Name] = true
	}
	next := *run.Status.DeepCopy()
	next.Decisions = decisions
	next.ActiveCampaign = nil
	next.ActiveChild = nil
	usage.ActiveFaults = 0
	next.BudgetUsage = usage
	if len(decisions) > 0 {
		latest := decisionMaps[len(decisionMaps)-1]
		phase, _ := latest["phase"].(string)
		switch phase {
		case "Failed":
			if run.Spec.StopPolicy.OnCampaignFailure == "PauseForTriage" {
				return reconcile.Result{}, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Paused", "ChildCampaignFailed", "", r.now()))
			}
			return reconcile.Result{}, r.finish(ctx, run, next, "Failed", "ChildCampaignFailed", "Untriaged")
		case "Inconclusive":
			if run.Spec.StopPolicy.OnInconclusive != "Continue" || usage.InconclusiveCampaigns > run.Spec.Budgets.MaxInconclusiveCampaigns {
				if run.Spec.StopPolicy.OnInconclusive == "PauseForTriage" {
					return reconcile.Result{}, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Paused", "ChildCampaignInconclusive", "", r.now()))
				}
				return reconcile.Result{}, r.finish(ctx, run, next, "Inconclusive", "ChildCampaignInconclusive", "Untriaged")
			}
		case "Passed":
			if run.Spec.StopPolicy.OnSuccess == "Stop" {
				return reconcile.Result{}, r.finish(ctx, run, next, "Passed", "StoppedAfterSuccessfulCampaign", "NotRequired")
			}
		}
	}
	if len(decisions) >= len(schedule.Actions) || int32(len(decisions)) >= run.Spec.Budgets.MaxCampaigns {
		return reconcile.Result{}, r.finish(ctx, run, next, "Passed", "SequenceCompleted", "NotRequired")
	}
	if len(decisions) > 0 {
		prior := schedule.Actions[len(decisions)-1]
		latest := decisionMaps[len(decisionMaps)-1]
		completedAt, err := time.Parse(time.RFC3339Nano, fmt.Sprint(latest["completedAt"]))
		if err != nil {
			return reconcile.Result{}, r.fail(ctx, run, "DecisionIntegrityFailed", err)
		}
		if r.now().Sub(completedAt) < time.Duration(prior.DelayAfterSeconds)*time.Second {
			return reconcile.Result{RequeueAfter: time.Second}, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Running", "InterCampaignDelay", "", r.now()))
		}
	}
	action := schedule.Actions[len(decisions)]
	if run.Status.StartedAt != nil && r.now().Sub(run.Status.StartedAt.Time).Seconds() < action.NotBeforeOffsetSeconds {
		return reconcile.Result{RequeueAfter: time.Second}, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Running", "ScheduledStartPending", "", r.now()))
	}
	currentSignerSet, err := r.signerResolver().Resolve(ctx, network, pods)
	if err != nil {
		var transient *signerset.TransientError
		if errors.As(err, &transient) {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, r.finish(ctx, run, next, "Failed", "SignerSetParityFailed", "Inconclusive")
	}
	manifestDigest, err := canonical.ArtifactDigest(canonicalManifest(network, currentSignerSet.WeightsByActor))
	if err != nil {
		return reconcile.Result{}, err
	}
	if manifestDigest != schedule.Network.ManifestDigest {
		return reconcile.Result{}, r.finish(ctx, run, next, "Failed", "SignerSetChangedBeforeCampaign", "Inconclusive")
	}
	return reconcile.Result{}, r.startAction(ctx, run, next, action, usage)
}

// runIsCurrent prevents an informer-delayed reconcile from reversing a newer
// durable phase or acting on a superseded run specification.
func (r *Reconciler) runIsCurrent(ctx context.Context, cached *attacknetv1alpha1.AttacknetRun) (bool, error) {
	if r.APIReader == nil {
		return false, errors.New("run reconciler requires an uncached Kubernetes API reader")
	}
	live := &attacknetv1alpha1.AttacknetRun{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(cached), live); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return cached.ResourceVersion == live.ResourceVersion, nil
}

func (r *Reconciler) prepare(ctx context.Context, run *attacknetv1alpha1.AttacknetRun) error {
	live, err := inventory.ReadLiveView(ctx, r.APIReader, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.NetworkRef})
	if err != nil {
		return err
	}
	network, pods := live.Network, live.Pods
	published, err := inventory.Published(network)
	if err != nil {
		return r.transition(ctx, run, "Pending", "NetworkInventoryNotReady", err.Error())
	}
	if differences := inventory.CompareLive(published, network, pods, nil); len(differences) > 0 {
		return r.transition(ctx, run, "Pending", "NetworkInventoryNotReady", "published inventory differs from live Pods")
	}
	signerSet, err := r.signerResolver().Resolve(ctx, network, pods)
	if err != nil {
		var transient *signerset.TransientError
		if errors.As(err, &transient) {
			return err
		}
		return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
	}
	manifest := canonicalManifest(network, signerSet.WeightsByActor)
	templates := map[string]*attacknetv1alpha1.FaultCampaign{}
	for _, entry := range run.Spec.CampaignCatalog {
		source := &attacknetv1alpha1.FaultCampaign{}
		if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: entry.CampaignRef}, source); err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
		templates[source.Name] = source
	}
	var schedule resolvedSchedule
	if run.Spec.Replay.Enabled || run.Spec.Minimization.Enabled {
		sourceName := run.Spec.Replay.SourceRunRef
		if run.Spec.Minimization.Enabled {
			sourceName = run.Spec.Minimization.SourceRunRef
		}
		sourceRun := &attacknetv1alpha1.AttacknetRun{}
		if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: sourceName}, sourceRun); err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
		if !terminal(sourceRun.Status.Phase) || sourceRun.Status.ScheduleRef == nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", errors.New("source run must be terminal with a persisted schedule"))
		}
		source, err := r.readSchedule(ctx, sourceRun, *sourceRun.Status.ScheduleRef)
		if err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
		if run.Spec.Replay.Enabled {
			expectedURI := fmt.Sprintf("k8s://attacknetruns/%s/resolved-schedule", sourceRun.Name)
			if run.Spec.Replay.DescriptorURI != expectedURI {
				return r.fail(ctx, run, "ScheduleAdmissionFailed", fmt.Errorf("replay descriptorURI must be %s", expectedURI))
			}
			if run.Spec.Replay.DescriptorDigest != source.Integrity.Digest {
				return r.fail(ctx, run, "ScheduleAdmissionFailed", errors.New("replay descriptorDigest does not match source schedule"))
			}
		}
		schedule, err = applyReplay(source, run, network, published, manifest, templates, run.Spec.Minimization.Enabled)
		if err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
	} else {
		schedule, err = buildSchedule(run, network, published, templates, manifest)
		if err != nil {
			return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
		}
		if run.Spec.Resume.Enabled {
			if err := r.validateResume(ctx, run, schedule); err != nil {
				return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
			}
		}
	}
	reference, err := r.persistSchedule(ctx, run, schedule)
	if err != nil {
		return r.fail(ctx, run, "ScheduleAdmissionFailed", err)
	}
	started := metav1.NewTime(r.now())
	next := *run.Status.DeepCopy()
	next.StartedAt = &started
	next.ScheduleRef = &reference
	next.ScheduleSummary = &attacknetv1alpha1.ScheduleSummary{
		SchemaVersion:         schedule.SchemaVersion,
		Actions:               int32(len(schedule.Actions)),
		Replay:                run.Spec.Replay.Enabled || run.Spec.Minimization.Enabled,
		NetworkUID:            string(network.UID),
		NetworkGeneration:     network.Generation,
		ManifestDigest:        schedule.Network.ManifestDigest,
		SignerSetDigest:       signerSet.SignerSetDigest,
		SignerSetObservedFrom: signerSet.ObservedFrom,
		NetworkInventory:      published,
	}
	if signerSet.HasSigners {
		rewardCycle := signerSet.RewardCycle
		totalWeight := signerSet.ObservedTotalWeight
		next.ScheduleSummary.SignerSetRewardCycle = &rewardCycle
		next.ScheduleSummary.SignerSetTotalWeight = &totalWeight
	}
	next.BudgetUsage = &attacknetv1alpha1.BudgetUsage{MinimizationAttempts: ternary(run.Spec.Minimization.Enabled, int32(1), int32(0))}
	return r.patchStatus(ctx, run, runTransition(next, run.Generation, "Preparing", "ResolvedSchedulePersisted", "", r.now()))
}

func (r *Reconciler) validateResume(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, candidate resolvedSchedule) error {
	sourceRun := &attacknetv1alpha1.AttacknetRun{}
	key := types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.Resume.SourceRunRef}
	if err := r.APIReader.Get(ctx, key, sourceRun); err != nil {
		return err
	}
	if !terminal(sourceRun.Status.Phase) || sourceRun.Status.ScheduleRef == nil {
		return errors.New("resume source run must be terminal with a persisted schedule")
	}
	source, err := r.readSchedule(ctx, sourceRun, *sourceRun.Status.ScheduleRef)
	if err != nil {
		return err
	}
	if run.Spec.Resume.RequireSameSeed && fmt.Sprint(source.Run["seed"]) != run.Spec.Seed {
		return errors.New("resume seed differs from source schedule")
	}
	if run.Spec.Resume.RequireSameResolvedImages && !reflect.DeepEqual(source.ImageConstraints, candidate.ImageConstraints) {
		return errors.New("resume images differ from source schedule")
	}
	boundary := -1
	for index := range source.Actions {
		if source.Actions[index].InstructionID == run.Spec.Resume.AfterInstructionID {
			boundary = index
			break
		}
	}
	if boundary < 0 {
		return errors.New("resume boundary is absent from source schedule")
	}
	decisions, _, err := validatedDecisions(sourceRun.Status.Decisions)
	if err != nil {
		return fmt.Errorf("resume source decisions are invalid: %w", err)
	}
	completedBoundary := false
	for _, decision := range decisions {
		if decision["instructionId"] == run.Spec.Resume.AfterInstructionID {
			completedBoundary = true
			break
		}
	}
	if !completedBoundary {
		return errors.New("resume boundary was not completed by source run")
	}
	expected := source.Actions[boundary+1:]
	if len(expected) != len(candidate.Actions) {
		return errors.New("resume schedule differs from source suffix")
	}
	for index := range expected {
		if expected[index].InstructionID != candidate.Actions[index].InstructionID ||
			expected[index].Source != candidate.Actions[index].Source ||
			expected[index].Resolved.CampaignSpecDigest != candidate.Actions[index].Resolved.CampaignSpecDigest {
			return fmt.Errorf("resume instruction %d differs from immutable source suffix", index+1)
		}
	}
	return nil
}

func (r *Reconciler) persistSchedule(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, schedule resolvedSchedule) (attacknetv1alpha1.ScheduleReference, error) {
	return r.scheduleStore().persist(ctx, run, schedule)
}
func (r *Reconciler) readSchedule(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, reference attacknetv1alpha1.ScheduleReference) (resolvedSchedule, error) {
	return r.scheduleStore().read(ctx, run, reference)
}

func (r *Reconciler) scheduleStore() scheduleStore {
	return scheduleStore{writer: r.Client, reader: r.APIReader}
}

func (r *Reconciler) startAction(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, next attacknetv1alpha1.AttacknetRunStatus, action action, usage *attacknetv1alpha1.BudgetUsage) error {
	child := desiredExecutionCampaign(run, action)
	digest, _ := canonical.ArtifactDigest(child.Spec)
	if digest != action.Resolved.CampaignSpecDigest {
		return r.fail(ctx, run, "ScheduleIntegrityFailed", errors.New("resolved campaign spec digest mismatch"))
	}
	usage.Campaigns++
	usage.CampaignsStarted++
	usage.ActiveFaults = 1
	usage.CumulativeFaultSeconds += action.BudgetCharge.FaultSeconds
	usage.MaximumSignerImpactPercent = max(usage.MaximumSignerImpactPercent, action.BudgetCharge.SignerImpactPercent)
	usage.BurnchainFaults += action.BudgetCharge.BurnchainFaults
	if usage.Campaigns > run.Spec.Budgets.MaxCampaigns || usage.CumulativeFaultSeconds > float64(run.Spec.Budgets.MaxCumulativeFaultSeconds) || usage.MaximumSignerImpactPercent > float64(run.Spec.Budgets.MaxSignerImpactPercent) || usage.BurnchainFaults > run.Spec.Budgets.MaxBurnchainFaults {
		return r.budgetTerminal(ctx, run, "CampaignBudgetExhausted", usage)
	}
	desired := child.DeepCopy()
	if err := r.Create(ctx, child); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		child = &attacknetv1alpha1.FaultCampaign{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(desired), child); err != nil {
			return err
		}
	}
	if !executionCampaignMatches(run, desired, child) {
		return r.fail(ctx, run, "CampaignIdentityConflict", fmt.Errorf("refusing to adopt FaultCampaign %s with different ownership or execution inputs", child.Name))
	}
	next.ActiveCampaign = ptr(child.Name)
	next.BudgetUsage = usage
	next.ResolvedCampaigns = upsertResolved(next.ResolvedCampaigns, attacknetv1alpha1.ResolvedCampaign{Name: action.CampaignAlias, SourceName: action.Source.Name, SourceUID: action.Source.UID, SourceGeneration: action.Source.Generation, SpecDigest: action.Source.SpecDigest})
	return r.patchStatus(ctx, run, runTransition(next, run.Generation, "Running", "CampaignCreated", "", r.now()))
}

func desiredExecutionCampaign(run *attacknetv1alpha1.AttacknetRun, action action) *attacknetv1alpha1.FaultCampaign {
	spec := action.Resolved.CampaignSpec
	spec.Template = false
	return &attacknetv1alpha1.FaultCampaign{
		TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1alpha1.GroupVersion.String(), Kind: "FaultCampaign"},
		ObjectMeta: metav1.ObjectMeta{
			Name: stableName(run.Name, fmt.Sprint(action.Order), action.InstructionID), Namespace: run.Namespace,
			Labels: map[string]string{fault.NetworkLabel: run.Spec.NetworkRef, "testing.stacks.org/run": run.Name},
			Annotations: map[string]string{
				"testing.stacks.org/source-template":            action.Source.Name,
				"testing.stacks.org/source-template-uid":        action.Source.UID,
				"testing.stacks.org/source-template-generation": fmt.Sprint(action.Source.Generation),
				"testing.stacks.org/source-template-digest":     action.Source.SpecDigest,
				"testing.stacks.org/schedule-digest":            run.Status.ScheduleRef.Digest,
				"testing.stacks.org/instruction-id":             action.InstructionID,
			},
			OwnerReferences: []metav1.OwnerReference{ownership.Reference(run, attacknetv1alpha1.GroupVersion.WithKind("AttacknetRun"))},
		},
		Spec: spec,
	}
}

func budgetUsageFromChildren(run *attacknetv1alpha1.AttacknetRun, children []attacknetv1alpha1.FaultCampaign, schedule resolvedSchedule) (*attacknetv1alpha1.BudgetUsage, error) {
	usage := &attacknetv1alpha1.BudgetUsage{MinimizationAttempts: ternary(run.Spec.Minimization.Enabled, int32(1), int32(0))}
	actions := make(map[string]action, len(schedule.Actions))
	for _, item := range schedule.Actions {
		if _, exists := actions[item.InstructionID]; exists {
			return nil, fmt.Errorf("schedule contains duplicate instruction %s", item.InstructionID)
		}
		actions[item.InstructionID] = item
	}
	seen := map[string]bool{}
	for index := range children {
		child := &children[index]
		instruction := child.Annotations["testing.stacks.org/instruction-id"]
		item, ok := actions[instruction]
		if !ok || seen[instruction] {
			return nil, fmt.Errorf("owned campaign %s has an unknown or duplicate instruction binding", child.Name)
		}
		seen[instruction] = true
		if !executionCampaignMatches(run, desiredExecutionCampaign(run, item), child) {
			return nil, fmt.Errorf("owned campaign %s differs from its immutable schedule action", child.Name)
		}
		usage.Campaigns++
		usage.CampaignsStarted++
		usage.CumulativeFaultSeconds += item.BudgetCharge.FaultSeconds
		usage.MaximumSignerImpactPercent = max(usage.MaximumSignerImpactPercent, item.BudgetCharge.SignerImpactPercent)
		usage.BurnchainFaults += item.BudgetCharge.BurnchainFaults
		if terminal(child.Status.Phase) {
			usage.CampaignsCompleted++
			if child.Status.Phase == "Inconclusive" {
				usage.InconclusiveCampaigns++
			}
		} else {
			usage.ActiveFaults++
		}
	}
	if usage.ActiveFaults > 1 {
		return nil, fmt.Errorf("run has %d concurrently active owned campaigns", usage.ActiveFaults)
	}
	return usage, nil
}

func executionCampaignMatches(run *attacknetv1alpha1.AttacknetRun, desired, observed *attacknetv1alpha1.FaultCampaign) bool {
	if desired.Name != observed.Name || desired.Namespace != observed.Namespace || !reflect.DeepEqual(desired.Spec, observed.Spec) {
		return false
	}
	owner := metav1.GetControllerOf(observed)
	if owner == nil || owner.UID != run.UID || owner.APIVersion != attacknetv1alpha1.GroupVersion.String() || owner.Kind != "AttacknetRun" {
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

func (r *Reconciler) enforceIdentity(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, children []attacknetv1alpha1.FaultCampaign, active *attacknetv1alpha1.FaultCampaign, completed map[string]bool) (bool, error) {
	expected := run.Status.ScheduleSummary.NetworkInventory
	allowed := map[string]struct{}{}
	transition := active
	if transition == nil {
		for i := range children {
			child := &children[i]
			if terminal(child.Status.Phase) && !completed[child.Name] {
				transition = child
				break
			}
		}
	}
	if transition != nil && transition.Spec.Fault.Type == "pod" && transition.Spec.Fault.Action == "pod-kill" {
		for _, target := range transition.Status.ResolvedTargets {
			allowed[target.Actor] = struct{}{}
		}
	}
	differences := inventory.CompareLive(expected, network, pods, allowed)
	if len(differences) > 0 {
		now := metav1.NewTime(r.now())
		next := *run.Status.DeepCopy()
		next.IdentityDivergence = inventory.DivergenceEvidence(expected, network.Status.InventoryDigest, differences, now)
		next.Attribution = "Inconclusive"
		next.CompletedAt = &now
		return true, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Inconclusive", "TargetIdentityDiverged", "admitted network identity changed; remaining actions were not started", r.now()))
	}
	if transition != nil && len(allowed) > 0 && network.Status.InventoryReady && network.Status.InventoryDigest != expected.Digest {
		current, err := inventory.Published(network)
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
		next.IdentityTransitions = append(next.IdentityTransitions, attacknetv1alpha1.IdentityTransition{Campaign: transition.Name, Actors: actors, PreviousDigest: expected.Digest, CurrentDigest: current.Digest, ObservedAt: now})
		return true, r.patchStatus(ctx, run, runTransition(next, run.Generation, "Running", "ExpectedTargetIdentityTransition", "", r.now()))
	}
	return false, nil
}

func (r *Reconciler) finish(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, next attacknetv1alpha1.AttacknetRunStatus, phase, reason, attribution string) error {
	children, err := r.children(ctx, run)
	if err != nil {
		return err
	}
	now := metav1.NewTime(r.now())
	if next.CompletedAt == nil {
		next.CompletedAt = &now
	}
	next.Attribution = attribution
	next.Cleanup = runCleanup(children, next.Cleanup, now)
	if next.Cleanup.Completed {
		clearActiveRunState(&next)
		next.FinishedAt = &now
		next.TerminalClassification = classify(run, children)
	} else {
		next.FinishedAt = nil
		next.TerminalClassification = nil
	}
	message := ""
	if phase == "Failed" {
		message = next.Message
	}
	return r.patchStatus(ctx, run, runTransition(next, run.Generation, phase, reason, message, r.now()))
}

// reconcileTerminal keeps cleanup evidence truthful after an outcome has been
// recorded. Owned FaultCampaign watches wake this path as their finalizers
// remove mutations and publish terminal cleanup evidence.
func (r *Reconciler) reconcileTerminal(ctx context.Context, run *attacknetv1alpha1.AttacknetRun) (reconcile.Result, error) {
	children, err := r.children(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	}
	now := metav1.NewTime(r.now())
	next := *run.Status.DeepCopy()
	next.Cleanup = runCleanup(children, next.Cleanup, now)
	if next.Cleanup.Completed {
		clearActiveRunState(&next)
		if next.FinishedAt == nil {
			next.FinishedAt = &now
		}
		next.TerminalClassification = classify(run, children)
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
	return reconcile.Result{}, nil
}

func runCleanup(children []attacknetv1alpha1.FaultCampaign, existing *attacknetv1alpha1.RunCleanup, now metav1.Time) *attacknetv1alpha1.RunCleanup {
	pending := 0
	for index := range children {
		child := &children[index]
		if !terminal(child.Status.Phase) || child.Status.Cleanup == nil ||
			!child.Status.Cleanup.Absent || !child.Status.Cleanup.AllRecovered {
			pending++
		}
	}
	if pending > 0 {
		return &attacknetv1alpha1.RunCleanup{
			Required:  true,
			Completed: false,
			Message:   fmt.Sprintf("waiting for %d owned child campaign(s) to prove cleanup", pending),
		}
	}
	completedAt := &now
	if existing != nil && existing.Completed && existing.CompletedAt != nil {
		completedAt = existing.CompletedAt.DeepCopy()
	}
	return &attacknetv1alpha1.RunCleanup{
		Required:    true,
		Completed:   true,
		CompletedAt: completedAt,
		Message:     "all owned child campaigns proved cleanup",
	}
}

func clearActiveRunState(status *attacknetv1alpha1.AttacknetRunStatus) {
	status.ActiveCampaign = nil
	status.ActiveChild = nil
	if status.BudgetUsage != nil {
		status.BudgetUsage.ActiveFaults = 0
	}
}

func (r *Reconciler) budgetTerminal(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, reason string, usage *attacknetv1alpha1.BudgetUsage) error {
	next := *run.Status.DeepCopy()
	next.BudgetUsage = usage
	if run.Spec.StopPolicy.OnBudgetExhausted == "Pause" {
		return r.patchStatus(ctx, run, runTransition(next, run.Generation, "Paused", reason, "", r.now()))
	}
	return r.finish(ctx, run, next, "Failed", reason, "Inconclusive")
}
func (r *Reconciler) fail(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, reason string, err error) error {
	next := *run.Status.DeepCopy()
	next.Message = truncate(err.Error(), 1000)
	return r.finish(ctx, run, next, "Failed", reason, "Inconclusive")
}
func (r *Reconciler) transition(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, phase, reason, message string) error {
	return r.patchStatus(ctx, run, runTransition(run.Status, run.Generation, phase, reason, message, r.now()))
}
func (r *Reconciler) patchStatus(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, next attacknetv1alpha1.AttacknetRunStatus) error {
	if reflect.DeepEqual(run.Status, next) {
		return nil
	}
	base := run.DeepCopy()
	run.Status = next
	return r.Status().Patch(ctx, run, client.MergeFrom(base))
}
func runTransition(status attacknetv1alpha1.AttacknetRunStatus, generation int64, phase, reason, message string, now time.Time) attacknetv1alpha1.AttacknetRunStatus {
	status = *status.DeepCopy()
	changed := status.Phase != phase || status.Reason != reason
	status.ObservedGeneration = generation
	status.Phase, status.Reason, status.Message = phase, reason, message
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

func (r *Reconciler) children(ctx context.Context, run *attacknetv1alpha1.AttacknetRun) ([]attacknetv1alpha1.FaultCampaign, error) {
	list := &attacknetv1alpha1.FaultCampaignList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(run.Namespace)); err != nil {
		return nil, err
	}
	result := []attacknetv1alpha1.FaultCampaign{}
	for _, item := range list.Items {
		owner := metav1.GetControllerOf(&item)
		if owner != nil && owner.UID == run.UID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Reconciler) signerResolver() signerset.Resolver {
	if r.SignerSets != nil {
		return r.SignerSets
	}
	return &signerset.HTTPResolver{}
}

func canonicalManifest(network *attacknetv1alpha1.StacksNetwork, weights map[string]float64) fault.Manifest {
	return manifestWithSignerWeights(fault.ManifestFromNetwork(network), weights)
}

func manifestWithSignerWeights(manifest fault.Manifest, weights map[string]float64) fault.Manifest {
	for index := range manifest.Actors {
		if weight, ok := weights[manifest.Actors[index].Name]; ok {
			manifest.Actors[index].SignerWeight = ptr(weight)
		}
	}
	return manifest
}
func activeChild(children []attacknetv1alpha1.FaultCampaign) *attacknetv1alpha1.FaultCampaign {
	for i := range children {
		if !terminal(children[i].Status.Phase) {
			return &children[i]
		}
	}
	return nil
}
func terminal(phase string) bool {
	return phase == "Passed" || phase == "Failed" || phase == "Inconclusive"
}
func validatedDecisions(values []apixv1.JSON) ([]map[string]any, map[string]bool, error) {
	decoded := make([]map[string]any, len(values))
	executions, instructions := map[string]bool{}, map[string]bool{}
	for index, value := range values {
		if err := json.Unmarshal(value.Raw, &decoded[index]); err != nil {
			return nil, nil, fmt.Errorf("decision %d is not valid JSON: %w", index, err)
		}
		execution, executionOK := decoded[index]["execution"].(string)
		instruction, instructionOK := decoded[index]["instructionId"].(string)
		phase, phaseOK := decoded[index]["phase"].(string)
		completedAt, completedOK := decoded[index]["completedAt"].(string)
		decisionIndex, indexOK := decoded[index]["index"].(float64)
		if !executionOK || execution == "" || !instructionOK || instruction == "" || !phaseOK || !terminal(phase) || !completedOK {
			return nil, nil, fmt.Errorf("decision %d lacks its bounded execution, instruction, phase, or completion fields", index)
		}
		if !indexOK || decisionIndex != float64(index) {
			return nil, nil, fmt.Errorf("decision %d has a non-canonical index", index)
		}
		if _, err := time.Parse(time.RFC3339Nano, completedAt); err != nil {
			return nil, nil, fmt.Errorf("decision %d has an invalid completion time: %w", index, err)
		}
		if executions[execution] || instructions[instruction] {
			return nil, nil, fmt.Errorf("decision %d duplicates an execution or instruction", index)
		}
		executions[execution], instructions[instruction] = true, true
	}
	return decoded, executions, nil
}
func jsonValue(value any) (apixv1.JSON, error) {
	encoded, err := json.Marshal(value)
	return apixv1.JSON{Raw: encoded}, err
}
func timeValue(value *metav1.Time, fallback time.Time) string {
	if value != nil {
		return value.Format(time.RFC3339Nano)
	}
	return fallback.Format(time.RFC3339Nano)
}
func stableName(parts ...string) string {
	candidate := ""
	for i, part := range parts {
		if i > 0 {
			candidate += "-"
		}
		candidate += part
	}
	if len(candidate) <= 63 {
		return candidate
	}
	digest, _ := canonical.ArtifactDigest(candidate)
	return candidate[:52] + "-" + digest[7:17]
}
func upsertResolved(values []attacknetv1alpha1.ResolvedCampaign, value attacknetv1alpha1.ResolvedCampaign) []attacknetv1alpha1.ResolvedCampaign {
	result := []attacknetv1alpha1.ResolvedCampaign{}
	for _, item := range values {
		if item.Name != value.Name {
			result = append(result, item)
		}
	}
	return append(result, value)
}
func classify(run *attacknetv1alpha1.AttacknetRun, children []attacknetv1alpha1.FaultCampaign) *attacknetv1alpha1.TerminalClassification {
	expectedAssertion, expectedStatus, attempt, candidateDigest := "", "", "", ""
	if run.Spec.Minimization.Enabled {
		expectedAssertion, expectedStatus, attempt, candidateDigest = run.Spec.Minimization.ExpectedAssertion, run.Spec.Minimization.ExpectedStatus, run.Spec.Minimization.AttemptID, run.Spec.Minimization.CandidateDigest
	} else if run.Spec.Replay.Enabled && run.Spec.Replay.VerifyExpectedFailure {
		expectedAssertion, expectedStatus, attempt, candidateDigest = run.Spec.Replay.ExpectedAssertion, run.Spec.Replay.ExpectedStatus, run.Spec.Replay.AttemptID, run.Spec.Replay.DescriptorDigest
	} else {
		return nil
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	evidence := make([]map[string]any, 0, len(children))
	matching := []map[string]any{}
	for _, child := range children {
		effectResults := decodeJSONValues(child.Status.EffectResults)
		recoveryResults := decodeJSONValues(child.Status.RecoveryResults)
		evidence = append(evidence, map[string]any{"name": child.Name, "uid": string(child.UID), "phase": defaultString(child.Status.Phase, "Pending"), "reason": child.Status.Reason, "effectResults": effectResults, "recoveryResults": recoveryResults})
		for _, result := range append(tagResults(effectResults, child.Name, "effect"), tagResults(recoveryResults, child.Name, "recovery")...) {
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
		raw, _ := jsonValue(value)
		stored = append(stored, raw)
	}
	scheduleDigest := ""
	if run.Status.ScheduleRef != nil {
		scheduleDigest = run.Status.ScheduleRef.Digest
	}
	digest, _ := canonical.ArtifactDigest(map[string]any{"runUID": string(run.UID), "scheduleDigest": scheduleDigest, "attemptId": attempt, "expectedAssertion": expectedAssertion, "expectedStatus": expectedStatus, "evidence": evidence})
	return &attacknetv1alpha1.TerminalClassification{AttemptID: attempt, CandidateDigest: candidateDigest, ExpectedAssertion: expectedAssertion, ExpectedStatus: expectedStatus, Outcome: outcome, Reason: reason, ObservationCount: int32(len(matching)), Observations: stored, EvidenceDigest: digest, EvidenceURI: fmt.Sprintf("k8s://attacknetruns/%s/terminal-assertion-evidence", run.Name), CausalMinimalityClaimed: false}
}

func decodeJSONValues(values []apixv1.JSON) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		var decoded map[string]any
		if json.Unmarshal(value.Raw, &decoded) == nil {
			result = append(result, decoded)
		}
	}
	return result
}

func tagResults(values []map[string]any, child, source string) []map[string]any {
	result := make([]map[string]any, len(values))
	for index, value := range values {
		copy := make(map[string]any, len(value)+2)
		for key, item := range value {
			copy[key] = item
		}
		copy["child"], copy["source"] = child, source
		result[index] = copy
	}
	return result
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func ptr[T any](value T) *T { return &value }
func ternary[T any](condition bool, yes, no T) T {
	if condition {
		return yes
	}
	return no
}
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// SetupWithManager registers run, child campaign, and network watches.
func (r *Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if r.APIReader == nil {
		return errors.New("AttacknetRun reconciler requires an uncached Kubernetes API reader")
	}
	mapNetwork := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
		list := &attacknetv1alpha1.AttacknetRunList{}
		if err := r.List(ctx, list, client.InNamespace(object.GetNamespace()), client.MatchingFields{"spec.networkRef": object.GetName()}); err != nil {
			return nil
		}
		result := make([]reconcile.Request, len(list.Items))
		for i := range list.Items {
			result[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
		}
		return result
	})
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &attacknetv1alpha1.AttacknetRun{}, "spec.networkRef", func(object client.Object) []string {
		return []string{object.(*attacknetv1alpha1.AttacknetRun).Spec.NetworkRef}
	}); err != nil {
		return err
	}
	return builder.ControllerManagedBy(mgr).For(&attacknetv1alpha1.AttacknetRun{}).Owns(&corev1.ConfigMap{}).Owns(&attacknetv1alpha1.FaultCampaign{}).Watches(&attacknetv1alpha1.StacksNetwork{}, mapNetwork).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).Complete(r)
}
