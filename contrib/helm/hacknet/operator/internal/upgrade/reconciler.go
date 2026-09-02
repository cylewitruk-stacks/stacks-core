package upgrade

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolassertion"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
)

const campaignFinalizer = "testing.stacks.org/upgrade-campaign-cleanup"

// Reconciler advances UpgradeCampaign status while StacksNetwork reconciliation
// remains the sole writer of actor workloads.
type Reconciler struct {
	client.Client
	APIReader    client.Reader
	Scheme       *runtime.Scheme
	Observations ObservationReader
	Now          func() time.Time
}

// ObservationReader supplies identity-bound protocol telemetry for stage gates.
type ObservationReader interface {
	Read(context.Context, *attacknetv1beta1.StacksNetwork) (protocolobservation.Snapshot, error)
}

// Reconcile advances one durable rollout or rollback state transition.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	campaign := &attacknetv1beta1.UpgradeCampaign{}
	if err := r.Get(ctx, request.NamespacedName, campaign); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if campaign.Spec.Template {
		return reconcile.Result{}, nil
	}
	if !campaign.DeletionTimestamp.IsZero() {
		return r.reconcileDeletion(ctx, campaign)
	}
	if !controllerutil.ContainsFinalizer(campaign, campaignFinalizer) {
		base := campaign.DeepCopy()
		controllerutil.AddFinalizer(campaign, campaignFinalizer)
		return reconcile.Result{Requeue: true}, r.Patch(ctx, campaign, client.MergeFrom(base))
	}
	network := &attacknetv1beta1.StacksNetwork{}
	key := types.NamespacedName{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef}
	if err := r.APIReader.Get(ctx, key, network); err != nil {
		return reconcile.Result{}, err
	}
	if err := Validate(campaign, network); err != nil {
		return reconcile.Result{}, r.setStatus(ctx, campaign, "Failed", "AdmissionFailed", err.Error())
	}
	if campaign.Status.ObservedGeneration != 0 && campaign.Status.ObservedGeneration != campaign.Generation {
		return reconcile.Result{}, r.setStatus(ctx, campaign, "Failed", "AdmittedCampaignChanged", "campaign spec changed after admission")
	}
	switch campaign.Status.Phase {
	case "", "Pending":
		return r.admit(ctx, campaign, network)
	case "Running":
		return r.observeStage(ctx, campaign, network)
	case "RollingBack":
		return r.observeRollback(ctx, campaign, network)
	case "Passed", "Failed", "Inconclusive":
		return reconcile.Result{}, nil
	default:
		return reconcile.Result{}, r.setStatus(ctx, campaign, "Failed", "StatusIntegrityFailed", "unknown campaign phase")
	}
}

func (r *Reconciler) admit(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign, network *attacknetv1beta1.StacksNetwork) (reconcile.Result, error) {
	if network.Status.Phase != "Ready" || !network.Status.InventoryReady {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.setStatus(ctx, campaign, "Pending", "NetworkNotReady", "")
	}
	published, err := inventory.BetaPublished(network)
	if err != nil {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.setStatus(ctx, campaign, "Pending", "NetworkInventoryNotReady", err.Error())
	}
	if conflict, err := r.activeConflict(ctx, campaign); err != nil {
		return reconcile.Result{}, err
	} else if conflict != "" {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.setStatus(ctx, campaign, "Pending", "UpgradeLeaseHeld", conflict)
	}
	now := metav1.NewTime(r.now())
	next := *campaign.Status.DeepCopy()
	next.ObservedGeneration = campaign.Generation
	next.Phase, next.Reason = "Running", "StageStarted"
	next.NetworkUID = string(network.UID)
	next.BaselineInventory = &published
	next.CurrentInventory = published.DeepCopy()
	next.CurrentStage = 0
	next.StageStartedAt, next.StageReadySince = &now, nil
	next.AppliedAssignments = EffectiveAssignments(&attacknetv1beta1.UpgradeCampaign{Spec: campaign.Spec, Status: next})
	return reconcile.Result{RequeueAfter: time.Second}, r.patchStatus(ctx, campaign, next)
}

func (r *Reconciler) observeStage(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign, network *attacknetv1beta1.StacksNetwork) (reconcile.Result, error) {
	if campaign.Status.NetworkUID != string(network.UID) {
		return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "NetworkIdentityChanged", "StacksNetwork UID changed")
	}
	stageIndex := int(campaign.Status.CurrentStage)
	if stageIndex < 0 || stageIndex >= len(campaign.Spec.Stages) || campaign.Status.StageStartedAt == nil {
		return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "StatusIntegrityFailed", "invalid current stage")
	}
	stage := campaign.Spec.Stages[stageIndex]
	deadlineExceeded := r.now().Sub(campaign.Status.StageStartedAt.Time) > stage.Deadline.Duration
	ready := network.Status.Phase == "Ready" && stageActorsReady(campaign, network, EffectiveAssignments(campaign))
	var provenAssertions *attacknetv1beta1.ProtocolAssertionSetStatus
	if !ready {
		if deadlineExceeded {
			return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "StartupIncompatible", stage.Name)
		}
		if campaign.Status.StageReadySince != nil || campaign.Status.StageAssertions != nil {
			next := *campaign.Status.DeepCopy()
			next.StageReadySince = nil
			next.StageAssertions = nil
			return reconcile.Result{RequeueAfter: time.Second}, r.patchStatus(ctx, campaign, next)
		}
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	if stage.Assertions != nil {
		snapshot, err := r.Observations.Read(ctx, network)
		if err != nil {
			if deadlineExceeded {
				return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Inconclusive", "TelemetryUnavailable", stage.Name)
			}
			return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
		}
		observed, err := protocolassertion.EvaluateSet(*stage.Assertions, campaign.Status.StageAssertions, snapshot, r.now())
		if err != nil {
			return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "ProtocolAssertionIntegrityFailed", err.Error())
		}
		switch observed.Outcome {
		case protocolassertion.OutcomeViolated:
			return reconcile.Result{}, r.failOrRollbackWithAssertions(ctx, campaign, "Failed", "ProtocolAssertionViolated", stage.Name, &observed)
		case protocolassertion.OutcomeInconclusive:
			return reconcile.Result{}, r.failOrRollbackWithAssertions(ctx, campaign, "Inconclusive", "ProtocolAssertionInconclusive", stage.Name, &observed)
		case protocolassertion.OutcomePending:
			if deadlineExceeded {
				return reconcile.Result{}, r.failOrRollbackWithAssertions(ctx, campaign, "Inconclusive", "TelemetryUnavailable", stage.Name, &observed)
			}
			if campaign.Status.StageAssertions == nil || !reflect.DeepEqual(*campaign.Status.StageAssertions, observed) {
				next := *campaign.Status.DeepCopy()
				next.StageAssertions = &observed
				return reconcile.Result{RequeueAfter: time.Second}, r.patchStatus(ctx, campaign, next)
			}
			return reconcile.Result{RequeueAfter: time.Second}, nil
		case protocolassertion.OutcomeProven:
			// Persist the first proof with the stage-ready transition below. The
			// assertion is still re-evaluated during stableFor so a later
			// violation fails the campaign without churning terminal timestamps.
			provenAssertions = observed.DeepCopy()
		default:
			return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "ProtocolAssertionIntegrityFailed", "unknown assertion outcome")
		}
	}
	if campaign.Status.StageReadySince == nil {
		if deadlineExceeded {
			return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "StageDeadlineExceeded", stage.Name)
		}
		next := *campaign.Status.DeepCopy()
		now := metav1.NewTime(r.now())
		next.StageReadySince = &now
		if provenAssertions != nil {
			next.StageAssertions = provenAssertions
		}
		current, err := inventory.BetaPublished(network)
		if err != nil {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		appendInventoryTransition(&next, stage.Name, stage.Assignments, current, now)
		return reconcile.Result{RequeueAfter: max(time.Second, stage.StableFor.Duration)}, r.patchStatus(ctx, campaign, next)
	}
	if r.now().Sub(campaign.Status.StageReadySince.Time) < stage.StableFor.Duration {
		if deadlineExceeded {
			return reconcile.Result{}, r.failOrRollback(ctx, campaign, "Failed", "StageDeadlineExceeded", stage.Name)
		}
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	if stageIndex == len(campaign.Spec.Stages)-1 {
		return reconcile.Result{}, r.setStatus(ctx, campaign, "Passed", "UpgradeCompleted", "")
	}
	next := *campaign.Status.DeepCopy()
	next.CurrentStage++
	now := metav1.NewTime(r.now())
	next.StageStartedAt, next.StageReadySince = &now, nil
	next.StageAssertions = nil
	next.AppliedAssignments = EffectiveAssignments(&attacknetv1beta1.UpgradeCampaign{Spec: campaign.Spec, Status: next})
	next.Reason = "StageStarted"
	return reconcile.Result{RequeueAfter: time.Second}, r.patchStatus(ctx, campaign, next)
}

func stageActorsReady(campaign *attacknetv1beta1.UpgradeCampaign, network *attacknetv1beta1.StacksNetwork, assignments []attacknetv1beta1.UpgradeAssignment) bool {
	profiles := map[string]attacknetv1beta1.UpgradeProfileSpec{}
	for _, profile := range campaign.Spec.Profiles {
		profiles[profile.Name] = profile
	}
	statuses := map[string]attacknetv1beta1.ActorStatus{}
	for _, status := range network.Status.Actors {
		statuses[status.Name] = status
	}
	for _, assignment := range assignments {
		status, ok := statuses[assignment.Actor]
		profile := profiles[assignment.Profile]
		if !ok || !status.Ready || !status.IdentityReady || status.Image != profile.Image || !inventory.RuntimeImageMatches(status.RuntimeImageID, profile.ImageID) || !configurationReady(status, assignment) {
			return false
		}
	}
	return true
}

func (r *Reconciler) failOrRollback(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign, terminalPhase, reason, message string) error {
	return r.failOrRollbackWithAssertions(ctx, campaign, terminalPhase, reason, message, nil)
}

func (r *Reconciler) failOrRollbackWithAssertions(
	ctx context.Context,
	campaign *attacknetv1beta1.UpgradeCampaign,
	terminalPhase, reason, message string,
	assertions *attacknetv1beta1.ProtocolAssertionSetStatus,
) error {
	next := *campaign.Status.DeepCopy()
	if assertions != nil {
		next.StageAssertions = assertions.DeepCopy()
	}
	if campaign.Spec.RollbackOnFailure {
		next.RollbackTerminalPhase = terminalPhase
		next.Phase, next.Reason, next.Message = "RollingBack", reason, message
		return r.patchStatus(ctx, campaign, next)
	}
	next.Phase, next.Reason, next.Message = terminalPhase, reason, message
	return r.patchStatus(ctx, campaign, next)
}

func (r *Reconciler) observeRollback(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign, network *attacknetv1beta1.StacksNetwork) (reconcile.Result, error) {
	if campaign.Status.BaselineInventory == nil || !baselineImagesReady(campaign.Status.BaselineInventory, network) {
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	next := *campaign.Status.DeepCopy()
	next.Phase, next.RollbackComplete = defaultTerminalPhase(campaign.Status.RollbackTerminalPhase), true
	next.AppliedAssignments = nil
	if current, err := inventory.BetaPublished(network); err == nil {
		now := metav1.NewTime(r.now())
		appendInventoryTransition(&next, "rollback", campaign.Status.AppliedAssignments, current, now)
	}
	return reconcile.Result{}, r.patchStatus(ctx, campaign, next)
}

func appendInventoryTransition(status *attacknetv1beta1.UpgradeCampaignStatus, campaign string, assignments []attacknetv1beta1.UpgradeAssignment, current attacknetv1beta1.NetworkInventory, observedAt metav1.Time) {
	previous := status.BaselineInventory
	if status.CurrentInventory != nil {
		previous = status.CurrentInventory
	}
	if previous == nil || previous.Digest == current.Digest {
		status.CurrentInventory = current.DeepCopy()
		return
	}
	actors := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		actors = append(actors, assignment.Actor)
	}
	sort.Strings(actors)
	status.IdentityTransitions = append(status.IdentityTransitions, attacknetv1beta1.IdentityTransition{
		Campaign: campaign, Actors: actors, PreviousDigest: previous.Digest,
		CurrentDigest: current.Digest, ObservedAt: observedAt,
	})
	status.CurrentInventory = current.DeepCopy()
}

func defaultTerminalPhase(value string) string {
	if value == "Inconclusive" {
		return value
	}
	return "Failed"
}

func baselineImagesReady(baseline *attacknetv1beta1.NetworkInventory, network *attacknetv1beta1.StacksNetwork) bool {
	if network.Status.Phase != "Ready" {
		return false
	}
	status := map[string]attacknetv1beta1.ActorStatus{}
	for _, actor := range network.Status.Actors {
		status[actor.Name] = actor
	}
	for _, expected := range baseline.Actors {
		observed, ok := status[expected.Name]
		if !ok || !observed.Ready || !observed.IdentityReady || observed.Image != expected.RequestedImage || observed.RuntimeImageID != expected.RuntimeImageID || observed.ConfigDigest != expected.ConfigDigest {
			return false
		}
	}
	return true
}

func configurationReady(status attacknetv1beta1.ActorStatus, assignment attacknetv1beta1.UpgradeAssignment) bool {
	if assignment.Config == nil {
		return true
	}
	return status.ConfigDigest == assignment.Config.ExpectedDigest
}

func (r *Reconciler) reconcileDeletion(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign) (reconcile.Result, error) {
	if !controllerutil.ContainsFinalizer(campaign, campaignFinalizer) {
		return reconcile.Result{}, nil
	}
	if campaign.Status.Phase != "RollingBack" && campaign.Status.BaselineInventory != nil && !campaign.Status.RollbackComplete {
		if err := r.setStatus(ctx, campaign, "RollingBack", "DeletionRollback", ""); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	if campaign.Status.Phase == "RollingBack" {
		network := &attacknetv1beta1.StacksNetwork{}
		err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef}, network)
		if err == nil && !baselineImagesReady(campaign.Status.BaselineInventory, network) {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
	}
	base := campaign.DeepCopy()
	controllerutil.RemoveFinalizer(campaign, campaignFinalizer)
	return reconcile.Result{}, r.Patch(ctx, campaign, client.MergeFrom(base))
}

func (r *Reconciler) activeConflict(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign) (string, error) {
	list := &attacknetv1beta1.UpgradeCampaignList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(campaign.Namespace)); err != nil {
		return "", err
	}
	for index := range list.Items {
		other := &list.Items[index]
		inactive := other.Status.Phase == "Failed" || other.Status.Phase == "Inconclusive"
		if other.UID != campaign.UID && other.Spec.NetworkRef == campaign.Spec.NetworkRef && !other.Spec.Template && !inactive && other.DeletionTimestamp.IsZero() {
			return fmt.Sprintf("UpgradeCampaign %s is active", other.Name), nil
		}
	}
	return "", nil
}

func terminal(phase string) bool {
	return phase == "Passed" || phase == "Failed" || phase == "Inconclusive"
}

func (r *Reconciler) setStatus(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign, phase, reason, message string) error {
	next := *campaign.Status.DeepCopy()
	next.Phase, next.Reason, next.Message = phase, reason, message
	if phase != campaign.Status.Phase {
		now := metav1.NewTime(r.now())
		next.LastTransitionTime = &now
		if terminal(phase) {
			next.CompletedAt = &now
		}
	}
	return r.patchStatus(ctx, campaign, next)
}

func (r *Reconciler) patchStatus(ctx context.Context, campaign *attacknetv1beta1.UpgradeCampaign, next attacknetv1beta1.UpgradeCampaignStatus) error {
	if campaign.Status.Phase != next.Phase || campaign.Status.Reason != next.Reason {
		now := metav1.NewTime(r.now())
		next.LastTransitionTime = &now
		if terminal(next.Phase) && next.CompletedAt == nil {
			next.CompletedAt = &now
		}
	}
	conditionStatus := metav1.ConditionUnknown
	if next.Phase == "Passed" {
		conditionStatus = metav1.ConditionTrue
	} else if terminal(next.Phase) {
		conditionStatus = metav1.ConditionFalse
	}
	meta.SetStatusCondition(&next.Conditions, metav1.Condition{
		Type: "Succeeded", Status: conditionStatus, ObservedGeneration: campaign.Generation,
		Reason: defaultReason(next.Reason), Message: next.Message, LastTransitionTime: metav1.NewTime(r.now()),
	})
	if reflect.DeepEqual(campaign.Status, next) {
		return nil
	}
	base := campaign.DeepCopy()
	campaign.Status = next
	return r.Status().Patch(ctx, campaign, client.MergeFrom(base))
}

func defaultReason(value string) string {
	if value == "" {
		return "Reconciling"
	}
	return value
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// SetupWithManager registers upgrade and network watches.
func (r *Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if r.APIReader == nil || r.Scheme == nil || r.Observations == nil {
		return errors.New("upgrade reconciler requires API reader, scheme, and trusted observations")
	}
	mapNetwork := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
		network, ok := object.(*attacknetv1beta1.StacksNetwork)
		if !ok {
			return nil
		}
		list := &attacknetv1beta1.UpgradeCampaignList{}
		if err := r.List(ctx, list, client.InNamespace(network.Namespace)); err != nil {
			return nil
		}
		requests := []reconcile.Request{}
		for _, campaign := range list.Items {
			if campaign.Spec.NetworkRef == network.Name {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&campaign)})
			}
		}
		return requests
	})
	return builder.ControllerManagedBy(mgr).For(&attacknetv1beta1.UpgradeCampaign{}).Watches(&attacknetv1beta1.StacksNetwork{}, mapNetwork).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).Complete(r)
}
