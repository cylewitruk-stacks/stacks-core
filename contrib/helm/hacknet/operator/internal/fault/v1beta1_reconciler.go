package fault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

const betaFinalizer = "testing.stacks.org/v1beta1-fault-cleanup"

var betaTerminalPhases = map[string]bool{"Passed": true, "Failed": true, "Inconclusive": true}

// TriggerObservationReader supplies trusted height and observation inputs. It
// never decides eligibility; the pure trigger evaluator owns that policy.
type TriggerObservationReader interface {
	ReadTriggerSnapshot(context.Context, *attacknetv1beta1.FaultCampaign, *attacknetv1beta1.StacksNetwork) (trigger.Snapshot, error)
}

// V1Beta1Reconciler executes a multi-stage campaign while retaining the A4
// compiler, capability, and mutation contracts as the mechanism boundary.
type V1Beta1Reconciler struct {
	client.Client
	APIReader              client.Reader
	Scheme                 *runtime.Scheme
	Observations           TriggerObservationReader
	Probes                 ProbeClient
	Now                    func() time.Time
	IOPressureImage        string
	IOPressurePull         corev1.PullPolicy
	IOChaosArchitectures   map[string]bool
	TimeChaosArchitectures map[string]bool
	CompilationCache       *CompilationCache
	ReorgWorkerImage       string
	ReorgWorkerPull        corev1.PullPolicy
	ReorgHTTPClient        *http.Client
}

// Reconcile advances every eligible stage by one durable transition.
func (r *V1Beta1Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	campaign := &attacknetv1beta1.FaultCampaign{}
	if err := r.Get(ctx, request.NamespacedName, campaign); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if r.APIReader == nil {
		return reconcile.Result{}, errors.New("v1beta1 FaultCampaign reconciler requires an uncached Kubernetes API reader")
	}
	current := &attacknetv1beta1.FaultCampaign{}
	if err := r.APIReader.Get(ctx, request.NamespacedName, current); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if current.ResourceVersion != campaign.ResourceVersion {
		return reconcile.Result{Requeue: true}, nil
	}
	if !campaign.DeletionTimestamp.IsZero() {
		r.forgetBetaCompilation(campaign)
		return r.reconcileBetaDeletion(ctx, campaign)
	}
	if campaign.Spec.Template {
		return reconcile.Result{}, r.reconcileBetaTemplate(ctx, campaign)
	}
	if !controllerutil.ContainsFinalizer(campaign, betaFinalizer) {
		base := campaign.DeepCopy()
		controllerutil.AddFinalizer(campaign, betaFinalizer)
		return reconcile.Result{}, r.Patch(ctx, campaign, client.MergeFrom(base))
	}
	if betaTerminalPhases[campaign.Status.Phase] {
		r.forgetBetaCompilation(campaign)
		return reconcile.Result{}, r.reconcileBetaTerminal(ctx, campaign)
	}

	live, err := inventory.ReadBetaLiveView(ctx, r.APIReader, types.NamespacedName{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef})
	if err != nil {
		return reconcile.Result{}, err
	}
	if campaign.Status.Admission == nil && (!live.Network.Status.InventoryReady || live.Network.Status.ObservedGeneration != live.Network.Generation) {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transitionBeta(ctx, campaign, "Pending", "NetworkInventoryNotReady", "the current network generation has no complete admitted inventory")
	}
	manifest := ManifestFromV1Beta1(live.Network)
	compiled, err := r.compileBetaCampaign(campaign, manifest)
	if err != nil {
		return reconcile.Result{}, r.failBeta(ctx, campaign, "CampaignInvalid", err)
	}
	if campaign.Status.Admission == nil {
		return r.admitBeta(ctx, campaign, live.Network, live.Pods, manifest, compiled)
	}
	if err := r.verifyBetaAdmission(campaign, live.Network, compiled); err != nil {
		return reconcile.Result{}, r.failBeta(ctx, campaign, "AdmissionInputChanged", err)
	}
	lease, err := r.legacyRuntime().holdMutationLease(ctx, betaLeaseCampaign(campaign), false)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !lease.Held || !lease.EnvironmentReady {
		return reconcile.Result{}, r.failBeta(ctx, campaign, "MutationLeaseLost", errors.New("the campaign mutation lease or environment lease changed after admission"))
	}
	if changed, err := r.enforceBetaIdentity(ctx, campaign, live.Network, live.Pods); err != nil || changed {
		return reconcile.Result{}, err
	}
	return r.advanceBeta(ctx, campaign, live.Network, live.Pods, compiled)
}

func (r *V1Beta1Reconciler) compileBetaCampaign(campaign *attacknetv1beta1.FaultCampaign, manifest Manifest) (CompiledCampaign, error) {
	if r.CompilationCache == nil {
		return CompileV1Beta1(campaign, manifest)
	}
	return r.CompilationCache.Compile(campaign, manifest)
}

func (r *V1Beta1Reconciler) forgetBetaCompilation(campaign *attacknetv1beta1.FaultCampaign) {
	if r.CompilationCache != nil {
		r.CompilationCache.Forget(campaign.UID)
	}
}

// ManifestFromV1Beta1 derives one compiler view without importing topology.
func ManifestFromV1Beta1(network *attacknetv1beta1.StacksNetwork) Manifest {
	indexes := map[string]int32{}
	weights := map[string]float64{}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			indexes[member.Name], indexes[member.NodeName] = member.Index, member.Index
			weights[member.Name] = float64(member.Weight)
		}
	}
	actors := make([]ManifestActor, 0, len(network.Status.Actors))
	for _, actor := range network.Status.Actors {
		item := ManifestActor{Name: actor.Name, Role: actor.Role}
		if value, ok := indexes[actor.Name]; ok {
			index := value
			item.SignerIndex = &index
		}
		if value, ok := weights[actor.Name]; ok {
			weight := value
			item.SignerWeight = &weight
		}
		actors = append(actors, item)
	}
	sort.Slice(actors, func(i, j int) bool { return actors[i].Name < actors[j].Name })
	return Manifest{Network: network.Name, Namespace: network.Namespace, Actors: actors}
}

// betaProbeNetwork projects only the enrolled endpoint contract needed by the
// approved A4 probe selector. Workload rendering remains topology-owned.
func betaProbeNetwork(network *attacknetv1beta1.StacksNetwork) *attacknetv1alpha1.StacksNetwork {
	result := &attacknetv1alpha1.StacksNetwork{ObjectMeta: *network.ObjectMeta.DeepCopy()}
	if network.Spec.Probe != nil {
		result.Spec.Probe = &attacknetv1alpha1.ProbeSpec{Enabled: network.Spec.Probe.Enabled}
	}
	rawPorts := map[string][]attacknetv1alpha1.ActorPort{}
	for _, raw := range network.Spec.RawActors {
		for _, port := range raw.Ports {
			rawPorts[raw.Name] = append(rawPorts[raw.Name], attacknetv1alpha1.ActorPort{
				Name: port.Name, ContainerPort: port.ContainerPort, ServicePort: port.ServicePort, Protocol: port.Protocol,
			})
		}
	}
	for _, status := range network.Status.Actors {
		actor := attacknetv1alpha1.ActorSpec{Name: status.Name, Role: status.Role, Image: status.Image, RuntimeExposure: "reachable"}
		actor.Ports = append(actor.Ports, rawPorts[status.Name]...)
		if len(actor.Ports) == 0 {
			switch status.Role {
			case "burnchain":
				actor.Ports = []attacknetv1alpha1.ActorPort{{Name: "rpc", ContainerPort: 18443, ServicePort: 18443}, {Name: "p2p", ContainerPort: 18444, ServicePort: 18444}}
			case "signer":
				actor.Ports = []attacknetv1alpha1.ActorPort{{Name: "events", ContainerPort: 30000, ServicePort: 30000}, {Name: "metrics", ContainerPort: 31000, ServicePort: 31000}}
			default:
				actor.Ports = []attacknetv1alpha1.ActorPort{{Name: "rpc", ContainerPort: 20443, ServicePort: 20443}, {Name: "p2p", ContainerPort: 20444, ServicePort: 20444}, {Name: "metrics", ContainerPort: 20446, ServicePort: 20446}}
			}
		}
		result.Spec.Actors = append(result.Spec.Actors, actor)
	}
	return result
}

func (r *V1Beta1Reconciler) admitBeta(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, manifest Manifest, compiled CompiledCampaign) (reconcile.Result, error) {
	published, err := inventory.BetaPublished(network)
	if err != nil {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transitionBeta(ctx, campaign, "Pending", "NetworkInventoryNotReady", err.Error())
	}
	if differences := inventory.BetaCompareLive(published, network, pods, nil); len(differences) > 0 {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transitionBeta(ctx, campaign, "Pending", "NetworkInventoryNotReady", "published inventory does not match live Pods")
	}
	// Standalone campaigns hold an exclusive lease. Children admitted by one
	// AttacknetRun share that run's lease, because the run controller has already
	// compiled their aggregate concurrency and signer-impact budgets.
	lease, err := r.legacyRuntime().holdMutationLease(ctx, betaLeaseCampaign(campaign), true)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !lease.EnvironmentReady {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transitionBeta(ctx, campaign, "Pending", "WaitingForEnvironmentLease", lease.EnvironmentMessage)
	}
	if !lease.Held {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transitionBeta(ctx, campaign, "Pending", "WaitingForMutationLease", "")
	}
	legacy := r.legacyRuntime()
	legacyNetwork := betaProbeNetwork(network)
	probeArtifacts := map[string]string{}
	stages := make([]attacknetv1beta1.FaultStageStatus, len(compiled.Stages))
	for stageIndex, stage := range compiled.Stages {
		stages[stageIndex] = attacknetv1beta1.FaultStageStatus{ID: stage.ID, Phase: "Pending"}
		for _, action := range stage.Actions {
			targets, resolveErr := ResolveTargets(manifest, action.Evidence.SelectedActors, pods)
			if resolveErr != nil {
				return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transitionBeta(ctx, campaign, "Pending", "NetworkInventoryNotReady", resolveErr.Error())
			}
			shadow := betaShadowCampaign(campaign, stage.ID, action.ID, targets)
			capabilities := legacy.capabilityEvidence(ctx, shadow, pods, targets)
			if definition := mustMechanismForType(actionResourceType(action.Resource)); definition.Backend == burnchainReorgBackend {
				capabilities, err = r.burnchainReorgCapabilities(ctx, campaign, network, action, targets)
				if err != nil {
					return reconcile.Result{}, r.failBeta(ctx, campaign, "FaultCapabilityUnavailable", err)
				}
			}
			capabilityJSON := make([]apixv1.JSON, 0, len(capabilities))
			for _, capability := range capabilities {
				value, _ := json.Marshal(capability)
				capabilityJSON = append(capabilityJSON, apixv1.JSON{Raw: value})
				if !capability.Supported {
					return reconcile.Result{}, r.failBeta(ctx, campaign, "FaultCapabilityUnavailable", fmt.Errorf("stage %s action %s actor %s: %s", stage.ID, action.ID, capability.Actor, capability.Reason))
				}
			}
			definition := mustMechanismForType(actionResourceType(action.Resource))
			if definition.EffectKind != "pod" && definition.Backend != burnchainReorgBackend {
				before, probeErr := legacy.captureProbePhase(ctx, shadow, legacyNetwork, pods, targets, Compiled{Resource: action.Resource, Evidence: action.Evidence}, "before", false)
				if probeErr != nil {
					return reconcile.Result{}, r.failBeta(ctx, campaign, "ProbeBaselineUnavailable", probeErr)
				}
				if !baselineUsable(definition.MutationKind, before, action.Evidence.SelectedActors) {
					_, validationErr := decodeProbePhase(string(before), "before", definition.MutationKind, set(action.Evidence.SelectedActors))
					return reconcile.Result{}, r.failBeta(ctx, campaign, "ProbeBaselineUnavailable", fmt.Errorf("stage %s action %s has no usable trusted probe baseline: %v", stage.ID, action.ID, validationErr))
				}
				probeArtifacts[betaProbeKey(stage.ID, action.ID, "before")] = string(before)
			}
			stages[stageIndex].Actions = append(stages[stageIndex].Actions, attacknetv1beta1.FaultActionStatus{
				ID: action.ID, Phase: "Pending", ResolvedTargets: betaTargets(targets),
				CapabilityEvidence: capabilityJSON,
			})
		}
	}
	specDigest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		return reconcile.Result{}, err
	}
	planDigest, err := compiledCampaignDigest(compiled)
	if err != nil {
		return reconcile.Result{}, err
	}
	impact, err := rawAPIJSON(compiled.AggregateImpact)
	if err != nil {
		return reconcile.Result{}, err
	}
	now := metav1.NewTime(r.now())
	next := *campaign.Status.DeepCopy()
	next.Admission = &attacknetv1beta1.CampaignAdmission{
		NetworkUID: string(network.UID), NetworkGeneration: network.Generation,
		NetworkInventory: published, CampaignGeneration: campaign.Generation,
		CampaignSpecDigest: specDigest, CompiledPlanDigest: planDigest,
		AdmittedAt: now, AggregateImpact: &impact,
	}
	next.Stages = stages
	next.ProbeArtifacts = probeArtifacts
	return reconcile.Result{Requeue: true}, r.patchBetaStatus(ctx, campaign, betaStatusTransition(next, campaign.Generation, "Admitted", "SafetyPolicySatisfied", "", r.now()))
}

func (r *V1Beta1Reconciler) verifyBetaAdmission(campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, compiled CompiledCampaign) error {
	specDigest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		return err
	}
	planDigest, err := compiledCampaignDigest(compiled)
	if err != nil {
		return err
	}
	admission := campaign.Status.Admission
	if admission.NetworkUID != string(network.UID) || admission.NetworkGeneration != network.Generation ||
		admission.CampaignGeneration != campaign.Generation || admission.CampaignSpecDigest != specDigest ||
		admission.CompiledPlanDigest != planDigest {
		return errors.New("campaign specification, compiled plan, or admitted network changed")
	}
	return nil
}

func compiledCampaignDigest(compiled CompiledCampaign) (string, error) {
	resources := make([]any, 0)
	for _, stage := range compiled.Stages {
		for _, action := range stage.Actions {
			resources = append(resources, map[string]any{"stage": stage.ID, "action": action.ID, "resource": action.Resource.Object, "evidence": action.Evidence})
		}
	}
	return canonical.ArtifactDigest(map[string]any{"resources": resources, "aggregateImpact": compiled.AggregateImpact})
}

func (r *V1Beta1Reconciler) advanceBeta(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, compiled CompiledCampaign) (reconcile.Result, error) {
	next := *campaign.Status.DeepCopy()
	requeueAfter := 2 * time.Second
	for stageIndex := range next.Stages {
		stage := &next.Stages[stageIndex]
		compiledStage := compiled.Stages[stageIndex]
		switch stage.Phase {
		case "Pending":
			decision, err := r.evaluateBetaStage(ctx, campaign, network, stage.ID)
			if err != nil {
				// The trigger specification was already compiled at admission. Runtime
				// errors therefore describe an unavailable or malformed observation
				// source and must not be converted into a safety verdict.
				stage.Reason = "TriggerObservationUnavailable"
				continue
			}
			if decision.Expired {
				stage.Phase, stage.Reason = "Failed", decision.Reason
				completed := metav1.NewTime(r.now())
				stage.CompletedAt = &completed
				continue
			}
			if !decision.Eligible {
				if decision.RequeueAt != nil {
					wait := time.Until(*decision.RequeueAt)
					if wait > 0 && wait < requeueAfter {
						requeueAfter = wait
					}
				}
				continue
			}
			receipt, _ := rawAPIJSON(decision.Receipt)
			eligible := metav1.NewTime(decision.Receipt.SatisfiedAt)
			stage.TriggerReceipt, stage.EligibleAt = &receipt, &eligible
			if err := r.injectBetaStage(ctx, campaign, network, pods, &compiledStage, stage); err != nil {
				stage.Phase, stage.Reason = "Failed", "PartialInjectionRolledBack"
				cleanupView := campaign.DeepCopy()
				cleanupView.Status = *next.DeepCopy()
				cleanupErr := r.cleanupAllBeta(ctx, cleanupView)
				if cleanupErr == nil {
					_ = r.releaseBetaMutationLease(ctx, campaign)
				}
				completed := metav1.NewTime(r.now())
				next.CompletedAt = &completed
				next.Cleanup = &attacknetv1beta1.CleanupEvidence{Absent: cleanupErr == nil, AllRecovered: cleanupErr == nil, Method: "PartialInjectionRollback", ObservedAt: completed}
				if cleanupErr != nil {
					err = fmt.Errorf("%w; cleanup: %v", err, cleanupErr)
				}
				return reconcile.Result{}, r.patchBetaStatus(ctx, campaign, betaStatusTransition(next, campaign.Generation, "Failed", "StageInjectionFailed", truncate(err.Error(), 1000), r.now()))
			}
			if skew, maximum := betaStageStartSkew(stage), betaStageSpec(campaign, stage.ID).MaxStartSkew.Duration; maximum > 0 && skew > maximum {
				stage.ObservedStartSkew = &metav1.Duration{Duration: skew}
				stage.Phase, stage.Reason = "Failed", "MaximumStartSkewExceeded"
				completed := metav1.NewTime(r.now())
				stage.CompletedAt = &completed
				continue
			}
			started := metav1.NewTime(r.now())
			stage.StartedAt, stage.Phase, stage.Reason = &started, "Injecting", "MutationsCreated"
		case "Injecting", "Active", "Recovering":
			if err := r.advanceBetaStage(ctx, campaign, network, pods, &compiledStage, stage, &next); err != nil {
				return reconcile.Result{}, r.failBetaWithStatus(ctx, campaign, next, "StageExecutionFailed", err)
			}
		}
	}
	next.ActiveStageIDs = activeBetaStages(next.Stages)
	phase, reason := aggregateBetaPhase(next.Stages)
	if betaTerminalPhases[phase] {
		cleanupView := campaign.DeepCopy()
		cleanupView.Status = *next.DeepCopy()
		if err := r.cleanupAllBeta(ctx, cleanupView); err != nil {
			return reconcile.Result{}, err
		}
		_ = r.releaseBetaMutationLease(ctx, campaign)
		completed := metav1.NewTime(r.now())
		next.CompletedAt = &completed
		next.Cleanup = &attacknetv1beta1.CleanupEvidence{
			Absent: true, AllRecovered: true, Method: "TerminalCleanup", ObservedAt: completed,
		}
	}
	if err := r.patchBetaStatus(ctx, campaign, betaStatusTransition(next, campaign.Generation, phase, reason, "", r.now())); err != nil {
		return reconcile.Result{}, err
	}
	if betaTerminalPhases[phase] {
		return reconcile.Result{}, nil
	}
	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

func (r *V1Beta1Reconciler) evaluateBetaStage(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, id string) (trigger.Decision, error) {
	var specStage *attacknetv1beta1.FaultStageSpec
	for index := range campaign.Spec.Stages {
		if campaign.Spec.Stages[index].ID == id {
			specStage = &campaign.Spec.Stages[index]
			break
		}
	}
	if specStage == nil {
		return trigger.Decision{}, fmt.Errorf("stage %s disappeared", id)
	}
	stageCopy := specStage.DeepCopy()
	if stageTriggerEmpty(stageCopy.Trigger) {
		stageCopy.Trigger.AfterCampaignStart = &metav1.Duration{}
	}
	spec, err := trigger.ForStage(*stageCopy)
	if err != nil {
		return trigger.Decision{}, err
	}
	snapshot := trigger.Snapshot{StartedAt: campaign.Status.Admission.AdmittedAt.Time, Now: r.now()}
	needsObservationSource := stageCopy.Trigger.BurnHeight != nil || stageCopy.Trigger.StacksHeight != nil || stageCopy.Trigger.Observation != nil
	if r.Observations != nil && needsObservationSource {
		observed, readErr := r.Observations.ReadTriggerSnapshot(ctx, campaign, network)
		if readErr != nil {
			return trigger.Decision{}, readErr
		}
		observed.StartedAt, observed.Now = snapshot.StartedAt, snapshot.Now
		snapshot = observed
	}
	snapshot.Dependencies = betaDependencyObservations(campaign)
	return trigger.Evaluate(spec, snapshot)
}

func stageTriggerEmpty(value attacknetv1beta1.StageTriggerSpec) bool {
	return value.AfterCampaignStart == nil && value.AfterStage == nil && value.BurnHeight == nil && value.StacksHeight == nil && value.Observation == nil
}

func betaDependencyObservations(campaign *attacknetv1beta1.FaultCampaign) []trigger.DependencyObservation {
	result := make([]trigger.DependencyObservation, 0, len(campaign.Status.Stages))
	for _, stage := range campaign.Status.Stages {
		transitions := []trigger.DependencyTransition{}
		if injectedAt, complete := betaStageInjectedAt(stage); complete {
			transitions = append(transitions, trigger.DependencyTransition{State: trigger.DependencyInjected, ReachedAt: injectedAt})
			if stage.Phase == "Active" || stage.Phase == "Recovering" || stage.Phase == "Completed" {
				transitions = append(transitions, trigger.DependencyTransition{State: trigger.DependencyEffective, ReachedAt: injectedAt})
			}
		}
		if stage.CompletedAt != nil {
			transitions = append(transitions,
				trigger.DependencyTransition{State: trigger.DependencyRecovered, ReachedAt: stage.CompletedAt.Time},
				trigger.DependencyTransition{State: trigger.DependencyTerminal, ReachedAt: stage.CompletedAt.Time})
		}
		result = append(result, trigger.DependencyObservation{ID: stage.ID, Source: trigger.Source{Kind: "FaultCampaign", Namespace: campaign.Namespace, Name: campaign.Name, UID: string(campaign.UID), ResourceVersion: campaign.ResourceVersion, Trusted: true}, Transitions: transitions})
	}
	return result
}

func betaStageInjectedAt(stage attacknetv1beta1.FaultStageStatus) (time.Time, bool) {
	var latest time.Time
	if len(stage.Actions) == 0 {
		return time.Time{}, false
	}
	for _, action := range stage.Actions {
		if action.Mutation == nil || action.Mutation.InjectedAt == nil {
			return time.Time{}, false
		}
		if action.Mutation.InjectedAt.Time.After(latest) {
			latest = action.Mutation.InjectedAt.Time
		}
	}
	return latest, !latest.IsZero()
}

func (r *V1Beta1Reconciler) injectBetaStage(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, compiled *CompiledStage, status *attacknetv1beta1.FaultStageStatus) error {
	created := make([]int, 0, len(compiled.Actions))
	for index := range compiled.Actions {
		fresh, err := inventory.ReadBetaLiveView(ctx, r.APIReader, client.ObjectKey{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef})
		if err != nil {
			r.rollbackBetaActions(ctx, campaign, status, created)
			return err
		}
		if differences := inventory.BetaCompareLive(campaign.Status.Admission.NetworkInventory, fresh.Network, fresh.Pods, nil); len(differences) > 0 {
			r.rollbackBetaActions(ctx, campaign, status, created)
			return errors.New("network identity changed immediately before mutation")
		}
		object, err := r.createBetaMutation(ctx, campaign, network, pods, compiled.Actions[index], &status.Actions[index])
		if err != nil {
			r.rollbackBetaActions(ctx, campaign, status, created)
			return fmt.Errorf("action %s: %w", compiled.Actions[index].ID, err)
		}
		kind := compiled.Actions[index].Resource.GetKind()
		now := metav1.NewTime(r.now())
		status.Actions[index].Mutation = &attacknetv1beta1.ChaosReference{
			ActionID: compiled.Actions[index].ID, Kind: kind, Name: object.GetName(),
			UID: string(object.GetUID()), CreatedAt: &now, Mechanism: kind,
		}
		recovery, recoveryErr := betaRecoveryContract(kind, object)
		if recoveryErr != nil {
			r.rollbackBetaActions(ctx, campaign, status, append(created, index))
			return recoveryErr
		}
		contract, err := betaMutationContract(kind, object, &status.Actions[index])
		if err != nil {
			r.rollbackBetaActions(ctx, campaign, status, append(created, index))
			return err
		}
		digest, err := canonical.ArtifactDigest(contract)
		if err != nil {
			return err
		}
		status.Actions[index].Mutation = &attacknetv1beta1.ChaosReference{
			ActionID: compiled.Actions[index].ID, Kind: kind,
			Name: object.GetName(), UID: string(object.GetUID()), CreatedAt: &now,
			Mechanism: compiled.Actions[index].Resource.GetKind(), ResourceDigest: digest,
			RecoveryContract: recovery,
		}
		status.Actions[index].Phase, status.Actions[index].Reason = "Injecting", "MutationCreated"
		created = append(created, index)
	}
	return nil
}

func (r *V1Beta1Reconciler) createBetaMutation(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, action CompiledAction, status *attacknetv1beta1.FaultActionStatus) (client.Object, error) {
	definition := mustMechanismForType(actionResourceType(action.Resource))
	shadow := betaShadowCampaign(campaign, action.Resource.GetLabels()["testing.stacks.org/stage"], action.ID, legacyTargets(status.ResolvedTargets))
	legacy := r.legacyRuntime()
	var desired client.Object
	switch definition.Backend {
	case chaosMeshBackend:
		value := action.Resource.DeepCopy()
		value.SetOwnerReferences([]metav1.OwnerReference{ownership.Reference(campaign, attacknetv1beta1.GroupVersion.WithKind("FaultCampaign"))})
		desired = value
	case ioPressureBackend:
		compiled := Compiled{Resource: action.Resource, Evidence: action.Evidence}
		pod, err := legacy.buildIOPressurePod(shadow, pods, compiled)
		if err != nil {
			return nil, err
		}
		pod.OwnerReferences = []metav1.OwnerReference{ownership.Reference(campaign, attacknetv1beta1.GroupVersion.WithKind("FaultCampaign"))}
		pod.Labels["testing.stacks.org/campaign"] = campaign.Name
		pod.Labels["testing.stacks.org/stage"] = action.Resource.GetLabels()["testing.stacks.org/stage"]
		pod.Labels["testing.stacks.org/action"] = action.ID
		desired = pod
	case burnchainReorgBackend:
		return r.createBurnchainReorgMutation(ctx, campaign, network, action, status)
	case clockPolicyBackend:
		policy := &corev1.ConfigMap{}
		name := campaign.Spec.NetworkRef + "-clock-policy"
		if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: name}, policy); err != nil {
			return nil, err
		}
		if policy.Labels[NetworkLabel] != campaign.Spec.NetworkRef || policy.Labels["testing.stacks.org/clock-policy"] != "true" {
			return nil, errors.New("clock policy identity is invalid")
		}
		base := policy.DeepCopy()
		offset := parameterString(shadow.Spec.Fault.Parameters.Raw, "timeOffset") + "\n"
		for _, target := range status.ResolvedTargets {
			policy.Data[target.Actor] = offset
		}
		if err := r.Patch(ctx, policy, client.MergeFrom(base)); err != nil {
			return nil, err
		}
		policy.GetObjectKind().SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
		return policy, nil
	default:
		return nil, fmt.Errorf("unsupported mutation backend %s", definition.Backend)
	}
	if err := r.Create(ctx, desired); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	observed := desired.DeepCopyObject().(client.Object)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(desired), observed); err != nil {
		return nil, err
	}
	if controllerOwnerUID(observed) != string(campaign.UID) {
		return nil, fmt.Errorf("refusing to adopt %s/%s without the v1beta1 campaign owner", observed.GetNamespace(), observed.GetName())
	}
	if !mutationDesiredMatches(action.Resource.GetKind(), desired, observed) {
		return nil, fmt.Errorf("refusing to adopt %s/%s with a different execution contract", observed.GetNamespace(), observed.GetName())
	}
	return observed, nil
}

func actionResourceType(resource *unstructured.Unstructured) string {
	for _, definition := range registeredMechanisms() {
		if definition.MutationKind == resource.GetKind() {
			return definition.FaultType
		}
	}
	return ""
}

func (r *V1Beta1Reconciler) advanceBetaStage(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, compiled *CompiledStage, status *attacknetv1beta1.FaultStageStatus, campaignStatus *attacknetv1beta1.FaultCampaignStatus) error {
	allActive, allComplete := true, true
	for index := range status.Actions {
		actionStatus := &status.Actions[index]
		actionSpec := betaActionSpec(campaign, status.ID, actionStatus.ID)
		if actionSpec == nil {
			return fmt.Errorf("action %s/%s disappeared", status.ID, actionStatus.ID)
		}
		switch actionStatus.Phase {
		case "Injecting":
			injected, err := r.betaMutationInjected(ctx, campaign, actionSpec, actionStatus)
			if err != nil {
				return err
			}
			if injected {
				if actionStatus.Mutation.InjectedAt == nil {
					now := metav1.NewTime(r.now())
					actionStatus.Mutation.InjectedAt = &now
				}
				proven, evidenceErr := r.captureBetaDuring(ctx, campaign, network, pods, status.ID, actionSpec, &compiled.Actions[index], actionStatus, campaignStatus)
				if evidenceErr != nil || !proven {
					if betaInjectionTimedOut(campaign, status.ID, actionStatus, r.now()) {
						actionStatus.Phase, actionStatus.Reason = "Inconclusive", "EffectEvidenceTimeout"
						allActive, allComplete = false, false
						continue
					}
					actionStatus.Reason = "WaitingForEffectEvidence"
					if evidenceErr != nil {
						actionStatus.Reason = "EffectEvidenceUnavailable"
					}
					allActive, allComplete = false, false
					continue
				}
				actionStatus.Phase, actionStatus.Reason = "Active", "InjectionObserved"
			} else {
				recovered, recoveryErr := r.betaMutationRecovered(ctx, campaign, actionSpec, actionStatus)
				if recoveryErr != nil {
					return recoveryErr
				}
				if recovered {
					return fmt.Errorf("action %s/%s recovered before full injection was observed", status.ID, actionStatus.ID)
				}
				if betaInjectionTimedOut(campaign, status.ID, actionStatus, r.now()) {
					return fmt.Errorf("action %s/%s injection was not observed before its effect-evidence deadline", status.ID, actionStatus.ID)
				}
				allActive = false
			}
			allComplete = false
		case "Active":
			allComplete = false
			if actionStatus.Mutation == nil || actionStatus.Mutation.InjectedAt == nil || r.now().Sub(actionStatus.Mutation.InjectedAt.Time) < actionSpec.Fault.Duration.Duration {
				continue
			}
			if err := r.removeBetaMutation(ctx, campaign, actionSpec, actionStatus); err != nil {
				if errors.Is(err, errBurnchainReorgWorkerRemovalPending) {
					allActive, allComplete = false, false
					continue
				}
				return err
			}
			actionStatus.Phase, actionStatus.Reason = "Recovering", "DurationElapsed"
			allActive = false
		case "Recovering":
			allActive = false
			recovered, err := r.betaMutationRecovered(ctx, campaign, actionSpec, actionStatus)
			if err != nil {
				return err
			}
			if recovered {
				proven, evidenceErr := r.captureBetaRecovery(ctx, campaign, network, pods, status.ID, actionSpec, &compiled.Actions[index], actionStatus, campaignStatus)
				if evidenceErr != nil {
					if betaRecoveryTimedOut(campaign, status.ID, actionSpec, actionStatus, r.now()) {
						actionStatus.Phase, actionStatus.Reason = "Inconclusive", "RecoveryEvidenceTimeout"
						allComplete = false
						continue
					}
					allComplete = false
					continue
				}
				if !proven {
					if betaRecoveryTimedOut(campaign, status.ID, actionSpec, actionStatus, r.now()) {
						actionStatus.Phase, actionStatus.Reason = "Inconclusive", "EffectOrRecoveryNotProven"
					}
					allComplete = false
					continue
				}
				actionStatus.Phase, actionStatus.Reason = "Completed", "RecoveryObserved"
			} else {
				allComplete = false
			}
		case "Completed":
			allActive = false
		case "Failed", "Inconclusive":
			status.Phase, status.Reason = actionStatus.Phase, "Action"+actionStatus.Phase
			if status.CompletedAt == nil {
				completed := metav1.NewTime(r.now())
				status.CompletedAt = &completed
			}
			aggregateBetaStageResults(status)
			return nil
		default:
			allActive, allComplete = false, false
		}
	}
	aggregateBetaStageResults(status)
	if allComplete {
		now := metav1.NewTime(r.now())
		status.Phase, status.Reason, status.CompletedAt = "Completed", "AllActionsRecovered", &now
	} else if allActive {
		status.Phase, status.Reason = "Active", "AllActionsInjected"
	} else if status.Phase == "Active" {
		status.Phase, status.Reason = "Recovering", "ActionsRecovering"
	}
	return nil
}

func betaInjectionTimedOut(campaign *attacknetv1beta1.FaultCampaign, stageID string, status *attacknetv1beta1.FaultActionStatus, now time.Time) bool {
	if status.Mutation == nil || status.Mutation.CreatedAt == nil {
		return false
	}
	return now.Sub(status.Mutation.CreatedAt.Time) > betaAssertionTimeout(campaign, stageID, status.ID, true, 90*time.Second)
}

func aggregateBetaStageResults(stage *attacknetv1beta1.FaultStageStatus) {
	stage.EffectResults = nil
	stage.RecoveryResults = nil
	for _, action := range stage.Actions {
		stage.EffectResults = append(stage.EffectResults, action.EffectResults...)
		stage.RecoveryResults = append(stage.RecoveryResults, action.RecoveryResults...)
	}
}

func (r *V1Beta1Reconciler) betaMutationInjected(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus) (bool, error) {
	object, err := r.getBetaMutation(ctx, campaign, spec, status)
	if err != nil || object == nil {
		return false, err
	}
	switch typed := object.(type) {
	case *corev1.ConfigMap:
		offset := betaParameterString(spec.Fault.Parameters.Raw, "timeOffset") + "\n"
		for _, target := range status.ResolvedTargets {
			if typed.Data[target.Actor] != offset {
				return false, nil
			}
		}
		return true, nil
	case *corev1.Pod:
		if status.Mutation.Kind == "BurnchainReorgWorker" {
			return r.burnchainReorgInjected(ctx, campaign, spec, status, typed)
		}
		return typed.Status.Phase == corev1.PodRunning && containerRunning(typed, "io-pressure"), nil
	case *unstructured.Unstructured:
		return conditionTrue(typed, "AllInjected"), nil
	default:
		return false, fmt.Errorf("unsupported mutation object %T", object)
	}
}

func (r *V1Beta1Reconciler) getBetaMutation(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus) (client.Object, error) {
	if status.Mutation == nil {
		return nil, nil
	}
	var object client.Object
	switch status.Mutation.Kind {
	case "ConfigMap", "ClockSkewPolicy":
		object = &corev1.ConfigMap{}
	case "Pod", "IOPressurePod", "BurnchainReorgWorker":
		object = &corev1.Pod{}
	default:
		value := &unstructured.Unstructured{}
		value.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: status.Mutation.Kind})
		object = value
	}
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: status.Mutation.Name}, object)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if string(object.GetUID()) != status.Mutation.UID {
		return nil, errors.New("admitted mutation UID changed")
	}
	if !(status.Mutation.Kind == "ClockSkewPolicy" && status.Phase == "Recovering") {
		contract, contractErr := betaMutationContract(status.Mutation.Kind, object, status)
		if contractErr != nil {
			return nil, contractErr
		}
		digest, digestErr := canonical.ArtifactDigest(contract)
		if digestErr != nil {
			return nil, digestErr
		}
		if digest != status.Mutation.ResourceDigest {
			return nil, fmt.Errorf("admitted %s execution contract changed", status.Mutation.Kind)
		}
	}
	_ = spec
	return object, nil
}

func betaMutationContract(kind string, object client.Object, status *attacknetv1beta1.FaultActionStatus) (any, error) {
	if kind == "BurnchainReorgWorker" {
		return burnchainReorgPodContract(object)
	}
	if kind != "ClockSkewPolicy" {
		return mutationContract(kind, object)
	}
	policy, ok := object.(*corev1.ConfigMap)
	if !ok {
		return nil, fmt.Errorf("ClockSkewPolicy mutation is %T, want ConfigMap", object)
	}
	selected := map[string]string{}
	for _, target := range status.ResolvedTargets {
		selected[target.Actor] = policy.Data[target.Actor]
	}
	return map[string]any{
		"uid": policy.UID, "name": policy.Name, "namespace": policy.Namespace,
		"labels": policy.Labels, "selectedData": selected,
	}, nil
}

func (r *V1Beta1Reconciler) removeBetaMutation(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus) error {
	object, err := r.getBetaMutation(ctx, campaign, spec, status)
	if err != nil || object == nil {
		if status.Mutation != nil && status.Mutation.Kind == "BurnchainReorgWorker" {
			return r.restoreBurnchainPolicy(ctx, campaign, status)
		}
		return err
	}
	if status.Mutation.Kind == "BurnchainReorgWorker" {
		return r.removeBurnchainReorgWorker(ctx, campaign, status, object.(*corev1.Pod))
	}
	if policy, ok := object.(*corev1.ConfigMap); ok {
		base := policy.DeepCopy()
		for _, target := range status.ResolvedTargets {
			policy.Data[target.Actor] = clockPolicyZero
		}
		return r.Patch(ctx, policy, client.MergeFrom(base))
	}
	if controllerOwnerUID(object) != string(campaign.UID) {
		return errors.New("refusing to delete a mutation not owned by the campaign")
	}
	return client.IgnoreNotFound(r.Delete(ctx, object))
}

func (r *V1Beta1Reconciler) betaMutationRecovered(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus) (bool, error) {
	object, err := r.getBetaMutation(ctx, campaign, spec, status)
	if err != nil {
		return false, err
	}
	if object == nil {
		if status.Mutation != nil && status.Mutation.Kind == "BurnchainReorgWorker" {
			return r.burnchainPolicyRecovered(ctx, campaign, status)
		}
		return true, nil
	}
	if policy, ok := object.(*corev1.ConfigMap); ok {
		for _, target := range status.ResolvedTargets {
			if policy.Data[target.Actor] != clockPolicyZero {
				return false, nil
			}
		}
		return true, nil
	}
	return mutationRecovered(object), nil
}

func (r *V1Beta1Reconciler) captureBetaDuring(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, stageID string, spec *attacknetv1beta1.FaultActionSpec, compiled *CompiledAction, status *attacknetv1beta1.FaultActionStatus, campaignStatus *attacknetv1beta1.FaultCampaignStatus) (bool, error) {
	definition := mustMechanismForType(spec.Fault.Type)
	if definition.Backend == burnchainReorgBackend {
		return r.captureBurnchainReorgDuring(ctx, campaign, spec, status)
	}
	shadow := betaShadowCampaign(campaign, stageID, status.ID, legacyTargets(status.ResolvedTargets))
	object, err := r.getBetaMutation(ctx, campaign, spec, status)
	if err != nil {
		return false, err
	}
	if object == nil {
		return false, errors.New("mutation disappeared before evidence capture")
	}
	actual, err := actualInjectionEvidence(object, mutationIdentity{Kind: status.Mutation.Kind, Name: status.Mutation.Name}, shadow, metav1.NewTime(r.now()))
	if err != nil {
		return false, err
	}
	status.ActualInjection = &actual
	if definition.EffectKind == "pod" {
		status.EffectResults = podEffectResults(shadow, pods, r.now())
		return provenResults(status.EffectResults) >= minimumAffected(shadow.Spec.Fault, len(status.ResolvedTargets)) &&
			assertionsSatisfied(shadow.Spec.EffectAssertions, status.EffectResults), nil
	}
	legacyNetwork := betaProbeNetwork(network)
	during, err := r.legacyRuntime().captureProbePhase(ctx, shadow, legacyNetwork, pods, legacyTargets(status.ResolvedTargets), Compiled{Resource: compiled.Resource, Evidence: compiled.Evidence}, "during", true)
	if err != nil {
		return false, err
	}
	if campaignStatus.ProbeArtifacts == nil {
		campaignStatus.ProbeArtifacts = map[string]string{}
	}
	campaignStatus.ProbeArtifacts[betaProbeKey(stageID, status.ID, "during")] = string(during)
	if definition.Backend == clockPolicyBackend {
		proven, proofErr := clockInjectionProven(shadow, legacyTargets(status.ResolvedTargets), betaActionProbeArtifacts(campaignStatus.ProbeArtifacts, stageID, status.ID))
		if proofErr != nil {
			return false, proofErr
		}
		return proven, nil
	}
	report, err := evaluateDuringProbeEvidence(shadow, Compiled{Resource: compiled.Resource, Evidence: compiled.Evidence}, legacyTargets(status.ResolvedTargets), betaActionProbeArtifacts(campaignStatus.ProbeArtifacts, stageID, status.ID))
	if err != nil {
		return false, err
	}
	status.EffectResults, _ = evaluationResults(shadow, report, r.now())
	return report.Verdict == "Proven" && assertionsSatisfied(shadow.Spec.EffectAssertions, status.EffectResults), nil
}

func (r *V1Beta1Reconciler) captureBetaRecovery(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod, stageID string, spec *attacknetv1beta1.FaultActionSpec, compiled *CompiledAction, status *attacknetv1beta1.FaultActionStatus, campaignStatus *attacknetv1beta1.FaultCampaignStatus) (bool, error) {
	shadow := betaShadowCampaign(campaign, stageID, status.ID, legacyTargets(status.ResolvedTargets))
	definition := mustMechanismForType(spec.Fault.Type)
	if definition.Backend == burnchainReorgBackend {
		return r.captureBurnchainReorgRecovery(ctx, campaign, status)
	}
	manifest := ManifestFromV1Beta1(network)
	targets, err := ResolveTargets(manifest, compiled.Evidence.SelectedActors, pods)
	if err != nil {
		return false, nil
	}
	if definition.EffectKind == "pod" {
		status.RecoveryResults = nil
		for _, target := range targets {
			value, _ := rawJSON(map[string]any{"assertion": "TargetReady", "outcome": "Proven", "actor": target.Actor, "podUid": target.PodUID, "observedAt": r.now()})
			status.RecoveryResults = append(status.RecoveryResults, value)
		}
		return assertionsSatisfied(shadow.Spec.EffectAssertions, status.EffectResults) && assertionsSatisfied(shadow.Spec.RecoveryAssertions, status.RecoveryResults), nil
	}
	legacyNetwork := betaProbeNetwork(network)
	after, err := r.legacyRuntime().captureProbePhase(ctx, shadow, legacyNetwork, pods, targets, Compiled{Resource: compiled.Resource, Evidence: compiled.Evidence}, "after", false)
	if err != nil {
		return false, err
	}
	if campaignStatus.ProbeArtifacts == nil {
		campaignStatus.ProbeArtifacts = map[string]string{}
	}
	campaignStatus.ProbeArtifacts[betaProbeKey(stageID, status.ID, "after")] = string(after)
	report, err := evaluateProbeEvidence(shadow, Compiled{Resource: compiled.Resource, Evidence: compiled.Evidence}, legacyTargets(status.ResolvedTargets), betaActionProbeArtifacts(campaignStatus.ProbeArtifacts, stageID, status.ID))
	if err != nil {
		return false, err
	}
	status.EffectResults, status.RecoveryResults = evaluationResults(shadow, report, r.now())
	return report.Verdict == "Proven" && report.RecoveryVerdict == "Proven" &&
		assertionsSatisfied(shadow.Spec.EffectAssertions, status.EffectResults) &&
		assertionsSatisfied(shadow.Spec.RecoveryAssertions, status.RecoveryResults), nil
}

func betaProbeKey(stageID, actionID, phase string) string {
	return stageID + "/" + actionID + "/" + phase + "Json"
}

func betaActionProbeArtifacts(values map[string]string, stageID, actionID string) map[string]string {
	result := map[string]string{}
	for _, phase := range []string{"before", "during", "after"} {
		if value := values[betaProbeKey(stageID, actionID, phase)]; value != "" {
			result[phase+"Json"] = value
		}
	}
	return result
}

func betaAssertionTimeout(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string, effect bool, fallback time.Duration) time.Duration {
	assertions := betaScopedAssertions(campaign, stageID, actionID, effect)
	result := time.Duration(0)
	for _, assertion := range assertions {
		if value := time.Duration(assertion.TimeoutSeconds) * time.Second; value > result {
			result = value
		}
	}
	if result == 0 {
		return fallback
	}
	return result
}

func betaRecoveryTimedOut(campaign *attacknetv1beta1.FaultCampaign, stageID string, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus, now time.Time) bool {
	if status.Mutation == nil || status.Mutation.InjectedAt == nil {
		return true
	}
	deadline := status.Mutation.InjectedAt.Time.Add(spec.Fault.Duration.Duration).Add(
		betaAssertionTimeout(campaign, stageID, status.ID, false, 300*time.Second),
	)
	return !now.Before(deadline)
}

func (r *V1Beta1Reconciler) rollbackBetaActions(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, stage *attacknetv1beta1.FaultStageStatus, indexes []int) {
	for _, index := range indexes {
		if index >= len(stage.Actions) {
			continue
		}
		_ = r.removeBetaMutation(ctx, campaign, nil, &stage.Actions[index])
	}
}

func (r *V1Beta1Reconciler) enforceBetaIdentity(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, pods []corev1.Pod) (bool, error) {
	allowed := betaAllowedPodChanges(campaign)
	differences := inventory.BetaCompareLive(campaign.Status.Admission.NetworkInventory, network, pods, allowed)
	if len(differences) == 0 {
		return false, nil
	}
	cleanupErr := r.cleanupAllBeta(ctx, campaign)
	if cleanupErr == nil {
		_ = r.releaseBetaMutationLease(ctx, campaign)
	}
	now := metav1.NewTime(r.now())
	next := *campaign.Status.DeepCopy()
	next.IdentityDivergence = &attacknetv1beta1.IdentityDivergence{
		ExpectedDigest: campaign.Status.Admission.NetworkInventory.Digest, CurrentDigest: network.Status.InventoryDigest,
		ObservedAt: now, Differences: differences,
	}
	next.CompletedAt = &now
	next.Cleanup = &attacknetv1beta1.CleanupEvidence{Absent: cleanupErr == nil, AllRecovered: cleanupErr == nil, Method: "IdentityDivergenceCleanup", ObservedAt: now}
	message := "the admitted network identity changed; the campaign was not retargeted"
	if cleanupErr != nil {
		message += "; cleanup remains pending: " + truncate(cleanupErr.Error(), 500)
	}
	return true, r.patchBetaStatus(ctx, campaign, betaStatusTransition(next, campaign.Generation, "Inconclusive", "TargetIdentityDiverged", message, r.now()))
}

func betaAllowedPodChanges(campaign *attacknetv1beta1.FaultCampaign) map[string]struct{} {
	allowed := map[string]struct{}{}
	for _, stage := range campaign.Status.Stages {
		for _, action := range stage.Actions {
			spec := betaActionSpec(campaign, stage.ID, action.ID)
			// Once the admitted pod-kill mutation exists, its target Pod UID may
			// legitimately differ for the remainder of this campaign. Completion
			// is not an identity rebase: image, StatefulSet, revision, role, and
			// service identity remain enforced by inventory comparison.
			if spec != nil && spec.Fault.Type == "pod" && spec.Fault.Action == "pod-kill" && action.Mutation != nil {
				for _, target := range action.ResolvedTargets {
					allowed[target.Actor] = struct{}{}
				}
			}
		}
	}
	return allowed
}

func (r *V1Beta1Reconciler) cleanupAllBeta(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign) error {
	var failures []string
	for stageIndex := range campaign.Status.Stages {
		stage := &campaign.Status.Stages[stageIndex]
		for actionIndex := range stage.Actions {
			action := &stage.Actions[actionIndex]
			if err := r.removeBetaMutation(ctx, campaign, nil, action); err != nil {
				failures = append(failures, err.Error())
			}
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (r *V1Beta1Reconciler) reconcileBetaDeletion(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign) (reconcile.Result, error) {
	if !controllerutil.ContainsFinalizer(campaign, betaFinalizer) {
		return reconcile.Result{}, nil
	}
	// Terminal cleanup is durable proof that every mutation is absent and every
	// shared policy is restored. Do not repeat semantic cleanup during a later
	// deletion: dependencies may already have been removed, and requiring them
	// again can strand an otherwise-clean campaign finalizer forever.
	if !betaCleanupComplete(campaign.Status.Cleanup) {
		if err := r.cleanupAllBeta(ctx, campaign); err != nil {
			return reconcile.Result{}, err
		}
	}
	_ = r.releaseBetaMutationLease(ctx, campaign)
	base := campaign.DeepCopy()
	controllerutil.RemoveFinalizer(campaign, betaFinalizer)
	return reconcile.Result{}, r.Patch(ctx, campaign, client.MergeFrom(base))
}

func (r *V1Beta1Reconciler) reconcileBetaTerminal(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign) error {
	if !betaCleanupComplete(campaign.Status.Cleanup) {
		if err := r.cleanupAllBeta(ctx, campaign); err != nil {
			return err
		}
		next := *campaign.Status.DeepCopy()
		observed := metav1.NewTime(r.now())
		next.Cleanup = &attacknetv1beta1.CleanupEvidence{
			Absent: true, AllRecovered: true, Method: "TerminalCleanup", ObservedAt: observed,
		}
		return r.patchBetaStatus(ctx, campaign, next)
	}
	if err := r.releaseBetaMutationLease(ctx, campaign); err != nil {
		return err
	}
	if !controllerutil.ContainsFinalizer(campaign, betaFinalizer) {
		return nil
	}
	base := campaign.DeepCopy()
	controllerutil.RemoveFinalizer(campaign, betaFinalizer)
	return r.Patch(ctx, campaign, client.MergeFrom(base))
}

func (r *V1Beta1Reconciler) reconcileBetaTemplate(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign) error {
	if controllerutil.ContainsFinalizer(campaign, betaFinalizer) {
		base := campaign.DeepCopy()
		controllerutil.RemoveFinalizer(campaign, betaFinalizer)
		return r.Patch(ctx, campaign, client.MergeFrom(base))
	}
	return r.markBetaTemplate(ctx, campaign)
}

func betaCleanupComplete(cleanup *attacknetv1beta1.CleanupEvidence) bool {
	return cleanup != nil && cleanup.Absent && cleanup.AllRecovered
}

func (r *V1Beta1Reconciler) markBetaTemplate(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign) error {
	digest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		return err
	}
	next := *campaign.Status.DeepCopy()
	next.TemplateDigest = digest
	return r.patchBetaStatus(ctx, campaign, betaStatusTransition(next, campaign.Generation, "Pending", "TemplateReady", "", r.now()))
}

func (r *V1Beta1Reconciler) failBeta(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, reason string, cause error) error {
	return r.failBetaWithStatus(ctx, campaign, campaign.Status, reason, cause)
}

func (r *V1Beta1Reconciler) failBetaWithStatus(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, status attacknetv1beta1.FaultCampaignStatus, reason string, cause error) error {
	cleanupView := campaign.DeepCopy()
	cleanupView.Status = *status.DeepCopy()
	cleanupErr := r.cleanupAllBeta(ctx, cleanupView)
	if cleanupErr == nil {
		_ = r.releaseBetaMutationLease(ctx, campaign)
	}
	next := *status.DeepCopy()
	completed := metav1.NewTime(r.now())
	next.CompletedAt = &completed
	next.Cleanup = &attacknetv1beta1.CleanupEvidence{
		Absent: cleanupErr == nil, AllRecovered: cleanupErr == nil,
		Method: "FailureRollback", ObservedAt: completed,
	}
	if cleanupErr != nil {
		cause = fmt.Errorf("%w; cleanup: %v", cause, cleanupErr)
	}
	return r.patchBetaStatus(ctx, campaign, betaStatusTransition(next, campaign.Generation, "Failed", reason, truncate(cause.Error(), 1000), r.now()))
}

func (r *V1Beta1Reconciler) transitionBeta(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, phase, reason, message string) error {
	return r.patchBetaStatus(ctx, campaign, betaStatusTransition(campaign.Status, campaign.Generation, phase, reason, message, r.now()))
}

func betaStatusTransition(status attacknetv1beta1.FaultCampaignStatus, generation int64, phase, reason, message string, now time.Time) attacknetv1beta1.FaultCampaignStatus {
	status = *status.DeepCopy()
	changed := status.Phase != phase || status.Reason != reason
	status.ObservedGeneration, status.Phase, status.Reason, status.Message = generation, phase, reason, message
	if changed || status.LastTransitionTime == nil {
		at := metav1.NewTime(now)
		status.LastTransitionTime = &at
	}
	conditionStatus := metav1.ConditionFalse
	if phase == "Passed" {
		conditionStatus = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: "Succeeded", Status: conditionStatus, ObservedGeneration: generation,
		Reason: reason, Message: message,
	})
	return status
}

func (r *V1Beta1Reconciler) patchBetaStatus(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, next attacknetv1beta1.FaultCampaignStatus) error {
	if reflect.DeepEqual(campaign.Status, next) {
		return nil
	}
	current := &attacknetv1beta1.FaultCampaign{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(campaign), current); err != nil {
		return err
	}
	if current.ResourceVersion != campaign.ResourceVersion {
		return apierrors.NewConflict(
			schema.GroupResource{Group: attacknetv1beta1.GroupVersion.Group, Resource: "faultcampaigns"},
			campaign.Name,
			fmt.Errorf("resource changed from version %s to %s before status write", campaign.ResourceVersion, current.ResourceVersion),
		)
	}
	base := campaign.DeepCopy()
	campaign.Status = next
	return r.Status().Patch(ctx, campaign, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func (r *V1Beta1Reconciler) legacyRuntime() *Reconciler {
	return &Reconciler{
		Client: r.Client, APIReader: r.APIReader, Scheme: r.Scheme, Probes: r.Probes, Now: r.Now,
		IOPressureImage: r.IOPressureImage, IOPressurePull: r.IOPressurePull,
		IOChaosArchitectures: r.IOChaosArchitectures, TimeChaosArchitectures: r.TimeChaosArchitectures,
	}
}

func (r *V1Beta1Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func betaRunOwner(campaign *attacknetv1beta1.FaultCampaign) *metav1.OwnerReference {
	owner := metav1.GetControllerOf(campaign)
	if owner == nil || owner.APIVersion != attacknetv1beta1.GroupVersion.String() || owner.Kind != "AttacknetRun" {
		return nil
	}
	return owner
}

func betaLeaseCampaign(campaign *attacknetv1beta1.FaultCampaign) *attacknetv1alpha1.FaultCampaign {
	name, uid := campaign.Name, campaign.UID
	annotations := map[string]string{}
	if owner := betaRunOwner(campaign); owner != nil {
		name, uid = owner.Name, owner.UID
		annotations[mutationLeaseOwnerKindAnnotation] = "attacknetrun"
	}
	return &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: campaign.Namespace, UID: uid, Annotations: annotations},
		Spec:       attacknetv1alpha1.FaultCampaignSpec{NetworkRef: campaign.Spec.NetworkRef},
	}
}

func (r *V1Beta1Reconciler) releaseBetaMutationLease(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign) error {
	if owner := betaRunOwner(campaign); owner != nil {
		siblings := &attacknetv1beta1.FaultCampaignList{}
		if err := r.APIReader.List(ctx, siblings, client.InNamespace(campaign.Namespace)); err != nil {
			return err
		}
		for index := range siblings.Items {
			sibling := &siblings.Items[index]
			siblingOwner := betaRunOwner(sibling)
			if sibling.UID != campaign.UID && siblingOwner != nil && siblingOwner.UID == owner.UID && !betaTerminalPhases[sibling.Status.Phase] {
				return nil
			}
		}
	}
	return r.legacyRuntime().releaseMutationLease(ctx, betaLeaseCampaign(campaign))
}

func betaShadowCampaign(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string, targets []attacknetv1alpha1.ResolvedTarget) *attacknetv1alpha1.FaultCampaign {
	spec := betaActionSpec(campaign, stageID, actionID)
	shadow := &attacknetv1alpha1.FaultCampaign{ObjectMeta: *campaign.ObjectMeta.DeepCopy()}
	shadow.Name = mutationName(campaign.Name, stageID, actionID)
	shadow.UID = campaign.UID
	shadow.Spec.NetworkRef = campaign.Spec.NetworkRef
	shadow.Spec.Safety = attacknetv1alpha1.FaultSafety{
		MaxUnavailableSignerPercent: 100, MaxUnavailableMinerPercent: 100,
		AllowQuorumLoss: true, AllowMinerMajorityOutage: true,
		AllowBurnchain: campaign.Spec.Safety.AllowBurnchain, AllowExtendedDuration: campaign.Spec.Safety.AllowExtendedDuration,
		AllowExtremeSeverity: campaign.Spec.Safety.AllowExtremeSeverity, AllowUnenrolledTargets: campaign.Spec.Safety.AllowUnenrolledTargets,
	}
	if spec != nil {
		shadow.Spec.Target = attacknetv1alpha1.FaultTarget{Actors: append([]string(nil), spec.Target.Actors...), Roles: append([]string(nil), spec.Target.Roles...)}
		shadow.Spec.Fault = attacknetv1alpha1.FaultSpec{Type: spec.Fault.Type, Action: spec.Fault.Action, Mode: spec.Fault.Mode, Value: spec.Fault.Value, Duration: legacyDuration(spec.Fault.Duration.Duration), Parameters: spec.Fault.Parameters}
		shadow.Spec.EffectAssertions = betaAssertions(campaign, stageID, actionID, true)
		shadow.Spec.RecoveryAssertions = betaAssertions(campaign, stageID, actionID, false)
	}
	shadow.Status.ResolvedTargets = targets
	return shadow
}

func betaAssertions(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string, effect bool) []attacknetv1alpha1.CampaignAssertion {
	values := betaScopedAssertions(campaign, stageID, actionID, effect)
	result := make([]attacknetv1alpha1.CampaignAssertion, len(values))
	for index, value := range values {
		result[index] = attacknetv1alpha1.CampaignAssertion{Type: value.Type, Actor: value.Actor, TimeoutSeconds: value.TimeoutSeconds}
	}
	return result
}

func betaScopedAssertions(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string, effect bool) []attacknetv1beta1.CampaignAssertion {
	values := make([]attacknetv1beta1.CampaignAssertion, 0)
	appendApplicable := func(assertions []attacknetv1beta1.CampaignAssertion) {
		for _, assertion := range assertions {
			if assertion.Action == "" || assertion.Action == actionID {
				values = append(values, assertion)
			}
		}
	}
	appendApplicable(ternary(effect, campaign.Spec.EffectAssertions, campaign.Spec.RecoveryAssertions))
	for _, stage := range campaign.Spec.Stages {
		if stage.ID != stageID {
			continue
		}
		appendApplicable(ternary(effect, stage.EffectAssertions, stage.RecoveryAssertions))
		for _, action := range stage.Faults {
			if action.ID == actionID {
				appendApplicable(ternary(effect, action.EffectAssertions, action.RecoveryAssertions))
			}
		}
	}
	return values
}

func betaActionSpec(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string) *attacknetv1beta1.FaultActionSpec {
	for stageIndex := range campaign.Spec.Stages {
		stage := &campaign.Spec.Stages[stageIndex]
		if stage.ID != stageID {
			continue
		}
		for actionIndex := range stage.Faults {
			if stage.Faults[actionIndex].ID == actionID {
				return &stage.Faults[actionIndex]
			}
		}
	}
	return nil
}

func betaStageSpec(campaign *attacknetv1beta1.FaultCampaign, stageID string) *attacknetv1beta1.FaultStageSpec {
	for index := range campaign.Spec.Stages {
		if campaign.Spec.Stages[index].ID == stageID {
			return &campaign.Spec.Stages[index]
		}
	}
	return &attacknetv1beta1.FaultStageSpec{}
}

func betaStageStartSkew(stage *attacknetv1beta1.FaultStageStatus) time.Duration {
	var first, last time.Time
	for _, action := range stage.Actions {
		if action.Mutation == nil || action.Mutation.CreatedAt == nil {
			continue
		}
		value := action.Mutation.CreatedAt.Time
		if first.IsZero() || value.Before(first) {
			first = value
		}
		if last.IsZero() || value.After(last) {
			last = value
		}
	}
	if first.IsZero() {
		return 0
	}
	return last.Sub(first)
}

func betaTargets(values []attacknetv1alpha1.ResolvedTarget) []attacknetv1beta1.ResolvedTarget {
	result := make([]attacknetv1beta1.ResolvedTarget, len(values))
	for index, value := range values {
		result[index] = attacknetv1beta1.ResolvedTarget{
			Actor: value.Actor, Role: value.Role, Pod: value.Pod, PodUID: value.PodUID, PodIP: value.PodIP,
			Node: value.Node, RequestedImage: value.RequestedImage, ResolvedImageID: value.ResolvedImageID, RestartCount: value.RestartCount,
		}
	}
	return result
}

func legacyTargets(values []attacknetv1beta1.ResolvedTarget) []attacknetv1alpha1.ResolvedTarget {
	result := make([]attacknetv1alpha1.ResolvedTarget, len(values))
	for index, value := range values {
		result[index] = attacknetv1alpha1.ResolvedTarget{
			Actor: value.Actor, Role: value.Role, Pod: value.Pod, PodUID: value.PodUID, PodIP: value.PodIP,
			Node: value.Node, RequestedImage: value.RequestedImage, ResolvedImageID: value.ResolvedImageID, RestartCount: value.RestartCount,
		}
	}
	return result
}

func activeBetaStages(stages []attacknetv1beta1.FaultStageStatus) []string {
	result := []string{}
	for _, stage := range stages {
		if stage.Phase == "Injecting" || stage.Phase == "Active" || stage.Phase == "Recovering" {
			result = append(result, stage.ID)
		}
	}
	sort.Strings(result)
	return result
}

func aggregateBetaPhase(stages []attacknetv1beta1.FaultStageStatus) (string, string) {
	completed, active := 0, 0
	for _, stage := range stages {
		if stage.Phase == "Failed" {
			return "Failed", "StageFailed"
		}
		if stage.Phase == "Inconclusive" {
			return "Inconclusive", "StageInconclusive"
		}
		if stage.Phase == "Completed" {
			completed++
		}
		if stage.Phase == "Injecting" || stage.Phase == "Active" || stage.Phase == "Recovering" {
			active++
		}
	}
	if completed == len(stages) {
		return "Passed", "AllStagesCompleted"
	}
	if active > 0 {
		return "Running", "StagesActive"
	}
	return "Admitted", "WaitingForTrigger"
}

func betaParameterString(raw []byte, name string) string {
	return parameterString(raw, name)
}

func rawAPIJSON(value any) (apixv1.JSON, error) {
	encoded, err := json.Marshal(value)
	return apixv1.JSON{Raw: encoded}, err
}

// SetupWithManager registers v1beta1 campaigns and all mutation watches.
func (r *V1Beta1Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if r.APIReader == nil {
		return errors.New("v1beta1 FaultCampaign reconciler requires an uncached Kubernetes API reader")
	}
	if r.Observations == nil {
		return errors.New("v1beta1 FaultCampaign reconciler requires trusted protocol observations")
	}
	if r.CompilationCache == nil {
		cache, err := NewCompilationCache(defaultCompilationCacheCapacity)
		if err != nil {
			return err
		}
		r.CompilationCache = cache
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &attacknetv1beta1.FaultCampaign{}, "spec.networkRef", func(object client.Object) []string {
		return []string{object.(*attacknetv1beta1.FaultCampaign).Spec.NetworkRef}
	}); err != nil {
		return fmt.Errorf("index v1beta1 FaultCampaign networkRef: %w", err)
	}
	campaignRequestsForNetwork := func(ctx context.Context, object client.Object) []reconcile.Request {
		campaigns := &attacknetv1beta1.FaultCampaignList{}
		if err := r.List(ctx, campaigns, client.InNamespace(object.GetNamespace()), client.MatchingFields{"spec.networkRef": object.GetName()}); err != nil {
			return nil
		}
		requests := make([]reconcile.Request, len(campaigns.Items))
		for index := range campaigns.Items {
			requests[index] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&campaigns.Items[index])}
		}
		return requests
	}
	mapNetwork := handler.EnqueueRequestsFromMapFunc(campaignRequestsForNetwork)
	mapLabels := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, object client.Object) []reconcile.Request {
		name := object.GetLabels()["testing.stacks.org/campaign"]
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
	})
	b := builder.ControllerManagedBy(mgr).For(&attacknetv1beta1.FaultCampaign{}).
		Watches(&attacknetv1beta1.StacksNetwork{}, mapNetwork).
		Watches(&attacknetv1beta1.BurnchainPolicy{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			policy := object.(*attacknetv1beta1.BurnchainPolicy)
			network := &attacknetv1beta1.StacksNetwork{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: policy.Namespace, Name: policy.Spec.NetworkRef}, network); err != nil {
				return nil
			}
			return campaignRequestsForNetwork(ctx, network)
		})).Watches(&corev1.Pod{}, mapLabels).
		Watches(&corev1.ConfigMap{}, mapLabels).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent})
	for _, definition := range registeredMechanisms() {
		if definition.Backend != chaosMeshBackend {
			continue
		}
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: definition.MutationKind})
		b = b.Watches(object, mapLabels)
	}
	return b.Complete(r)
}
