package fault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
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
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
)

const (
	Finalizer        = "testing.stacks.org/fault-cleanup"
	environmentLease = "attacknet-environment-lease"
	mutationLease    = "attacknet-mutation-lease"
	clockPolicyZero  = "+0s\n"
)

var terminalPhases = map[string]bool{"Passed": true, "Failed": true, "Inconclusive": true}

var (
	errMutationIdentityChanged = errors.New("admitted mutation identity changed")
	errMutationContractChanged = errors.New("admitted mutation execution contract changed")
)

// mutationLeaseState distinguishes an unavailable environment lease from a
// mutation lease held by another writer.
type mutationLeaseState struct {
	Held               bool
	EnvironmentReady   bool
	EnvironmentMessage string
}

// Reconciler executes one bounded FaultCampaign and records durable evidence.
type Reconciler struct {
	client.Client
	APIReader              client.Reader
	Scheme                 *runtime.Scheme
	Probes                 ProbeClient
	Now                    func() time.Time
	IOPressureImage        string
	IOPressurePull         corev1.PullPolicy
	SignerSets             signerset.Resolver
	IOChaosArchitectures   map[string]bool
	TimeChaosArchitectures map[string]bool
}

type mutationIdentity struct {
	Kind, Name string
	GVK        schema.GroupVersionKind
}

// Reconcile advances one campaign by at most one durable state transition.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	campaign := &attacknetv1alpha1.FaultCampaign{}
	if err := r.Get(ctx, request.NamespacedName, campaign); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	current, err := r.campaignIsCurrent(ctx, campaign)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !current {
		return reconcile.Result{Requeue: true}, nil
	}
	if !campaign.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, r.reconcileDeletion(ctx, campaign)
	}
	if campaign.Spec.Template {
		return reconcile.Result{}, r.markTemplate(ctx, campaign)
	}
	if !controllerutil.ContainsFinalizer(campaign, Finalizer) {
		base := campaign.DeepCopy()
		controllerutil.AddFinalizer(campaign, Finalizer)
		return reconcile.Result{}, r.Patch(ctx, campaign, client.MergeFrom(base))
	}
	if terminalPhases[campaign.Status.Phase] {
		return reconcile.Result{}, r.reconcileTerminal(ctx, campaign)
	}
	serialized, err := r.isSerializedTurn(ctx, campaign)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !serialized && (campaign.Status.Phase == "" || campaign.Status.Phase == "Pending") {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transition(ctx, campaign, "Pending", "SerializedBehindActiveFault", "")
	}
	phase := campaign.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	key := types.NamespacedName{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef}
	network := &attacknetv1alpha1.StacksNetwork{}
	var pods []corev1.Pod
	if phase == "Pending" {
		if err := r.Get(ctx, key, network); err != nil {
			return reconcile.Result{}, err
		}
		pods, err = r.networkPods(ctx, network.Name, network.Namespace)
	} else {
		var live inventory.LiveView
		live, err = inventory.ReadLiveView(ctx, r.APIReader, key)
		network, pods = live.Network, live.Pods
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if phase == "Pending" && network.Status.Phase != "Ready" {
		return reconcile.Result{}, r.transition(ctx, campaign, "Pending", "NetworkNotReady", "")
	}
	if phase != "Pending" {
		lease, leaseErr := r.holdMutationLease(ctx, campaign, false)
		if leaseErr != nil {
			return reconcile.Result{}, leaseErr
		}
		if !lease.Held {
			cleanup, cleanupErr := r.removeMutation(ctx, campaign)
			if cleanupErr != nil {
				return reconcile.Result{}, cleanupErr
			}
			now := metav1.NewTime(r.now())
			next := *campaign.Status.DeepCopy()
			next.Cleanup = cleanup
			next.CompletedAt = &now
			message := "the mutation lease changed after admission; only the controller-owned mutation was removed"
			if !lease.EnvironmentReady {
				message = lease.EnvironmentMessage + "; only the controller-owned mutation was removed"
			}
			return reconcile.Result{}, r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Failed", "MutationLeaseLost", message, r.now()))
		}
		identityChanged, err := r.enforceIdentity(ctx, campaign, network, pods)
		if err != nil {
			return reconcile.Result{}, err
		}
		if identityChanged {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
	}
	manifest := ManifestFromNetwork(network)
	var canonicalSignerSet *signerset.Result
	if phase == "Pending" {
		resolved, resolveErr := r.signerResolver().Resolve(ctx, network, pods)
		if resolveErr != nil {
			var transient *signerset.TransientError
			if errors.As(resolveErr, &transient) {
				return reconcile.Result{}, resolveErr
			}
			return reconcile.Result{}, r.fail(ctx, campaign, "SignerSetAdmissionFailed", resolveErr)
		}
		canonicalSignerSet = &resolved
		manifest = applyCanonicalWeights(manifest, resolved.WeightsByActor)
	}
	compiled, err := Compile(campaign, manifest)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, campaign, "CampaignInvalid", err)
	}
	compiledDigest, err := canonical.ArtifactDigest(compiled.Resource.Object)
	if err != nil {
		return reconcile.Result{}, err
	}
	campaignSpecDigest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		return reconcile.Result{}, err
	}
	if phase == "Pending" {
		return r.admit(ctx, campaign, network, pods, compiled, compiledDigest, campaignSpecDigest, *canonicalSignerSet)
	}
	if !admissionMatches(campaign.Status.Admission, campaign, network, compiledDigest, campaignSpecDigest) {
		return reconcile.Result{}, r.fail(ctx, campaign, "AdmissionInputChanged", errors.New("admitted campaign or network changed"))
	}
	var result reconcile.Result
	var phaseErr error
	switch phase {
	case "Admitted":
		currentSignerSet, resolveErr := r.signerResolver().Resolve(ctx, network, pods)
		if resolveErr != nil {
			var transient *signerset.TransientError
			if errors.As(resolveErr, &transient) {
				return reconcile.Result{}, resolveErr
			}
			return reconcile.Result{}, r.fail(ctx, campaign, "SignerSetChangedBeforeInjection", resolveErr)
		}
		if campaign.Status.Admission == nil || currentSignerSet.SignerSetDigest != campaign.Status.Admission.SignerSetDigest {
			return reconcile.Result{}, r.fail(ctx, campaign, "SignerSetChangedBeforeInjection", errors.New("canonical signer set changed after admission"))
		}
		phaseErr = r.inject(ctx, campaign, network, pods, compiled)
	case "Injecting":
		phaseErr = r.observeInjection(ctx, campaign, network, pods, compiled)
	case "Active":
		phaseErr = r.observeActive(ctx, campaign, network, compiled)
	case "Recovering":
		phaseErr = r.observeRecovery(ctx, campaign, network, pods, compiled)
	default:
		return reconcile.Result{}, r.fail(ctx, campaign, "UnknownPhase", fmt.Errorf("unsupported phase %s", phase))
	}
	if phaseErr != nil {
		switch {
		case errors.Is(phaseErr, errMutationIdentityChanged):
			return reconcile.Result{}, r.fail(ctx, campaign, "MutationIdentityChanged", phaseErr)
		case errors.Is(phaseErr, errMutationContractChanged):
			return reconcile.Result{}, r.fail(ctx, campaign, "MutationExecutionContractChanged", phaseErr)
		default:
			return reconcile.Result{}, phaseErr
		}
	}
	result.RequeueAfter = 2 * time.Second
	return result, nil
}

// campaignIsCurrent prevents an informer-delayed reconcile from reversing a
// newer durable phase or acting on a superseded campaign specification.
func (r *Reconciler) campaignIsCurrent(ctx context.Context, cached *attacknetv1alpha1.FaultCampaign) (bool, error) {
	if r.APIReader == nil {
		return false, errors.New("fault reconciler requires an uncached Kubernetes API reader")
	}
	live := &attacknetv1alpha1.FaultCampaign{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(cached), live); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return cached.ResourceVersion == live.ResourceVersion, nil
}

func (r *Reconciler) markTemplate(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) error {
	digest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		return err
	}
	if campaign.Status.Phase == "Pending" && campaign.Status.Reason == "TemplateReady" && campaign.Status.TemplateDigest == digest {
		return nil
	}
	next := *campaign.Status.DeepCopy()
	next.TemplateDigest = digest
	return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Pending", "TemplateReady", "", r.now()))
}

func (r *Reconciler) admit(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, compiled Compiled, compiledDigest, campaignSpecDigest string, signerSet signerset.Result) (reconcile.Result, error) {
	published, err := inventory.Published(network)
	if err != nil {
		return reconcile.Result{}, r.transition(ctx, campaign, "Pending", "NetworkInventoryNotReady", err.Error())
	}
	if differences := inventory.CompareLive(published, network, pods, nil); len(differences) > 0 {
		return reconcile.Result{}, r.transition(ctx, campaign, "Pending", "NetworkInventoryNotReady", "published inventory does not match live Pods")
	}
	targets, err := ResolveTargets(ManifestFromNetwork(network), compiled.Evidence.SelectedActors, pods)
	if err != nil {
		return reconcile.Result{}, r.transition(ctx, campaign, "Pending", "NetworkInventoryNotReady", err.Error())
	}
	lease, err := r.holdMutationLease(ctx, campaign, true)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !lease.EnvironmentReady {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transition(ctx, campaign, "Pending", "WaitingForEnvironmentLease", lease.EnvironmentMessage)
	}
	if !lease.Held {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transition(ctx, campaign, "Pending", "WaitingForMutationLease", "")
	}
	capabilities := r.capabilityEvidence(ctx, campaign, pods, targets)
	capabilityJSON := make([]apixv1.JSON, 0, len(capabilities))
	unavailable := []string{}
	for _, capability := range capabilities {
		value, _ := rawJSON(capability)
		capabilityJSON = append(capabilityJSON, value)
		if !capability.Supported {
			unavailable = append(unavailable, capability.Actor+": "+capability.Reason)
		}
	}
	if len(unavailable) > 0 {
		next := *campaign.Status.DeepCopy()
		next.ResolvedTargets = targets
		next.ResolvedTargetCount = int32(len(targets))
		next.CapabilityEvidence = capabilityJSON
		completed := metav1.NewTime(r.now())
		next.CompletedAt = &completed
		return reconcile.Result{}, r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Failed", "FaultCapabilityUnavailable", truncate(strings.Join(unavailable, "; "), 1000), r.now()))
	}
	probeArtifacts := map[string]string{}
	if kindByType[campaign.Spec.Fault.Type] != "PodChaos" {
		before, err := r.captureProbePhase(ctx, campaign, network, pods, targets, compiled, "before", false)
		if err != nil {
			return reconcile.Result{}, r.fail(ctx, campaign, "ProbeBaselineUnavailable", err)
		}
		probeArtifacts["beforeJson"] = string(before)
		if !baselineUsable(kindByType[campaign.Spec.Fault.Type], before, compiled.Evidence.SelectedActors) {
			next := *campaign.Status.DeepCopy()
			next.ResolvedTargets = targets
			next.ResolvedTargetCount = int32(len(targets))
			next.CapabilityEvidence = capabilityJSON
			next.ProbeArtifacts = probeArtifacts
			completed := metav1.NewTime(r.now())
			next.CompletedAt = &completed
			return reconcile.Result{}, r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Failed", "ProbeBaselineUnavailable", "trusted pre-fault probes did not establish a usable baseline", r.now()))
		}
	}
	signerImpact, _ := rawJSON(compiled.Evidence.SignerImpact)
	minerImpact, _ := rawJSON(compiled.Evidence.MinerImpact)
	now := metav1.NewTime(r.now())
	next := *campaign.Status.DeepCopy()
	next.Admission = &attacknetv1alpha1.CampaignAdmission{
		NetworkUID:            string(network.UID),
		NetworkGeneration:     network.Generation,
		NetworkInventory:      published,
		CampaignGeneration:    campaign.Generation,
		CampaignSpecDigest:    campaignSpecDigest,
		CompiledDigest:        compiledDigest,
		AdmittedAt:            now,
		SignerSetDigest:       signerSet.SignerSetDigest,
		SignerSetObservedFrom: signerSet.ObservedFrom,
		SignerImpact:          &signerImpact,
		MinerImpact:           &minerImpact,
	}
	if signerSet.HasSigners {
		rewardCycle := signerSet.RewardCycle
		totalWeight := signerSet.ObservedTotalWeight
		next.Admission.SignerSetRewardCycle = &rewardCycle
		next.Admission.SignerSetTotalWeight = &totalWeight
	}
	next.ResolvedTargets = targets
	next.ResolvedTargetCount = int32(len(targets))
	next.CapabilityEvidence = capabilityJSON
	next.ProbeArtifacts = probeArtifacts
	return reconcile.Result{}, r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Admitted", "SafetyPolicySatisfied", "", r.now()))
}

func (r *Reconciler) inject(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, compiled Compiled) error {
	identity, err := mutationFor(campaign)
	if err != nil {
		return err
	}
	var object client.Object
	switch identity.Kind {
	case "ClockSkewPolicy":
		policy := &corev1.ConfigMap{}
		if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: identity.Name}, policy); err != nil {
			return r.fail(ctx, campaign, "ClockPolicyUnavailable", err)
		}
		if policy.Labels[NetworkLabel] != campaign.Spec.NetworkRef || policy.Labels["testing.stacks.org/clock-policy"] != "true" {
			return r.fail(ctx, campaign, "ClockPolicyUnavailable", errors.New("clock policy identity is invalid"))
		}
		offset := parameterString(campaign.Spec.Fault.Parameters.Raw, "timeOffset") + "\n"
		base := policy.DeepCopy()
		selected := set(campaignTargetNames(campaign))
		for actor := range policy.Data {
			if selected[actor] {
				policy.Data[actor] = offset
			} else {
				policy.Data[actor] = clockPolicyZero
			}
		}
		if err := r.Patch(ctx, policy, client.MergeFrom(base)); err != nil {
			return err
		}
		object = policy
	case "IOPressurePod":
		pod, err := r.buildIOPressurePod(campaign, pods, compiled)
		if err != nil {
			return r.fail(ctx, campaign, "FaultCapabilityUnavailable", err)
		}
		object = pod
		if err := r.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	default:
		resource := compiled.Resource.DeepCopy()
		resource.SetOwnerReferences([]metav1.OwnerReference{ownership.Reference(campaign, attacknetv1alpha1.GroupVersion.WithKind("FaultCampaign"))})
		object = resource
		if err := r.Create(ctx, resource); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	desiredObject := object.DeepCopyObject().(client.Object)
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: identity.Name}, object); err != nil {
		return err
	}
	if identity.Kind != "ClockSkewPolicy" {
		if err := requireCampaignOwner(campaign, object); err != nil {
			return r.fail(ctx, campaign, "MutationIdentityConflict", err)
		}
	}
	observedContract, err := mutationContract(identity.Kind, object)
	if err != nil {
		return err
	}
	if !mutationDesiredMatches(identity.Kind, desiredObject, object) {
		return r.fail(ctx, campaign, "MutationIdentityConflict", fmt.Errorf("refusing to adopt %s/%s with a different execution contract", identity.Kind, identity.Name))
	}
	now := metav1.NewTime(r.now())
	digest, _ := canonical.ArtifactDigest(observedContract)
	next := *campaign.Status.DeepCopy()
	next.Chaos = &attacknetv1alpha1.ChaosReference{Kind: identity.Kind, Name: identity.Name, UID: string(object.GetUID()), CreatedAt: &now, ResourceDigest: digest}
	return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Injecting", injectionReason(identity.Kind), "", r.now()))
}

func (r *Reconciler) observeInjection(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, compiled Compiled) error {
	object, identity, err := r.getMutation(ctx, campaign)
	if err != nil {
		return err
	}
	if object == nil {
		latest := &attacknetv1alpha1.FaultCampaign{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(campaign), latest); err != nil {
			return err
		}
		if latest.Status.Phase != "Injecting" || latest.Status.ActualInjection != nil {
			return nil
		}
		return r.fail(ctx, campaign, "InjectionResourceDisappeared", errors.New("mutation disappeared before injection was observed"))
	}
	injected := false
	switch typed := object.(type) {
	case *corev1.ConfigMap:
		injected = clockPolicyMatches(typed, campaign, parameterString(campaign.Spec.Fault.Parameters.Raw, "timeOffset")+"\n")
	case *corev1.Pod:
		injected = typed.Status.Phase == corev1.PodRunning && containerRunning(typed, "io-pressure")
	case *unstructured.Unstructured:
		injected = conditionTrue(typed, "AllInjected")
	}
	if !injected {
		if unstructuredObject, ok := object.(*unstructured.Unstructured); ok && conditionTrue(unstructuredObject, "AllRecovered") {
			return r.fail(ctx, campaign, "InjectionFailed", errors.New("fault recovered before full injection was observed"))
		}
		if elapsed(campaign.Status.Chaos.CreatedAt, r.now()) > assertionTimeout(campaign.Spec.EffectAssertions, 90*time.Second) {
			_, _ = r.removeMutation(ctx, campaign)
			return r.fail(ctx, campaign, "InjectionTimeout", errors.New("fault injection was not observed before the deadline"))
		}
		return nil
	}
	next := *campaign.Status.DeepCopy()
	if identity.Kind == "PodChaos" {
		now := metav1.NewTime(r.now())
		if next.InjectedAt == nil {
			next.InjectedAt = &now
		}
		actual, evidenceErr := actualInjectionEvidence(object, identity, campaign, now)
		if evidenceErr != nil {
			return evidenceErr
		}
		next.ActualInjection = &actual
	}
	if identity.Kind != "PodChaos" {
		during, probeErr := r.captureProbePhase(ctx, campaign, network, pods, campaign.Status.ResolvedTargets, compiled, "during", true)
		if probeErr != nil {
			return probeErr
		}
		if next.ProbeArtifacts == nil {
			next.ProbeArtifacts = map[string]string{}
		}
		next.ProbeArtifacts["duringJson"] = string(during)
		if identity.Kind == "ClockSkewPolicy" {
			proven, proofErr := clockInjectionProven(campaign, campaign.Status.ResolvedTargets, next.ProbeArtifacts)
			if proofErr != nil {
				return proofErr
			}
			if !proven {
				if elapsed(campaign.Status.Chaos.CreatedAt, r.now()) > assertionTimeout(campaign.Spec.EffectAssertions, 90*time.Second) {
					_, _ = r.removeMutation(ctx, campaign)
					return r.fail(ctx, campaign, "InjectionTimeout", errors.New("application clock offset was not observed before the deadline"))
				}
				return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Injecting", "WaitingForEffectEvidence", "", r.now()))
			}
		}
	} else {
		pods, err := r.networkPods(ctx, network.Name, network.Namespace)
		if err != nil {
			return err
		}
		next.EffectResults = podEffectResults(campaign, pods, r.now())
		if provenResults(next.EffectResults) >= minimumAffected(campaign.Spec.Fault, len(campaign.Status.ResolvedTargets)) {
			if campaign.Spec.Fault.Action == "pod-kill" || campaign.Spec.Fault.Action == "container-kill" {
				cleanup, cleanupErr := r.removeMutation(ctx, campaign)
				if cleanupErr != nil {
					return cleanupErr
				}
				next.Cleanup = cleanup
				return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Recovering", "OneShotEffectObserved", "", r.now()))
			}
			return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Active", "PodEffectObserved", "", r.now()))
		}
		chaos, _ := object.(*unstructured.Unstructured)
		if (chaos == nil || !conditionTrue(chaos, "AllRecovered")) && elapsed(campaign.Status.Chaos.CreatedAt, r.now()) <= assertionTimeout(campaign.Spec.EffectAssertions, 90*time.Second) {
			return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Injecting", "WaitingForEffectEvidence", "", r.now()))
		}
	}
	if identity.Kind != "PodChaos" {
		now := metav1.NewTime(r.now())
		if next.InjectedAt == nil {
			next.InjectedAt = &now
		}
		actual, evidenceErr := actualInjectionEvidence(object, identity, campaign, now)
		if evidenceErr != nil {
			return evidenceErr
		}
		next.ActualInjection = &actual
	}
	return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Active", "InjectionObserved", "", r.now()))
}

func actualInjectionEvidence(object client.Object, identity mutationIdentity, campaign *attacknetv1alpha1.FaultCampaign, observedAt metav1.Time) (apixv1.JSON, error) {
	values := map[string]any{"allInjectedObserved": true, "observedAt": observedAt}
	switch typed := object.(type) {
	case *unstructured.Unstructured:
		values["chaosResourceVersion"] = typed.GetResourceVersion()
		records, found, err := unstructured.NestedFieldCopy(typed.Object, "status", "experiment")
		if err != nil {
			return apixv1.JSON{}, err
		}
		if !found {
			records, _, err = unstructured.NestedFieldCopy(typed.Object, "status", "instances")
			if err != nil {
				return apixv1.JSON{}, err
			}
		}
		values["records"] = records
	case *corev1.ConfigMap:
		values["mechanism"] = "controller-owned-application-clock-policy"
		values["configMapUid"] = string(typed.UID)
		values["policyName"] = identity.Name
		values["requestedOffset"] = parameterString(campaign.Spec.Fault.Parameters.Raw, "timeOffset")
	case *corev1.Pod:
		values["mechanism"] = "controller-owned-io-pressure-pod"
		values["podUid"] = string(typed.UID)
		values["node"] = typed.Spec.NodeName
		values["phase"] = string(typed.Status.Phase)
		for _, status := range typed.Status.ContainerStatuses {
			if status.Name == "io-pressure" {
				values["image"] = status.Image
				values["imageID"] = status.ImageID
				break
			}
		}
		for _, volume := range typed.Spec.Volumes {
			if volume.Name == "actor-data" && volume.PersistentVolumeClaim != nil {
				values["pvcClaim"] = volume.PersistentVolumeClaim.ClaimName
			}
		}
		if len(campaign.Status.ResolvedTargets) == 1 {
			values["targetActor"] = campaign.Status.ResolvedTargets[0].Actor
			values["targetPodUid"] = campaign.Status.ResolvedTargets[0].PodUID
		}
	default:
		return apixv1.JSON{}, fmt.Errorf("unsupported mutation evidence object %T", object)
	}
	return rawJSON(values)
}

func (r *Reconciler) observeActive(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, _ *attacknetv1alpha1.StacksNetwork, _ Compiled) error {
	object, identity, err := r.getMutation(ctx, campaign)
	if err != nil {
		return err
	}
	if identity.Kind == "PodChaos" && (campaign.Spec.Fault.Action == "pod-kill" || campaign.Spec.Fault.Action == "container-kill") && campaign.Status.ActualInjection != nil {
		cleanup, cleanupErr := r.removeMutation(ctx, campaign)
		if cleanupErr != nil {
			return cleanupErr
		}
		next := *campaign.Status.DeepCopy()
		next.Cleanup = cleanup
		return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Recovering", "OneShotMutationRemoved", "", r.now()))
	}
	recovered := false
	if object == nil {
		recovered = true
	} else if chaos, ok := object.(*unstructured.Unstructured); ok {
		recovered = conditionTrue(chaos, "AllRecovered")
	} else if pod, ok := object.(*corev1.Pod); ok {
		recovered = pod.Status.Phase == corev1.PodSucceeded
	}
	duration, _ := time.ParseDuration(campaign.Spec.Fault.Duration)
	if identity.Kind == "ClockSkewPolicy" {
		recovered = elapsed(campaign.Status.InjectedAt, r.now()) >= duration
	}
	if !recovered && elapsed(campaign.Status.InjectedAt, r.now()) < duration+assertionTimeout(campaign.Spec.RecoveryAssertions, 300*time.Second) {
		return nil
	}
	if !recovered {
		return r.fail(ctx, campaign, "RecoveryTimeout", errors.New("fault did not recover before the deadline"))
	}
	cleanup, err := r.removeMutation(ctx, campaign)
	if err != nil {
		return err
	}
	next := *campaign.Status.DeepCopy()
	next.Cleanup = cleanup
	return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Recovering", "RecoveryObserved", "", r.now()))
}

func (r *Reconciler) observeRecovery(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, compiled Compiled) error {
	object, _, err := r.getMutation(ctx, campaign)
	if err != nil {
		return err
	}
	if object != nil && campaign.Spec.Fault.Type != "clock-skew" {
		return nil
	}
	next := *campaign.Status.DeepCopy()
	cleanupChanged := false
	if next.Cleanup == nil {
		next.Cleanup = &attacknetv1alpha1.CleanupEvidence{
			Absent: true, AllRecovered: true, Method: "ObservedAbsent",
			ObservedAt: metav1.NewTime(r.now()),
		}
		cleanupChanged = true
	} else if object == nil && !next.Cleanup.Absent {
		next.Cleanup.Absent = true
		next.Cleanup.AllRecovered = true
		next.Cleanup.ObservedAt = metav1.NewTime(r.now())
		cleanupChanged = true
	}
	targets, err := ResolveTargets(ManifestFromNetwork(network), compiled.Evidence.SelectedActors, pods)
	if err != nil {
		if elapsed(next.Cleanup.ObservedAt.DeepCopy(), r.now()) < assertionTimeout(campaign.Spec.RecoveryAssertions, 300*time.Second) {
			if cleanupChanged {
				return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Recovering", "WaitingForTargetRecovery", truncate(err.Error(), 1000), r.now()))
			}
			return nil
		}
		return r.fail(ctx, campaign, "TargetRecoveryTimeout", err)
	}
	effectProven := campaign.Status.ActualInjection != nil
	recoveryProven := true
	evidenceReason := ""
	if kindByType[campaign.Spec.Fault.Type] == "PodChaos" {
		effectProven = provenResults(campaign.Status.EffectResults) >= minimumAffected(campaign.Spec.Fault, len(campaign.Status.ResolvedTargets))
	} else {
		after, probeErr := r.captureProbePhase(ctx, campaign, network, pods, targets, compiled, "after", false)
		if probeErr != nil {
			effectProven, recoveryProven = false, false
			evidenceReason = probeErr.Error()
		} else {
			if next.ProbeArtifacts == nil {
				next.ProbeArtifacts = map[string]string{}
			}
			next.ProbeArtifacts["afterJson"] = string(after)
			report, evaluationErr := evaluateProbeEvidence(campaign, compiled, campaign.Status.ResolvedTargets, next.ProbeArtifacts)
			if evaluationErr != nil {
				effectProven, recoveryProven = false, false
				evidenceReason = evaluationErr.Error()
			} else {
				effectProven = report.Verdict == "Proven"
				recoveryProven = report.RecoveryVerdict == "Proven"
				next.EffectResults, next.RecoveryResults = evaluationResults(campaign, report, r.now())
			}
		}
	}
	if kindByType[campaign.Spec.Fault.Type] == "PodChaos" {
		recoveries := []apixv1.JSON{}
		for _, target := range targets {
			recovery, _ := rawJSON(map[string]any{"assertion": "TargetReady", "outcome": "Proven", "actor": target.Actor, "podUid": target.PodUID, "observedAt": r.now()})
			recoveries = append(recoveries, recovery)
		}
		next.RecoveryResults = recoveries
	}
	effectProven = effectProven && assertionsSatisfied(campaign.Spec.EffectAssertions, next.EffectResults)
	recoveryProven = recoveryProven && assertionsSatisfied(campaign.Spec.RecoveryAssertions, next.RecoveryResults)
	if (effectProven || campaign.Spec.Fault.Type == "clock-skew") && !recoveryProven && elapsed(next.Cleanup.ObservedAt.DeepCopy(), r.now()) <= assertionTimeout(campaign.Spec.RecoveryAssertions, 300*time.Second) {
		return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Recovering", "WaitingForRecoveryEvidence", truncate(evidenceReason, 1000), r.now()))
	}
	now := metav1.NewTime(r.now())
	next.CompletedAt = &now
	phase, reason := "Passed", "EffectAndRecoveryProven"
	if !effectProven || !recoveryProven {
		phase, reason = "Inconclusive", "EffectNotProven"
		if effectProven {
			reason = "RecoveryNotProven"
		}
		if evidenceReason != "" {
			reason = "ProbeEvidenceInvalid"
		}
	}
	return r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, phase, reason, truncate(evidenceReason, 1000), r.now()))
}

func admissionMatches(admission *attacknetv1alpha1.CampaignAdmission, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, compiledDigest, campaignSpecDigest string) bool {
	return admission != nil &&
		admission.NetworkUID == string(network.UID) &&
		admission.NetworkGeneration == network.Generation &&
		admission.CampaignGeneration == campaign.Generation &&
		admission.CampaignSpecDigest == campaignSpecDigest &&
		admission.CompiledDigest == compiledDigest
}

func (r *Reconciler) enforceIdentity(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod) (bool, error) {
	if campaign.Status.Admission == nil {
		return false, nil
	}
	allowed := map[string]struct{}{}
	if campaign.Spec.Fault.Type == "pod" && campaign.Spec.Fault.Action == "pod-kill" && (campaign.Status.Phase == "Injecting" || campaign.Status.Phase == "Active" || campaign.Status.Phase == "Recovering") {
		for _, target := range campaign.Status.ResolvedTargets {
			allowed[target.Actor] = struct{}{}
		}
	}
	differences := inventory.CompareLive(campaign.Status.Admission.NetworkInventory, network, pods, allowed)
	if len(differences) == 0 {
		return false, nil
	}
	cleanup, err := r.removeMutation(ctx, campaign)
	if err != nil {
		return false, err
	}
	now := metav1.NewTime(r.now())
	next := *campaign.Status.DeepCopy()
	next.IdentityDivergence = inventory.DivergenceEvidence(campaign.Status.Admission.NetworkInventory, network.Status.InventoryDigest, differences, now)
	next.Cleanup = cleanup
	next.CompletedAt = &now
	return true, r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Inconclusive", "TargetIdentityDiverged", "the admitted network identity changed; the campaign was not retargeted", r.now()))
}

func (r *Reconciler) reconcileTerminal(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) error {
	if !cleanupComplete(campaign.Status.Cleanup) {
		cleanup, err := r.removeMutation(ctx, campaign)
		if err != nil {
			return err
		}
		next := *campaign.Status.DeepCopy()
		next.Cleanup = cleanup
		return r.patchStatus(ctx, campaign, next)
	}
	if err := r.releaseMutationLease(ctx, campaign); err != nil {
		return err
	}
	if !controllerutil.ContainsFinalizer(campaign, Finalizer) {
		return nil
	}
	base := campaign.DeepCopy()
	controllerutil.RemoveFinalizer(campaign, Finalizer)
	return r.Patch(ctx, campaign, client.MergeFrom(base))
}
func (r *Reconciler) reconcileDeletion(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) error {
	if !controllerutil.ContainsFinalizer(campaign, Finalizer) {
		return nil
	}
	if !cleanupComplete(campaign.Status.Cleanup) {
		cleanup, err := r.removeMutation(ctx, campaign)
		if err != nil || !cleanup.Absent {
			return err
		}
	}
	if err := r.releaseMutationLease(ctx, campaign); err != nil {
		return err
	}
	base := campaign.DeepCopy()
	controllerutil.RemoveFinalizer(campaign, Finalizer)
	return r.Patch(ctx, campaign, client.MergeFrom(base))
}

func cleanupComplete(cleanup *attacknetv1alpha1.CleanupEvidence) bool {
	return cleanup != nil && cleanup.Absent && cleanup.AllRecovered
}

func (r *Reconciler) transition(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, phase, reason, message string) error {
	return r.patchStatus(ctx, campaign, statusTransition(campaign.Status, campaign.Generation, phase, reason, message, r.now()))
}
func (r *Reconciler) fail(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, reason string, err error) error {
	log.FromContext(ctx).Error(err, "campaign failed", "reason", reason)
	next := statusTransition(campaign.Status, campaign.Generation, "Failed", reason, truncate(err.Error(), 1000), r.now())
	completed := metav1.NewTime(r.now())
	next.CompletedAt = &completed
	return r.patchStatus(ctx, campaign, next)
}
func (r *Reconciler) patchStatus(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, next attacknetv1alpha1.FaultCampaignStatus) error {
	if reflect.DeepEqual(campaign.Status, next) {
		return nil
	}
	base := campaign.DeepCopy()
	campaign.Status = next
	return r.Status().Patch(ctx, campaign, client.MergeFrom(base))
}

func statusTransition(status attacknetv1alpha1.FaultCampaignStatus, generation int64, phase, reason, message string, now time.Time) attacknetv1alpha1.FaultCampaignStatus {
	status = *status.DeepCopy()
	changed := status.Phase != phase || status.Reason != reason
	status.ObservedGeneration = generation
	status.Phase, status.Reason, status.Message = phase, reason, message
	if changed || status.LastTransitionTime == nil {
		at := metav1.NewTime(now)
		status.LastTransitionTime = &at
	}
	conditionStatus := metav1.ConditionFalse
	if phase == "Passed" {
		conditionStatus = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Succeeded", Status: conditionStatus, ObservedGeneration: generation, Reason: reason, Message: message})
	return status
}

func (r *Reconciler) networkPods(ctx context.Context, network, namespace string) ([]corev1.Pod, error) {
	list := &corev1.PodList{}
	if err := r.List(ctx, list, client.InNamespace(namespace), client.MatchingLabels{NetworkLabel: network}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *Reconciler) isSerializedTurn(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) (bool, error) {
	list := &attacknetv1alpha1.FaultCampaignList{}
	if err := r.List(ctx, list, client.InNamespace(campaign.Namespace)); err != nil {
		return false, err
	}
	active := []attacknetv1alpha1.FaultCampaign{}
	for _, item := range list.Items {
		if item.Spec.Template || item.Spec.NetworkRef != campaign.Spec.NetworkRef || terminalPhases[item.Status.Phase] || !item.DeletionTimestamp.IsZero() {
			continue
		}
		active = append(active, item)
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].CreationTimestamp.Equal(&active[j].CreationTimestamp) {
			return active[i].Name < active[j].Name
		}
		return active[i].CreationTimestamp.Before(&active[j].CreationTimestamp)
	})
	return len(active) == 0 || active[0].UID == campaign.UID, nil
}

func mutationFor(campaign *attacknetv1alpha1.FaultCampaign) (mutationIdentity, error) {
	kind, ok := kindByType[campaign.Spec.Fault.Type]
	if !ok {
		return mutationIdentity{}, fmt.Errorf("unsupported fault type %s", campaign.Spec.Fault.Type)
	}
	switch kind {
	case "IOPressurePod":
		return mutationIdentity{Kind: kind, Name: stableFaultName("io-pressure", campaign.Name), GVK: corev1.SchemeGroupVersion.WithKind("Pod")}, nil
	case "ClockSkewPolicy":
		return mutationIdentity{Kind: kind, Name: campaign.Spec.NetworkRef + "-clock-policy", GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap")}, nil
	default:
		return mutationIdentity{Kind: kind, Name: campaign.Name, GVK: schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: kind}}, nil
	}
}
func (r *Reconciler) getMutation(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) (client.Object, mutationIdentity, error) {
	identity, err := mutationFor(campaign)
	if err != nil {
		return nil, identity, err
	}
	var object client.Object
	switch identity.Kind {
	case "ClockSkewPolicy":
		object = &corev1.ConfigMap{}
	case "IOPressurePod":
		object = &corev1.Pod{}
	default:
		value := &unstructured.Unstructured{}
		value.SetGroupVersionKind(identity.GVK)
		object = value
	}
	err = r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: identity.Name}, object)
	if apierrors.IsNotFound(err) {
		return nil, identity, nil
	}
	if err != nil {
		return object, identity, err
	}
	if campaign.Status.Chaos != nil {
		if string(object.GetUID()) != campaign.Status.Chaos.UID {
			if terminalPhases[campaign.Status.Phase] {
				// The admitted mutation is absent. A same-named replacement is
				// not owned evidence and must never be adopted or deleted.
				return nil, identity, nil
			}
			return nil, identity, fmt.Errorf("%w: admitted %s UID changed", errMutationIdentityChanged, identity.Kind)
		}
		if !terminalPhases[campaign.Status.Phase] && !expectedPostMutationState(campaign, identity.Kind, object) {
			contract, contractErr := mutationContract(identity.Kind, object)
			if contractErr != nil {
				return nil, identity, contractErr
			}
			digest, digestErr := canonical.ArtifactDigest(contract)
			if digestErr != nil || digest != campaign.Status.Chaos.ResourceDigest {
				return nil, identity, fmt.Errorf("%w: admitted %s execution contract changed", errMutationContractChanged, identity.Kind)
			}
		}
	}
	return object, identity, nil
}

func expectedPostMutationState(campaign *attacknetv1alpha1.FaultCampaign, kind string, object client.Object) bool {
	if kind != "ClockSkewPolicy" || campaign.Status.Phase != "Recovering" || campaign.Status.Cleanup == nil || campaign.Status.Cleanup.Method != "ClockPolicyReset" {
		return false
	}
	policy, ok := object.(*corev1.ConfigMap)
	return ok && clockPolicyMatches(policy, campaign, clockPolicyZero)
}

func (r *Reconciler) removeMutation(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) (*attacknetv1alpha1.CleanupEvidence, error) {
	now := metav1.NewTime(r.now())
	if campaign.Status.Chaos == nil {
		return &attacknetv1alpha1.CleanupEvidence{Absent: true, AllRecovered: true, Method: "Normal", ObservedAt: now}, nil
	}
	object, identity, err := r.getMutation(ctx, campaign)
	if err != nil {
		return nil, err
	}
	if object == nil {
		return &attacknetv1alpha1.CleanupEvidence{Absent: true, AllRecovered: true, Method: "Normal", ObservedAt: now}, nil
	}
	if identity.Kind == "ClockSkewPolicy" {
		policy := object.(*corev1.ConfigMap)
		base := policy.DeepCopy()
		selected := set(campaignTargetNames(campaign))
		for actor := range policy.Data {
			if selected[actor] {
				policy.Data[actor] = clockPolicyZero
			}
		}
		if err := r.Patch(ctx, policy, client.MergeFrom(base)); err != nil {
			return nil, err
		}
		return &attacknetv1alpha1.CleanupEvidence{Absent: clockPolicyMatches(policy, campaign, clockPolicyZero), AllRecovered: clockPolicyMatches(policy, campaign, clockPolicyZero), Method: "ClockPolicyReset", ObservedAt: now}, nil
	}
	owner := metav1.GetControllerOf(object)
	if owner == nil || owner.UID != campaign.UID {
		return nil, fmt.Errorf("refusing to delete unowned %s/%s", identity.Kind, identity.Name)
	}
	if object.GetDeletionTimestamp() == nil {
		if err := r.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		}
	}
	method := "Normal"
	if chaos, ok := object.(*unstructured.Unstructured); ok && zeroInjectionFinalizerAbortSafe(campaign, chaos, r.now()) {
		finalizers := slices.DeleteFunc(append([]string(nil), chaos.GetFinalizers()...), func(value string) bool { return value == "chaos-mesh/records" })
		if len(finalizers) != len(chaos.GetFinalizers()) {
			base := chaos.DeepCopy()
			chaos.SetFinalizers(finalizers)
			if err := r.Patch(ctx, chaos, client.MergeFrom(base)); err != nil {
				return nil, err
			}
			method = "ZeroInjectionFinalizerAbort"
		}
	}
	return &attacknetv1alpha1.CleanupEvidence{Absent: false, AllRecovered: mutationRecovered(object), Method: method, ZeroInjectionProven: method == "ZeroInjectionFinalizerAbort", ObservedAt: now}, nil
}

func (r *Reconciler) holdMutationLease(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, acquire bool) (mutationLeaseState, error) {
	environment := &corev1.ConfigMap{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: environmentLease}, environment); err != nil {
		if apierrors.IsNotFound(err) {
			return mutationLeaseState{EnvironmentMessage: fmt.Sprintf("no active environment lease exists for network %s", campaign.Spec.NetworkRef)}, nil
		}
		return mutationLeaseState{}, err
	}
	if environment.Data["network"] != campaign.Spec.NetworkRef {
		return mutationLeaseState{EnvironmentMessage: fmt.Sprintf("active environment lease belongs to network %s, not %s", environment.Data["network"], campaign.Spec.NetworkRef)}, nil
	}
	state := mutationLeaseState{EnvironmentReady: true}
	lease := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: campaign.Namespace, Name: mutationLease}
	err := r.APIReader.Get(ctx, key, lease)
	if apierrors.IsNotFound(err) && acquire {
		lease = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: mutationLease, Namespace: campaign.Namespace}, Data: map[string]string{"network": campaign.Spec.NetworkRef, "owner": "faultcampaign:" + string(campaign.UID), "purpose": "faultcampaign:" + campaign.Name, "token": string(campaign.UID), "acquiredAt": r.now().Format(time.RFC3339)}}
		err = r.Create(ctx, lease)
		if apierrors.IsAlreadyExists(err) {
			err = r.APIReader.Get(ctx, key, lease)
		}
	}
	if apierrors.IsNotFound(err) && !acquire {
		return state, nil
	}
	if err != nil {
		return mutationLeaseState{}, err
	}
	state.Held = lease.Data["network"] == campaign.Spec.NetworkRef && lease.Data["owner"] == "faultcampaign:"+string(campaign.UID) && lease.Data["token"] == string(campaign.UID)
	return state, nil
}
func (r *Reconciler) releaseMutationLease(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) error {
	lease := &corev1.ConfigMap{}
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: mutationLease}, lease)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if lease.Data["owner"] != "faultcampaign:"+string(campaign.UID) || lease.Data["token"] != string(campaign.UID) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, lease))
}

func (r *Reconciler) captureProbePhase(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, targets []attacknetv1alpha1.ResolvedTarget, compiled Compiled, phase string, injected bool) ([]byte, error) {
	probe := r.Probes
	if probe == nil {
		probe = HTTPProbeClient{}
	}
	observations := []any{}
	kind := kindByType[campaign.Spec.Fault.Type]
	probeKind := probeKindForMutation(kind)
	for _, target := range targets {
		request, err := probeRequest(kind, campaign, target, network, compiled)
		if err != nil {
			observations = append(observations, probeErrorObservation(target.Actor, probeKind, err))
			continue
		}
		response, err := probe.Probe(ctx, target, request)
		if err != nil {
			observations = append(observations, probeErrorObservation(target.Actor, probeKind, err))
			continue
		}
		observation, ok := response["observation"].(map[string]any)
		if !ok {
			observations = append(observations, probeErrorObservation(target.Actor, probeKind, errors.New("probe response omitted its observation object")))
			continue
		}
		observations = append(observations, observation)
	}
	if kind == "TimeChaos" || kind == "ClockSkewPolicy" {
		control, err := controlTarget(network, targets, pods)
		if err != nil {
			observations = append(observations, probeErrorObservation("clock-control", probeKind, err))
		} else {
			response, probeErr := probe.Probe(ctx, control, map[string]any{"kind": "processClock", "peer": control.Actor, "port": "metrics", "metric": "stacks_node_process_wall_clock_seconds", "control": true})
			if probeErr != nil {
				observations = append(observations, probeErrorObservation(control.Actor, probeKind, probeErr))
			} else if observation, ok := response["observation"].(map[string]any); ok {
				observations = append(observations, observation)
			} else {
				observations = append(observations, probeErrorObservation(control.Actor, probeKind, errors.New("control probe response omitted its observation object")))
			}
		}
	}
	authority := "active-probe"
	if kind == "TimeChaos" || kind == "ClockSkewPolicy" {
		authority = "application-process-metric"
	}
	injectionAuthority := "chaos-mesh-status"
	if kind == "IOPressurePod" {
		injectionAuthority = "kubernetes-pod-status"
	} else if kind == "ClockSkewPolicy" {
		injectionAuthority = "controller-clock-policy"
	}
	source := map[string]any{"trust": "orchestrator-observed", "authority": authority, "collector": "attacknet-probe/v1"}
	if authority == "application-process-metric" {
		source["contentTrust"] = "actor-self-reported"
	}
	return json.Marshal(map[string]any{
		"schemaVersion": "stacks-attacknet-fault-probe/v1",
		"phase":         phase,
		"capturedAt":    r.now(),
		"source":        source,
		"injection": map[string]any{
			"allInjectedObserved": injected,
			"source": map[string]any{
				"trust": "orchestrator-observed", "authority": injectionAuthority,
				"collector": "attacknet-run-operator/v1",
			},
		},
		"observations": observations,
	})
}

func probeKindForMutation(kind string) string {
	switch kind {
	case "NetworkChaos":
		return "network"
	case "DNSChaos":
		return "dns"
	case "IOChaos", "IOPressurePod":
		return "io"
	case "TimeChaos", "ClockSkewPolicy":
		return "clock"
	default:
		return "unknown"
	}
}

func probeErrorObservation(actor, probe string, err error) map[string]any {
	return map[string]any{"actor": actor, "probe": probe, "status": "error", "error": truncate(err.Error(), 4096)}
}

func baselineUsable(kind string, encoded []byte, selectedActors []string) bool {
	selected := set(selectedActors)
	phase, err := decodeProbePhase(string(encoded), "before", kind, selected)
	if err != nil {
		return false
	}
	observed := map[string]map[string]any{}
	for _, observation := range phase.Observations {
		actor := text(observation["actor"])
		if selected[actor] {
			if observed[actor] != nil {
				return false
			}
			observed[actor] = observation
		}
	}
	if len(observed) != len(selected) {
		return false
	}
	for _, observation := range observed {
		if observation["status"] != "ok" {
			return false
		}
		switch kind {
		case "NetworkChaos", "IOChaos", "IOPressurePod":
			if number(observation["successes"]) <= 0 {
				return false
			}
		case "DNSChaos":
			if !boolean(observation["querySucceeded"]) || !boolean(observation["controlSucceeded"]) {
				return false
			}
		}
	}
	if kind == "TimeChaos" || kind == "ClockSkewPolicy" {
		for _, observation := range phase.Observations {
			if observation["status"] == "ok" && boolean(observation["control"]) && !selected[text(observation["actor"])] {
				return true
			}
		}
		return false
	}
	return true
}

func (r *Reconciler) buildIOPressurePod(campaign *attacknetv1alpha1.FaultCampaign, pods []corev1.Pod, compiled Compiled) (*corev1.Pod, error) {
	if r.IOPressureImage == "" {
		return nil, errors.New("trusted I/O-pressure image is not configured")
	}
	if len(campaign.Status.ResolvedTargets) != 1 {
		return nil, errors.New("disk-pressure requires exactly one admitted target")
	}
	target := campaign.Status.ResolvedTargets[0]
	var source *corev1.Pod
	for index := range pods {
		if string(pods[index].UID) == target.PodUID {
			source = &pods[index]
		}
	}
	if source == nil || source.Spec.NodeName != target.Node {
		return nil, errors.New("exact admitted disk-pressure target changed")
	}
	claim := ""
	for _, container := range source.Spec.Containers {
		if container.Name != "actor" {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/data" {
				continue
			}
			for _, volume := range source.Spec.Volumes {
				if volume.Name == mount.Name && volume.PersistentVolumeClaim != nil {
					claim = volume.PersistentVolumeClaim.ClaimName
				}
			}
		}
	}
	if claim == "" {
		return nil, errors.New("admitted actor has no persistent /data claim")
	}
	workers := parameterNumber(compiled.Evidence.Parameters, "workers")
	bytesMiB := parameterNumber(compiled.Evidence.Parameters, "bytesMiB")
	writeKiB := parameterNumber(compiled.Evidence.Parameters, "writeSizeKiB")
	duration, _ := time.ParseDuration(campaign.Spec.Fault.Duration)
	runAs := int64(65532)
	grace := int64(10)
	readOnly := true
	allow := false
	nonRoot := true
	seccomp := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	fsGroup := runAs
	if source.Spec.SecurityContext != nil && source.Spec.SecurityContext.FSGroup != nil {
		fsGroup = *source.Spec.SecurityContext.FSGroup
	}
	if fsGroup <= 0 {
		return nil, errors.New("target Pod fsGroup must be a positive non-root integer")
	}
	pull := r.IOPressurePull
	if pull == "" {
		pull = corev1.PullIfNotPresent
	}
	contractJSON, err := json.Marshal(compiled.Evidence.IOPressure)
	if err != nil {
		return nil, err
	}
	fsPolicy := corev1.FSGroupChangeOnRootMismatch
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: stableFaultName("io-pressure", campaign.Name), Namespace: campaign.Namespace, Labels: map[string]string{NetworkLabel: campaign.Spec.NetworkRef, "testing.stacks.org/campaign": campaign.Name, "testing.stacks.org/mechanism": "controller-owned-io-pressure-pod"}, Annotations: map[string]string{"testing.stacks.org/io-pressure-contract": string(contractJSON), "testing.stacks.org/target-pod-uid": target.PodUID, "testing.stacks.org/target-pvc": claim}, OwnerReferences: []metav1.OwnerReference{ownership.Reference(campaign, attacknetv1alpha1.GroupVersion.WithKind("FaultCampaign"))}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: ptr(false), RestartPolicy: corev1.RestartPolicyNever, TerminationGracePeriodSeconds: &grace, NodeName: target.Node, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonRoot, FSGroup: &fsGroup, FSGroupChangePolicy: &fsPolicy, SeccompProfile: seccomp}, Containers: []corev1.Container{{Name: "io-pressure", Image: r.IOPressureImage, ImagePullPolicy: pull, Args: []string{"--duration-seconds", fmt.Sprint(int64(duration.Seconds())), "--workers", fmt.Sprint(workers), "--bytes-mib", fmt.Sprint(bytesMiB), "--write-size-kib", fmt.Sprint(writeKiB), "--scratch-path", "/data/.attacknet-io-pressure-" + string(campaign.UID)}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &allow, ReadOnlyRootFilesystem: &readOnly, RunAsNonRoot: &nonRoot, RunAsUser: &runAs, RunAsGroup: &runAs, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: seccomp}, Resources: ioPressureResources(fmt.Sprint(compiled.Evidence.IOPressure["severity"])), VolumeMounts: []corev1.VolumeMount{{Name: "actor-data", MountPath: "/data"}}}}, Volumes: []corev1.Volume{{Name: "actor-data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}}}}
	return pod, nil
}

func ioPressureResources(severity string) corev1.ResourceRequirements {
	values := map[string][4]string{
		"low":    {"25m", "24Mi", "250m", "64Mi"},
		"medium": {"50m", "24Mi", "500m", "64Mi"},
		"high":   {"100m", "24Mi", "1", "96Mi"},
	}[severity]
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(values[0]), corev1.ResourceMemory: resource.MustParse(values[1])},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(values[2]), corev1.ResourceMemory: resource.MustParse(values[3])},
	}
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

func applyCanonicalWeights(manifest Manifest, weights map[string]float64) Manifest {
	manifest.Actors = append([]ManifestActor(nil), manifest.Actors...)
	for index := range manifest.Actors {
		if weight, ok := weights[manifest.Actors[index].Name]; ok {
			manifest.Actors[index].SignerWeight = ptr(weight)
		}
	}
	return manifest
}
func rawJSON(value any) (apixv1.JSON, error) {
	encoded, err := json.Marshal(value)
	return apixv1.JSON{Raw: encoded}, err
}
func conditionTrue(resource *unstructured.Unstructured, kind string) bool {
	conditions, _, _ := unstructured.NestedSlice(resource.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if condition["type"] == kind && condition["status"] == "True" {
			return true
		}
	}
	return false
}
func mutationRecovered(object client.Object) bool {
	if chaos, ok := object.(*unstructured.Unstructured); ok {
		return conditionTrue(chaos, "AllRecovered")
	}
	if pod, ok := object.(*corev1.Pod); ok {
		return pod.Status.Phase == corev1.PodSucceeded
	}
	return true
}

func zeroInjectionFinalizerAbortSafe(campaign *attacknetv1alpha1.FaultCampaign, resource *unstructured.Unstructured, now time.Time) bool {
	if campaign.Spec.Fault.Type != "io" || campaign.Status.Phase != "Failed" ||
		(campaign.Status.Reason != "InjectionFailed" && campaign.Status.Reason != "InjectionTimeout") ||
		conditionTrue(resource, "AllInjected") || resource.GetDeletionTimestamp() == nil ||
		now.Sub(resource.GetDeletionTimestamp().Time) < 30*time.Second {
		return false
	}
	parameters := parameterMap(campaign.Spec.Fault.Parameters.Raw)
	containerValues, ok := parameters["containerNames"].([]any)
	if !ok || len(containerValues) == 0 || len(campaign.Status.ResolvedTargets) == 0 {
		return false
	}
	containers := make([]string, 0, len(containerValues))
	for _, raw := range containerValues {
		value, ok := raw.(string)
		if !ok || value == "" {
			return false
		}
		containers = append(containers, value)
	}
	records, found, err := unstructured.NestedSlice(resource.Object, "status", "experiment", "containerRecords")
	if err != nil || !found {
		return false
	}
	expected := map[string]bool{}
	for _, target := range campaign.Status.ResolvedTargets {
		for _, container := range containers {
			expected[fmt.Sprintf("%s/%s/%s", campaign.Namespace, target.Pod, container)] = true
		}
	}
	if len(records) != len(expected) {
		return false
	}
	for _, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok || !expected[fmt.Sprint(record["id"])] || numberField(record["injectedCount"]) != 0 || numberField(record["recoveredCount"]) != 0 || record["phase"] != "Not Injected/Wait" {
			return false
		}
		failedApply, succeeded := false, false
		events, _ := record["events"].([]any)
		for _, eventRaw := range events {
			event, _ := eventRaw.(map[string]any)
			failedApply = failedApply || (event["type"] == "Failed" && event["operation"] == "Apply")
			succeeded = succeeded || event["type"] == "Succeeded"
		}
		if !failedApply || succeeded {
			return false
		}
		delete(expected, fmt.Sprint(record["id"]))
	}
	return len(expected) == 0
}

func numberField(value any) float64 {
	switch typed := value.(type) {
	case int64:
		return float64(typed)
	case float64:
		return typed
	case json.Number:
		result, _ := typed.Float64()
		return result
	default:
		return -1
	}
}
func clockPolicyMatches(policy *corev1.ConfigMap, campaign *attacknetv1alpha1.FaultCampaign, expected string) bool {
	if policy.Labels[NetworkLabel] != campaign.Spec.NetworkRef || policy.Labels["testing.stacks.org/clock-policy"] != "true" {
		return false
	}
	selected := set(campaignTargetNames(campaign))
	if len(selected) == 0 {
		return false
	}
	for actor, value := range policy.Data {
		wanted := clockPolicyZero
		if selected[actor] {
			wanted = expected
		}
		if value != wanted {
			return false
		}
	}
	return true
}
func campaignTargetNames(campaign *attacknetv1alpha1.FaultCampaign) []string {
	result := make([]string, len(campaign.Status.ResolvedTargets))
	for index, target := range campaign.Status.ResolvedTargets {
		result[index] = target.Actor
	}
	return result
}
func parameterString(raw []byte, name string) string {
	values := map[string]any{}
	_ = json.Unmarshal(raw, &values)
	value, _ := values[name].(string)
	return strings.TrimSuffix(value, "\n")
}
func parameterNumber(values map[string]any, name string) int64 {
	switch value := values[name].(type) {
	case float64:
		return int64(value)
	case json.Number:
		number, _ := value.Int64()
		return number
	default:
		return 0
	}
}
func mutationContract(kind string, object client.Object) (any, error) {
	switch value := object.(type) {
	case *unstructured.Unstructured:
		spec, found, err := unstructured.NestedFieldCopy(value.Object, "spec")
		if err != nil || !found {
			return nil, fmt.Errorf("%s lacks a readable spec", kind)
		}
		normalizeMutationSpec(kind, spec)
		return map[string]any{"apiVersion": value.GetAPIVersion(), "kind": value.GetKind(), "name": value.GetName(), "namespace": value.GetNamespace(), "labels": value.GetLabels(), "ownerUID": controllerOwnerUID(value), "spec": spec}, nil
	case *corev1.ConfigMap:
		return map[string]any{"uid": value.UID, "name": value.Name, "namespace": value.Namespace, "labels": value.Labels, "data": value.Data}, nil
	case *corev1.Pod:
		return ioPressurePodContract(value), nil
	default:
		return nil, fmt.Errorf("unsupported mutation contract object %T", object)
	}
}

// normalizeMutationSpec removes only API-documented, default-equivalent
// serialization differences introduced by the external chaos controller.
func normalizeMutationSpec(kind string, spec any) {
	values, ok := spec.(map[string]any)
	if !ok {
		return
	}
	if kind == "PodChaos" && zeroJSONNumber(values["gracePeriod"]) {
		delete(values, "gracePeriod")
	}
}

func zeroJSONNumber(value any) bool {
	switch number := value.(type) {
	case int:
		return number == 0
	case int32:
		return number == 0
	case int64:
		return number == 0
	case float64:
		return number == 0
	case json.Number:
		return number.String() == "0"
	default:
		return false
	}
}

func controllerOwnerUID(object client.Object) string {
	owner := metav1.GetControllerOf(object)
	if owner == nil {
		return ""
	}
	return string(owner.UID)
}

func requireCampaignOwner(campaign *attacknetv1alpha1.FaultCampaign, object client.Object) error {
	if controllerOwnerUID(object) != string(campaign.UID) {
		return fmt.Errorf("refusing to adopt %T %s/%s without the campaign controller identity", object, object.GetNamespace(), object.GetName())
	}
	return nil
}

func ioPressurePodContract(pod *corev1.Pod) any {
	var container *corev1.Container
	for index := range pod.Spec.Containers {
		if pod.Spec.Containers[index].Name == "io-pressure" {
			container = &pod.Spec.Containers[index]
			break
		}
	}
	claim := ""
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == "actor-data" && volume.PersistentVolumeClaim != nil {
			claim = volume.PersistentVolumeClaim.ClaimName
		}
	}
	containerContract := any(nil)
	if container != nil {
		containerContract = map[string]any{"image": container.Image, "imagePullPolicy": container.ImagePullPolicy, "command": container.Command, "args": container.Args, "securityContext": container.SecurityContext, "resources": container.Resources, "volumeMounts": container.VolumeMounts}
	}
	return map[string]any{
		"ownerUID":    controllerOwnerUID(pod),
		"labels":      map[string]string{"network": pod.Labels[NetworkLabel], "campaign": pod.Labels["testing.stacks.org/campaign"], "mechanism": pod.Labels["testing.stacks.org/mechanism"]},
		"annotations": map[string]string{"contract": pod.Annotations["testing.stacks.org/io-pressure-contract"], "targetPodUID": pod.Annotations["testing.stacks.org/target-pod-uid"], "targetPVC": pod.Annotations["testing.stacks.org/target-pvc"]},
		"pod":         map[string]any{"automountServiceAccountToken": pod.Spec.AutomountServiceAccountToken, "restartPolicy": pod.Spec.RestartPolicy, "terminationGracePeriodSeconds": pod.Spec.TerminationGracePeriodSeconds, "nodeName": pod.Spec.NodeName, "securityContext": pod.Spec.SecurityContext},
		"container":   containerContract, "volume": claim, "containerCount": len(pod.Spec.Containers), "volumeCount": len(pod.Spec.Volumes),
	}
}

func mutationDesiredMatches(kind string, desired, observed client.Object) bool {
	if desired.GetName() != observed.GetName() || desired.GetNamespace() != observed.GetNamespace() {
		return false
	}
	if kind == "IOPressurePod" {
		return reflect.DeepEqual(ioPressurePodContract(desired.(*corev1.Pod)), ioPressurePodContract(observed.(*corev1.Pod)))
	}
	if kind == "ClockSkewPolicy" {
		return reflect.DeepEqual(desired.(*corev1.ConfigMap).Data, observed.(*corev1.ConfigMap).Data)
	}
	wanted, wantedFound, wantedErr := unstructured.NestedFieldCopy(desired.(*unstructured.Unstructured).Object, "spec")
	current, currentFound, currentErr := unstructured.NestedFieldCopy(observed.(*unstructured.Unstructured).Object, "spec")
	if wantedErr != nil || currentErr != nil || !wantedFound || !currentFound || !apiequality.Semantic.DeepDerivative(wanted, current) {
		return false
	}
	for key, value := range desired.GetLabels() {
		if observed.GetLabels()[key] != value {
			return false
		}
	}
	return true
}
func containerRunning(pod *corev1.Pod, name string) bool {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == name && status.State.Running != nil && status.ImageID != "" {
			return true
		}
	}
	return false
}
func elapsed(timestamp *metav1.Time, now time.Time) time.Duration {
	if timestamp == nil {
		return 0
	}
	return now.Sub(timestamp.Time)
}

func assertionTimeout(assertions []attacknetv1alpha1.CampaignAssertion, fallback time.Duration) time.Duration {
	result := time.Duration(0)
	for _, assertion := range assertions {
		if assertion.TimeoutSeconds > 0 && time.Duration(assertion.TimeoutSeconds)*time.Second > result {
			result = time.Duration(assertion.TimeoutSeconds) * time.Second
		}
	}
	if result == 0 {
		return fallback
	}
	return result
}
func injectionReason(kind string) string {
	if kind == "ClockSkewPolicy" {
		return "ClockPolicyApplied"
	}
	if kind == "IOPressurePod" {
		return "PressurePodCreated"
	}
	return "ChaosResourceCreated"
}
func podEffectResults(campaign *attacknetv1alpha1.FaultCampaign, pods []corev1.Pod, observedAt time.Time) []apixv1.JSON {
	assertion := map[string]string{"pod-kill": "PodRestarted", "pod-failure": "PodUnavailable", "container-kill": "ContainerRestarted"}[campaign.Spec.Fault.Action]
	results := make([]apixv1.JSON, 0, len(campaign.Status.ResolvedTargets))
	for _, target := range campaign.Status.ResolvedTargets {
		var same *corev1.Pod
		for index := range pods {
			pod := &pods[index]
			if pod.DeletionTimestamp == nil && pod.Labels[NetworkLabel] == campaign.Spec.NetworkRef && pod.Labels[ActorLabel] == target.Actor && string(pod.UID) == target.PodUID {
				same = pod
				break
			}
		}
		outcome, message := "Failed", "admitted Pod state did not exhibit the requested effect"
		switch campaign.Spec.Fault.Action {
		case "pod-kill":
			if same == nil {
				outcome, message = "Proven", "the admitted Pod UID disappeared after injection"
			}
		case "pod-failure":
			if same == nil {
				outcome, message = "Inconclusive", "the admitted Pod disappeared instead of exhibiting pod-failure state"
			} else if !podIsReady(*same) {
				outcome, message = "Proven", "the admitted Pod became unavailable after injection"
			}
		case "container-kill":
			if same == nil {
				outcome, message = "Inconclusive", "the admitted Pod UID changed, so a container restart cannot be attributed"
			} else if actorRestartCount(*same) > target.RestartCount {
				outcome, message = "Proven", "the actor container restart count increased after injection"
			}
		}
		value, _ := rawJSON(map[string]any{"assertion": assertion, "outcome": outcome, "actor": target.Actor, "podUid": target.PodUID, "observedAt": observedAt, "message": message})
		results = append(results, value)
	}
	return results
}

func actorRestartCount(pod corev1.Pod) int32 {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "actor" {
			return status.RestartCount
		}
	}
	return -1
}

func provenResults(results []apixv1.JSON) int {
	count := 0
	for _, raw := range results {
		value := map[string]any{}
		if json.Unmarshal(raw.Raw, &value) == nil && value["outcome"] == "Proven" {
			count++
		}
	}
	return count
}

func minimumAffected(spec attacknetv1alpha1.FaultSpec, candidates int) int {
	value := 0
	if spec.Value != nil {
		value, _ = strconv.Atoi(spec.Value.String())
	}
	switch spec.Mode {
	case "all":
		return candidates
	case "fixed":
		return value
	case "fixed-percent":
		return int(math.Ceil(float64(candidates) * float64(value) / 100))
	default:
		return 1
	}
}

func evaluationResults(campaign *attacknetv1alpha1.FaultCampaign, report effectReport, observedAt time.Time) ([]apixv1.JSON, []apixv1.JSON) {
	effectAssertion := map[string]string{
		"network": "NetworkDegraded", "dns": "DNSDegraded", "io": "IODegraded",
		"io-pressure": "IOPressureObserved", "time": "ClockSkewObserved", "clock-skew": "ClockSkewObserved",
	}[campaign.Spec.Fault.Type]
	recoveryAssertion := map[string]string{
		"network": "NetworkRecovered", "dns": "DNSRecovered", "io": "IORecovered",
		"io-pressure": "IOPressureRecovered", "time": "ClockSkewCleared", "clock-skew": "ClockSkewCleared",
	}[campaign.Spec.Fault.Type]
	targets := map[string]string{}
	for _, target := range campaign.Status.ResolvedTargets {
		targets[target.Actor] = target.PodUID
	}
	effects, recoveries := make([]apixv1.JSON, 0, len(report.Evaluations)), make([]apixv1.JSON, 0, len(report.Evaluations))
	for _, evaluation := range report.Evaluations {
		effect, _ := rawJSON(map[string]any{"assertion": effectAssertion, "outcome": title(evaluation.Effect), "actor": evaluation.Actor, "podUid": targets[evaluation.Actor], "observedAt": observedAt, "message": evaluation.Reason})
		recoveryMessage := evaluation.RecoveryReason
		if recoveryMessage == "" {
			recoveryMessage = "trusted after-fault probe classified recovery=" + evaluation.Recovery
		}
		recovery, _ := rawJSON(map[string]any{"assertion": recoveryAssertion, "outcome": title(evaluation.Recovery), "actor": evaluation.Actor, "podUid": targets[evaluation.Actor], "observedAt": observedAt, "message": recoveryMessage})
		effects, recoveries = append(effects, effect), append(recoveries, recovery)
	}
	return effects, recoveries
}

func assertionsSatisfied(required []attacknetv1alpha1.CampaignAssertion, results []apixv1.JSON) bool {
	if len(required) == 0 {
		return true
	}
	for _, assertion := range required {
		matched := false
		for _, raw := range results {
			value := map[string]any{}
			if json.Unmarshal(raw.Raw, &value) == nil && value["outcome"] == "Proven" && value["assertion"] == assertion.Type && (assertion.Actor == "" || value["actor"] == assertion.Actor) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func title(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
func stableFaultName(parts ...string) string {
	candidate := strings.Join(parts, "-")
	if len(candidate) <= 63 {
		return candidate
	}
	digest, _ := canonical.ArtifactDigest(candidate)
	return strings.TrimRight(candidate[:52], "-") + "-" + strings.TrimPrefix(digest, "sha256:")[:10]
}
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
func ptr[T any](value T) *T { return &value }
func ternary[T any](condition bool, yes, no T) T {
	if condition {
		return yes
	}
	return no
}

// SetupWithManager registers campaign, topology, Pod, ConfigMap, and Chaos Mesh watches.
func (r *Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if r.APIReader == nil {
		return errors.New("FaultCampaign reconciler requires an uncached Kubernetes API reader")
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &attacknetv1alpha1.FaultCampaign{}, "spec.networkRef", func(object client.Object) []string {
		return []string{object.(*attacknetv1alpha1.FaultCampaign).Spec.NetworkRef}
	}); err != nil {
		return fmt.Errorf("index FaultCampaign networkRef: %w", err)
	}
	mapNetwork := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
		campaigns := &attacknetv1alpha1.FaultCampaignList{}
		if err := r.List(ctx, campaigns, client.InNamespace(object.GetNamespace()), client.MatchingFields{"spec.networkRef": object.GetName()}); err != nil {
			return nil
		}
		requests := make([]reconcile.Request, len(campaigns.Items))
		for index := range campaigns.Items {
			requests[index] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&campaigns.Items[index])}
		}
		return requests
	})
	mapLabels := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, object client.Object) []reconcile.Request {
		name := object.GetLabels()["testing.stacks.org/campaign"]
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
	})
	b := builder.ControllerManagedBy(mgr).For(&attacknetv1alpha1.FaultCampaign{}).Owns(&corev1.Pod{}).Watches(&attacknetv1alpha1.StacksNetwork{}, mapNetwork).Watches(&corev1.Pod{}, mapLabels).Watches(&corev1.ConfigMap{}, mapLabels).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent})
	for _, kind := range []string{"PodChaos", "NetworkChaos", "DNSChaos", "IOChaos", "TimeChaos"} {
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: kind})
		b = b.Watches(object, mapLabels)
	}
	return b.Complete(r)
}
