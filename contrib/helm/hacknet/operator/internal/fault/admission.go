package fault

import (
	"context"
	"errors"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
)

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
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	if definition.EffectKind != "pod" {
		before, err := r.captureProbePhase(ctx, campaign, network, pods, targets, compiled, "before", false)
		if err != nil {
			return reconcile.Result{}, r.fail(ctx, campaign, "ProbeBaselineUnavailable", err)
		}
		probeArtifacts["beforeJson"] = string(before)
		if !baselineUsable(definition.MutationKind, before, compiled.Evidence.SelectedActors) {
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

func applyCanonicalWeights(manifest Manifest, weights map[string]float64) Manifest {
	manifest.Actors = append([]ManifestActor(nil), manifest.Actors...)
	for index := range manifest.Actors {
		if weight, ok := weights[manifest.Actors[index].Name]; ok {
			manifest.Actors[index].SignerWeight = ptr(weight)
		}
	}
	return manifest
}
