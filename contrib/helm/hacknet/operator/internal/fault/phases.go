package fault

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

func (r *Reconciler) inject(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, compiled Compiled) error {
	identity, err := mutationFor(campaign)
	if err != nil {
		return err
	}
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	var object client.Object
	switch definition.Backend {
	case clockPolicyBackend:
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
	case ioPressureBackend:
		pod, err := r.buildIOPressurePod(campaign, pods, compiled)
		if err != nil {
			return r.fail(ctx, campaign, "FaultCapabilityUnavailable", err)
		}
		object = pod
		if err := r.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	case chaosMeshBackend:
		resource := compiled.Resource.DeepCopy()
		resource.SetOwnerReferences([]metav1.OwnerReference{ownership.Reference(campaign, attacknetv1alpha1.GroupVersion.WithKind("FaultCampaign"))})
		object = resource
		if err := r.Create(ctx, resource); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	default:
		return fmt.Errorf("unsupported mutation backend %s", definition.Backend)
	}
	desiredObject := object.DeepCopyObject().(client.Object)
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: identity.Name}, object); err != nil {
		return err
	}
	if definition.Backend != clockPolicyBackend {
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
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
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
	if definition.EffectKind == "pod" {
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
	if definition.EffectKind != "pod" {
		during, probeErr := r.captureProbePhase(ctx, campaign, network, pods, campaign.Status.ResolvedTargets, compiled, "during", true)
		if probeErr != nil {
			return probeErr
		}
		if next.ProbeArtifacts == nil {
			next.ProbeArtifacts = map[string]string{}
		}
		next.ProbeArtifacts["duringJson"] = string(during)
		if definition.Backend == clockPolicyBackend {
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
	if definition.EffectKind != "pod" {
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
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	object, _, err := r.getMutation(ctx, campaign)
	if err != nil {
		return err
	}
	if definition.EffectKind == "pod" && (campaign.Spec.Fault.Action == "pod-kill" || campaign.Spec.Fault.Action == "container-kill") && campaign.Status.ActualInjection != nil {
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
	if definition.Backend == clockPolicyBackend {
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
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	object, _, err := r.getMutation(ctx, campaign)
	if err != nil {
		return err
	}
	if object != nil && definition.Backend != clockPolicyBackend {
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
	if definition.EffectKind == "pod" {
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
	if definition.EffectKind == "pod" {
		recoveries := []apixv1.JSON{}
		for _, target := range targets {
			recovery, _ := rawJSON(map[string]any{"assertion": "TargetReady", "outcome": "Proven", "actor": target.Actor, "podUid": target.PodUID, "observedAt": r.now()})
			recoveries = append(recoveries, recovery)
		}
		next.RecoveryResults = recoveries
	}
	effectProven = effectProven && assertionsSatisfied(campaign.Spec.EffectAssertions, next.EffectResults)
	recoveryProven = recoveryProven && assertionsSatisfied(campaign.Spec.RecoveryAssertions, next.RecoveryResults)
	if (effectProven || definition.Backend == clockPolicyBackend) && !recoveryProven && elapsed(next.Cleanup.ObservedAt.DeepCopy(), r.now()) <= assertionTimeout(campaign.Spec.RecoveryAssertions, 300*time.Second) {
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
