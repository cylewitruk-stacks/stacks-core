package fault

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func mutationFor(campaign *attacknetv1alpha1.FaultCampaign) (mutationIdentity, error) {
	definition, err := mechanismForType(campaign.Spec.Fault.Type)
	if err != nil {
		return mutationIdentity{}, err
	}
	kind := definition.MutationKind
	switch definition.Backend {
	case ioPressureBackend:
		return mutationIdentity{Kind: kind, Name: stableFaultName("io-pressure", campaign.Name), GVK: corev1.SchemeGroupVersion.WithKind("Pod")}, nil
	case clockPolicyBackend:
		return mutationIdentity{Kind: kind, Name: campaign.Spec.NetworkRef + "-clock-policy", GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap")}, nil
	case chaosMeshBackend:
		return mutationIdentity{Kind: kind, Name: campaign.Name, GVK: schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: kind}}, nil
	default:
		return mutationIdentity{}, fmt.Errorf("unsupported mutation backend %s", definition.Backend)
	}
}

func (r *Reconciler) getMutation(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) (client.Object, mutationIdentity, error) {
	identity, err := mutationFor(campaign)
	if err != nil {
		return nil, identity, err
	}
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	var object client.Object
	switch definition.Backend {
	case clockPolicyBackend:
		object = &corev1.ConfigMap{}
	case ioPressureBackend:
		object = &corev1.Pod{}
	case chaosMeshBackend:
		value := &unstructured.Unstructured{}
		value.SetGroupVersionKind(identity.GVK)
		object = value
	default:
		return nil, identity, fmt.Errorf("unsupported mutation backend %s", definition.Backend)
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
	if mustMechanismForType(campaign.Spec.Fault.Type).Backend == clockPolicyBackend {
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

func injectionReason(kind string) string {
	if kind == "ClockSkewPolicy" {
		return "ClockPolicyApplied"
	}
	if kind == "SignerBehaviorSession" {
		return "BehaviorSessionActivated"
	}
	if kind == "IOPressurePod" {
		return "PressurePodCreated"
	}
	return "ChaosResourceCreated"
}
