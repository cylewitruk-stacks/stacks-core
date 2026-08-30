package topology

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

var runtimeImagePattern = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// Reconciler converges StacksNetwork declarations and publishes admitted identity.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Now    func() time.Time
}

// Reconcile renders, applies, prunes, and observes one StacksNetwork.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	network := &attacknetv1alpha1.StacksNetwork{}
	if err := r.Get(ctx, request.NamespacedName, network); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if !network.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, nil
	}
	resources, err := Render(network, r.Scheme)
	if err == nil {
		err = r.applyAndPrune(ctx, network, resources)
	}
	if err != nil {
		logger.Error(err, "reconciliation failed")
		status := r.degradedStatus(network, err)
		return reconcile.Result{}, r.updateStatus(ctx, network, status)
	}
	status, err := r.buildStatus(ctx, network)
	if err != nil {
		logger.Error(err, "status observation failed")
		status = r.degradedStatus(network, err)
	}
	return reconcile.Result{}, r.updateStatus(ctx, network, status)
}

func (r *Reconciler) applyAndPrune(ctx context.Context, network *attacknetv1alpha1.StacksNetwork, resources ResourceSet) error {
	for _, desired := range resources.Objects() {
		if err := r.apply(ctx, network, desired); err != nil {
			return err
		}
	}
	desired := map[string]map[string]struct{}{"ConfigMap": {}, "Service": {}, "StatefulSet": {}}
	for _, object := range resources.ConfigMaps {
		desired["ConfigMap"][object.Name] = struct{}{}
	}
	for _, object := range resources.Services {
		desired["Service"][object.Name] = struct{}{}
	}
	for _, object := range resources.StatefulSets {
		desired["StatefulSet"][object.Name] = struct{}{}
	}
	selector := client.MatchingLabels{managedByLabel: managedByValue, networkLabel: network.Name}
	lists := []struct {
		kind string
		list client.ObjectList
	}{{"ConfigMap", &corev1.ConfigMapList{}}, {"Service", &corev1.ServiceList{}}, {"StatefulSet", &appsv1.StatefulSetList{}}}
	for _, item := range lists {
		if err := r.List(ctx, item.list, client.InNamespace(network.Namespace), selector); err != nil {
			return fmt.Errorf("list managed %s: %w", item.kind, err)
		}
		var objects []client.Object
		switch list := item.list.(type) {
		case *corev1.ConfigMapList:
			for index := range list.Items {
				objects = append(objects, &list.Items[index])
			}
		case *corev1.ServiceList:
			for index := range list.Items {
				objects = append(objects, &list.Items[index])
			}
		case *appsv1.StatefulSetList:
			for index := range list.Items {
				objects = append(objects, &list.Items[index])
			}
		}
		for _, object := range objects {
			if _, keep := desired[item.kind][object.GetName()]; keep {
				continue
			}
			if err := assertOwned(network, object); err != nil {
				return fmt.Errorf("refuse to prune labelled %s %s: %w", item.kind, object.GetName(), err)
			}
			if err := r.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("prune %s %s: %w", item.kind, object.GetName(), err)
			}
		}
	}
	return nil
}

func (r *Reconciler) apply(ctx context.Context, network *attacknetv1alpha1.StacksNetwork, desired client.Object) error {
	current := desired.DeepCopyObject().(client.Object)
	key := client.ObjectKeyFromObject(desired)
	err := r.Get(ctx, key, current)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create %T %s: %w", desired, key, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get %T %s: %w", desired, key, err)
	}
	if err := assertOwned(network, current); err != nil {
		return err
	}
	before := current.DeepCopyObject().(client.Object)
	if err := mergeManagedObject(current, desired); err != nil {
		return fmt.Errorf("prepare update %T %s: %w", desired, key, err)
	}
	if reflect.DeepEqual(before, current) {
		return nil
	}
	if err := r.Patch(ctx, current, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("update %T %s: %w", desired, key, err)
	}
	return nil
}

func mergeManagedObject(current, desired client.Object) error {
	current.SetLabels(copyStringMap(desired.GetLabels()))
	current.SetAnnotations(copyStringMap(desired.GetAnnotations()))
	current.SetOwnerReferences(append([]metav1.OwnerReference(nil), desired.GetOwnerReferences()...))
	switch existing := current.(type) {
	case *corev1.ConfigMap:
		wanted := desired.(*corev1.ConfigMap)
		existing.Data = copyStringMap(wanted.Data)
		existing.BinaryData = copyByteMap(wanted.BinaryData)
		existing.Immutable = wanted.Immutable
	case *corev1.Service:
		wanted := desired.(*corev1.Service)
		clusterIP := existing.Spec.ClusterIP
		clusterIPs := append([]string(nil), existing.Spec.ClusterIPs...)
		ipFamilies := append([]corev1.IPFamily(nil), existing.Spec.IPFamilies...)
		ipFamilyPolicy := existing.Spec.IPFamilyPolicy
		healthCheckNodePort := existing.Spec.HealthCheckNodePort
		existing.Spec = *wanted.Spec.DeepCopy()
		existing.Spec.ClusterIP = clusterIP
		existing.Spec.ClusterIPs = clusterIPs
		existing.Spec.IPFamilies = ipFamilies
		existing.Spec.IPFamilyPolicy = ipFamilyPolicy
		existing.Spec.HealthCheckNodePort = healthCheckNodePort
	case *appsv1.StatefulSet:
		wanted := desired.(*appsv1.StatefulSet)
		if err := validateStatefulSetImmutableFields(existing, wanted); err != nil {
			return err
		}
		existing.Spec.Replicas = wanted.Spec.Replicas
		existing.Spec.Ordinals = wanted.Spec.Ordinals
		existing.Spec.Template = *wanted.Spec.Template.DeepCopy()
		existing.Spec.UpdateStrategy = wanted.Spec.UpdateStrategy
		existing.Spec.RevisionHistoryLimit = wanted.Spec.RevisionHistoryLimit
		existing.Spec.PersistentVolumeClaimRetentionPolicy = wanted.Spec.PersistentVolumeClaimRetentionPolicy
		existing.Spec.MinReadySeconds = wanted.Spec.MinReadySeconds
	default:
		return fmt.Errorf("unsupported managed object type %T", current)
	}
	return nil
}

func validateStatefulSetImmutableFields(current, desired *appsv1.StatefulSet) error {
	if current.Spec.ServiceName != desired.Spec.ServiceName ||
		current.Spec.PodManagementPolicy != desired.Spec.PodManagementPolicy ||
		!apiequality.Semantic.DeepEqual(current.Spec.Selector, desired.Spec.Selector) {
		return errors.New("StatefulSet service, pod-management, or selector identity is immutable; recreate the StacksNetwork")
	}
	if len(current.Spec.VolumeClaimTemplates) != len(desired.Spec.VolumeClaimTemplates) {
		return errors.New("StatefulSet volume claim templates are immutable; recreate the StacksNetwork for storage changes")
	}
	for index := range desired.Spec.VolumeClaimTemplates {
		currentClaim := &current.Spec.VolumeClaimTemplates[index]
		desiredClaim := &desired.Spec.VolumeClaimTemplates[index]
		if currentClaim.Name != desiredClaim.Name || !apiequality.Semantic.DeepDerivative(&desiredClaim.Spec, &currentClaim.Spec) {
			return errors.New("StatefulSet volume claim templates are immutable; recreate the StacksNetwork for storage changes")
		}
	}
	return nil
}

func copyStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func copyByteMap(source map[string][]byte) map[string][]byte {
	if source == nil {
		return nil
	}
	result := make(map[string][]byte, len(source))
	for key, value := range source {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

func assertOwned(network *attacknetv1alpha1.StacksNetwork, object client.Object) error {
	owner := metav1.GetControllerOf(object)
	if owner == nil || owner.UID != network.UID || owner.Kind != "StacksNetwork" || owner.Name != network.Name {
		return fmt.Errorf("resource %s/%s is not controlled by StacksNetwork UID %s", object.GetNamespace(), object.GetName(), network.UID)
	}
	return nil
}

func (r *Reconciler) buildStatus(ctx context.Context, network *attacknetv1alpha1.StacksNetwork) (attacknetv1alpha1.StacksNetworkStatus, error) {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.InNamespace(network.Namespace), client.MatchingLabels{managedByLabel: managedByValue, networkLabel: network.Name}); err != nil {
		return attacknetv1alpha1.StacksNetworkStatus{}, fmt.Errorf("list actor Pods: %w", err)
	}
	actorPods := map[string][]corev1.Pod{}
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp.IsZero() {
			actorPods[pod.Labels[actorLabel]] = append(actorPods[pod.Labels[actorLabel]], pod)
		}
	}
	statuses := make([]attacknetv1alpha1.ActorStatus, 0, len(network.Spec.Actors))
	ready, admitted := int32(0), 0
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		name := stableName(network.Name, actor.Name)
		statefulSet := &appsv1.StatefulSet{}
		err := r.Get(ctx, types.NamespacedName{Namespace: network.Namespace, Name: name}, statefulSet)
		if err != nil && !apierrors.IsNotFound(err) {
			return attacknetv1alpha1.StacksNetworkStatus{}, fmt.Errorf("get StatefulSet %s: %w", name, err)
		}
		if apierrors.IsNotFound(err) {
			statefulSet = &appsv1.StatefulSet{}
		}
		rolloutCurrent := statefulSet.Generation > 0 && statefulSet.Status.ObservedGeneration >= statefulSet.Generation && statefulSet.Status.ReadyReplicas >= 1 && statefulSet.Status.UpdatedReplicas >= 1 && statefulSet.Status.CurrentRevision != "" && statefulSet.Status.CurrentRevision == statefulSet.Status.UpdateRevision
		isReady := !network.Spec.Suspended && rolloutCurrent
		var pod *corev1.Pod
		if len(actorPods[actor.Name]) == 1 {
			pod = &actorPods[actor.Name][0]
		}
		container := actorContainerStatus(pod)
		runtimeImageID := ""
		if container != nil {
			runtimeImageID = container.ImageID
		}
		podIdentityReady := pod != nil && podReady(pod) && container != nil && container.Ready && pod.UID != "" && runtimeImagePattern.MatchString(runtimeImageID)
		identityReady := isReady && podIdentityReady && statefulSet.UID != "" && statefulSet.Status.CurrentRevision != ""
		status := attacknetv1alpha1.ActorStatus{Name: actor.Name, Role: actor.Role, ResourceName: name, Image: actorImage(network, actor), Ready: isReady, ReadyReplicas: statefulSet.Status.ReadyReplicas, UpdatedReplicas: statefulSet.Status.UpdatedReplicas, Generation: statefulSet.Generation, ObservedGeneration: statefulSet.Status.ObservedGeneration, CurrentRevision: statefulSet.Status.CurrentRevision, UpdateRevision: statefulSet.Status.UpdateRevision, ServiceName: name, StatefulSetUID: string(statefulSet.UID), StatefulSetResourceVersion: statefulSet.ResourceVersion, RuntimeImageID: runtimeImageID, ConfigDigest: actorConfigDigest(actor), IdentityReady: identityReady}
		if pod != nil {
			status.PodName = pod.Name
			status.PodUID = string(pod.UID)
			status.PodResourceVersion = pod.ResourceVersion
		}
		statuses = append(statuses, status)
		if isReady {
			ready++
		}
		if identityReady {
			admitted++
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	desired := int32(len(statuses))
	phase, conditionStatus, reason, message := "Progressing", metav1.ConditionFalse, "ActorsNotReady", fmt.Sprintf("%d of %d actors are ready", ready, desired)
	if network.Spec.Suspended {
		phase, reason, message = "Suspended", "NetworkSuspended", "All actor StatefulSets are intentionally scaled to zero"
	} else if ready == desired {
		phase, conditionStatus, reason, message = "Ready", metav1.ConditionTrue, "AllActorsReady", fmt.Sprintf("All %d actors are ready", desired)
	}
	status := attacknetv1alpha1.StacksNetworkStatus{ObservedGeneration: network.Generation, Phase: phase, DesiredActors: desired, ReadyActors: ready, ReadySummary: fmt.Sprintf("%d/%d", ready, desired), InventoryReady: !network.Spec.Suspended && admitted == len(statuses) && ready == desired, Actors: statuses, Conditions: append([]metav1.Condition(nil), network.Status.Conditions...)}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Ready", Status: conditionStatus, ObservedGeneration: network.Generation, Reason: reason, Message: message})
	now := metav1.NewTime(r.now())
	status.InventoryObservedAt = &now
	if network.Status.InventoryReady == status.InventoryReady && reflect.DeepEqual(network.Status.Actors, status.Actors) && network.Status.InventoryObservedAt != nil {
		status.InventoryObservedAt = network.Status.InventoryObservedAt.DeepCopy()
	}
	if status.InventoryReady {
		copy := network.DeepCopy()
		copy.Status = status
		payload, err := inventory.Build(copy)
		if err != nil {
			return attacknetv1alpha1.StacksNetworkStatus{}, err
		}
		status.InventoryDigest, err = inventory.Digest(payload)
		if err != nil {
			return attacknetv1alpha1.StacksNetworkStatus{}, err
		}
	}
	return status, nil
}

func actorConfigDigest(actor *attacknetv1alpha1.ActorSpec) string {
	if actor.Config == nil {
		return ""
	}
	return actor.Config.ExpectedDigest
}

func (r *Reconciler) degradedStatus(network *attacknetv1alpha1.StacksNetwork, reconcileError error) attacknetv1alpha1.StacksNetworkStatus {
	desired := int32(len(network.Spec.Actors))
	now := metav1.NewTime(r.now())
	status := attacknetv1alpha1.StacksNetworkStatus{ObservedGeneration: network.Generation, Phase: "Degraded", DesiredActors: desired, ReadySummary: fmt.Sprintf("0/%d", desired), InventoryObservedAt: &now, Conditions: append([]metav1.Condition(nil), network.Status.Conditions...)}
	message := reconcileError.Error()
	if len(message) > 1000 {
		message = message[:1000]
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, ObservedGeneration: network.Generation, Reason: "ReconcileFailed", Message: message})
	return status
}

func (r *Reconciler) updateStatus(ctx context.Context, network *attacknetv1alpha1.StacksNetwork, desired attacknetv1alpha1.StacksNetworkStatus) error {
	if reflect.DeepEqual(network.Status, desired) {
		return nil
	}
	base := network.DeepCopy()
	network.Status = desired
	if err := r.Status().Patch(ctx, network, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("update StacksNetwork status: %w", err)
	}
	return nil
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func podReady(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func actorContainerStatus(pod *corev1.Pod) *corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	for index := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[index].Name == "actor" {
			return &pod.Status.ContainerStatuses[index]
		}
	}
	return nil
}

// SetupWithManager registers StacksNetwork, owned-resource, and actor-Pod watches.
func (r *Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if maxConcurrent < 1 {
		return errors.New("maxConcurrent must be positive")
	}
	podToNetwork := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, object client.Object) []reconcile.Request {
		name := object.GetLabels()[networkLabel]
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
	})
	return builder.ControllerManagedBy(mgr).For(&attacknetv1alpha1.StacksNetwork{}).Owns(&corev1.ConfigMap{}).Owns(&corev1.Service{}).Owns(&appsv1.StatefulSet{}).Watches(&corev1.Pod{}, podToNetwork).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).Complete(r)
}
