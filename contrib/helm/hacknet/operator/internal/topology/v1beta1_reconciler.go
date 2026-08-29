package topology

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
)

// V1Beta1Reconciler compiles the domain API into the proven workload renderer.
// It is intentionally a thin migration adapter: the renderer remains the one
// authoritative implementation of workload defaults, ownership, and identity.
type V1Beta1Reconciler struct {
	client.Client
	APIReader      client.Reader
	Scheme         *runtime.Scheme
	ProbeImage     string
	ProbeImagePull corev1.PullPolicy
}

const environmentLeaseName = "attacknet-environment-lease"

// Reconcile compiles, applies, prunes, and observes a v1beta1 StacksNetwork.
func (r *V1Beta1Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	network := &attacknetv1beta1.StacksNetwork{}
	if err := r.Get(ctx, request.NamespacedName, network); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if !network.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, nil
	}
	if err := r.ensureEnvironmentLease(ctx, network); err != nil {
		logger.Error(err, "v1beta1 environment lease admission failed")
		return reconcile.Result{RequeueAfter: 5 * time.Second}, r.updateStatus(ctx, network, degradedV1Beta1Status(network, err))
	}
	compiled, err := CompileV1Beta1(network)
	if err == nil {
		applyV1Beta1RendererDefaults(compiled, r.ProbeImage, r.ProbeImagePull)
	}
	legacy := &Reconciler{Client: r.Client, Scheme: r.Scheme}
	var resources ResourceSet
	if err == nil {
		resources, err = Render(compiled, r.Scheme)
	}
	if err == nil {
		bindV1Beta1Owner(resources, network)
		err = legacy.applyAndPrune(ctx, compiled, resources)
	}
	if err != nil {
		logger.Error(err, "v1beta1 topology reconciliation failed")
		return reconcile.Result{}, r.updateStatus(ctx, network, degradedV1Beta1Status(network, err))
	}
	legacyStatus, err := legacy.buildStatus(ctx, compiled)
	if err != nil {
		logger.Error(err, "v1beta1 topology status observation failed")
		return reconcile.Result{}, r.updateStatus(ctx, network, degradedV1Beta1Status(network, err))
	}
	desired := convertV1Beta1Status(legacyStatus)
	statusView := network.DeepCopy()
	statusView.Status = desired
	policyUIDs, policiesPending, err := r.observeBurnchainPolicies(ctx, network, &desired)
	if err != nil {
		return reconcile.Result{}, err
	}
	desired.BurnchainTopology = nil
	if policyUIDs != nil {
		graph, graphErr := burnchaintopology.Build(statusView, policyUIDs)
		if graphErr == nil {
			desired.BurnchainTopology = graph
		} else if desired.InventoryReady {
			markBurnchainPolicyPending(&desired, network.Generation, "BurnchainTopologyNotReady", graphErr.Error())
			return reconcile.Result{RequeueAfter: 5 * time.Second}, r.updateStatus(ctx, network, desired)
		}
	}
	if policiesPending {
		return reconcile.Result{RequeueAfter: 5 * time.Second}, r.updateStatus(ctx, network, desired)
	}
	telemetryReady, reason, message, err := observeV1Beta1Telemetry(ctx, r.Client, network)
	if err != nil {
		return reconcile.Result{}, err
	}
	setV1Beta1TelemetryCondition(&desired, network.Generation, telemetryReady, reason, message)
	if !telemetryReady {
		return reconcile.Result{RequeueAfter: 5 * time.Second}, r.updateStatus(ctx, network, desired)
	}
	return reconcile.Result{}, r.updateStatus(ctx, network, desired)
}

// observeBurnchainPolicies verifies every Bitcoin node's independent cadence
// policy before the network becomes Ready.
func (r *V1Beta1Reconciler) observeBurnchainPolicies(ctx context.Context, network *attacknetv1beta1.StacksNetwork, status *attacknetv1beta1.StacksNetworkStatus) (map[string]string, bool, error) {
	bindings, err := burnchaintopology.PolicyBindings(network)
	if err != nil {
		return nil, false, err
	}
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	identities := make(map[string]string, len(names))
	pending := false
	for _, name := range names {
		policy := &attacknetv1beta1.BurnchainPolicy{}
		key := types.NamespacedName{Namespace: network.Namespace, Name: name}
		if err := r.Get(ctx, key, policy); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return nil, false, err
			}
			markBurnchainPolicyPending(status, network.Generation, "BurnchainPolicyNotFound", fmt.Sprintf("BurnchainPolicy %s does not exist", name))
			return nil, true, nil
		}
		node := bindings[name]
		if policy.Spec.NetworkRef != network.Name || policy.Spec.BitcoinNodeRef != node {
			markBurnchainPolicyPending(status, network.Generation, "BurnchainPolicyMismatch", fmt.Sprintf("BurnchainPolicy %s does not bind network %s Bitcoin node %s", name, network.Name, node))
			return nil, true, nil
		}
		if policy.UID == "" {
			markBurnchainPolicyPending(status, network.Generation, "BurnchainPolicyIdentityPending", fmt.Sprintf("BurnchainPolicy %s has no admitted UID", name))
			return nil, true, nil
		}
		identities[name] = string(policy.UID)
		if policy.Status.ObservedGeneration != policy.Generation || policy.Status.Phase != "Ready" {
			if !pending {
				markBurnchainPolicyPending(status, network.Generation, "BurnchainPolicyNotReady", fmt.Sprintf("BurnchainPolicy %s phase is %s", policy.Name, policy.Status.Phase))
			}
			pending = true
		}
	}
	return identities, pending, nil
}

func applyV1Beta1RendererDefaults(network *attacknetv1alpha1.StacksNetwork, probeImage string, probePull corev1.PullPolicy) {
	if network == nil || network.Spec.Probe == nil {
		return
	}
	if network.Spec.Probe.Image == "" && probeImage != "" {
		network.Spec.Probe.Image = probeImage
	}
	if network.Spec.Probe.ImagePullPolicy == "" && probePull != "" {
		network.Spec.Probe.ImagePullPolicy = probePull
	}
}

// ensureEnvironmentLease makes the network controller, rather than a host
// helper, the durable owner of the namespace-wide mutation admission barrier.
func (r *V1Beta1Reconciler) ensureEnvironmentLease(ctx context.Context, network *attacknetv1beta1.StacksNetwork) error {
	if r.APIReader == nil {
		return errors.New("v1beta1 topology reconciler requires an uncached Kubernetes API reader")
	}
	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: environmentLeaseName, Namespace: network.Namespace},
		Data: map[string]string{
			"network": network.Name,
			"owner":   "stacksnetwork:" + string(network.UID),
			"purpose": "controller-owned-environment",
			"token":   string(network.UID),
		},
	}
	if err := controllerutil.SetControllerReference(network, desired, r.Scheme); err != nil {
		return fmt.Errorf("bind environment lease ownership: %w", err)
	}
	current := &corev1.ConfigMap{}
	key := client.ObjectKeyFromObject(desired)
	err := r.APIReader.Get(ctx, key, current)
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("read environment lease: %w", err)
	}
	if err != nil {
		if createErr := r.Create(ctx, desired); createErr == nil {
			return nil
		} else if !apierrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("create environment lease: %w", createErr)
		}
		if err := r.APIReader.Get(ctx, key, current); err != nil {
			return fmt.Errorf("read raced environment lease: %w", err)
		}
	}
	owner := metav1.GetControllerOf(current)
	if owner == nil || owner.UID != network.UID || owner.Kind != "StacksNetwork" || owner.APIVersion != attacknetv1beta1.GroupVersion.String() {
		return fmt.Errorf("environment lease is held by network %q with owner UID %q", current.Data["network"], ownerUID(owner))
	}
	if !reflect.DeepEqual(current.Data, desired.Data) {
		return fmt.Errorf("environment lease data does not match StacksNetwork %s UID %s", network.Name, network.UID)
	}
	return nil
}

func ownerUID(owner *metav1.OwnerReference) string {
	if owner == nil {
		return ""
	}
	return string(owner.UID)
}

func markBurnchainPolicyPending(status *attacknetv1beta1.StacksNetworkStatus, generation int64, reason, message string) {
	status.Phase = "Pending"
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: "Ready", Status: metav1.ConditionFalse, ObservedGeneration: generation,
		Reason: reason, Message: message,
	})
}

func bindV1Beta1Owner(resources ResourceSet, network *attacknetv1beta1.StacksNetwork) {
	controller, blockDeletion := true, true
	reference := metav1.OwnerReference{
		APIVersion:         attacknetv1beta1.GroupVersion.String(),
		Kind:               "StacksNetwork",
		Name:               network.Name,
		UID:                network.UID,
		Controller:         &controller,
		BlockOwnerDeletion: &blockDeletion,
	}
	for _, object := range resources.Objects() {
		object.SetOwnerReferences([]metav1.OwnerReference{reference})
	}
}

func convertV1Beta1Status(source attacknetv1alpha1.StacksNetworkStatus) attacknetv1beta1.StacksNetworkStatus {
	actors := make([]attacknetv1beta1.ActorStatus, 0, len(source.Actors))
	for _, actor := range source.Actors {
		actors = append(actors, attacknetv1beta1.ActorStatus{
			Name: actor.Name, Role: actor.Role, ResourceName: actor.ResourceName,
			Image: actor.Image, Ready: actor.Ready, ReadyReplicas: actor.ReadyReplicas,
			UpdatedReplicas: actor.UpdatedReplicas, Generation: actor.Generation,
			ObservedGeneration: actor.ObservedGeneration, CurrentRevision: actor.CurrentRevision,
			UpdateRevision: actor.UpdateRevision, ServiceName: actor.ServiceName,
			StatefulSetUID: actor.StatefulSetUID, StatefulSetResourceVersion: actor.StatefulSetResourceVersion,
			PodName: actor.PodName, PodUID: actor.PodUID, PodResourceVersion: actor.PodResourceVersion,
			RuntimeImageID: actor.RuntimeImageID, IdentityReady: actor.IdentityReady,
		})
	}
	return attacknetv1beta1.StacksNetworkStatus{
		ObservedGeneration: source.ObservedGeneration, Phase: source.Phase,
		DesiredActors: source.DesiredActors, ReadyActors: source.ReadyActors,
		ReadySummary: source.ReadySummary, InventoryReady: source.InventoryReady,
		InventoryDigest: source.InventoryDigest, InventoryObservedAt: source.InventoryObservedAt,
		Actors: actors, Conditions: append([]metav1.Condition(nil), source.Conditions...),
	}
}

func degradedV1Beta1Status(network *attacknetv1beta1.StacksNetwork, reconcileError error) attacknetv1beta1.StacksNetworkStatus {
	desired := int32(len(network.Spec.Burnchain.Nodes) + len(network.Spec.Nodes) + len(network.Spec.RawActors))
	if network.Spec.Enrollment != nil {
		desired++
	}
	for _, set := range network.Spec.SignerSets {
		desired += int32(len(set.Members) * 2)
	}
	status := attacknetv1beta1.StacksNetworkStatus{
		ObservedGeneration: network.Generation,
		Phase:              "Degraded",
		DesiredActors:      desired,
		ReadySummary:       fmt.Sprintf("0/%d", desired),
		Conditions:         append([]metav1.Condition(nil), network.Status.Conditions...),
	}
	message := reconcileError.Error()
	if len(message) > 1000 {
		message = message[:1000]
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: "Ready", Status: metav1.ConditionFalse, ObservedGeneration: network.Generation,
		Reason: "ReconcileFailed", Message: message,
	})
	return status
}

func (r *V1Beta1Reconciler) updateStatus(ctx context.Context, network *attacknetv1beta1.StacksNetwork, desired attacknetv1beta1.StacksNetworkStatus) error {
	if reflect.DeepEqual(network.Status, desired) {
		return nil
	}
	base := network.DeepCopy()
	network.Status = desired
	if err := r.Status().Patch(ctx, network, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("update v1beta1 StacksNetwork status: %w", err)
	}
	return nil
}

// SetupWithManager registers v1beta1 network and owned-resource watches.
func (r *V1Beta1Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if maxConcurrent < 1 {
		return errors.New("maxConcurrent must be positive")
	}
	if r.APIReader == nil || r.Scheme == nil {
		return errors.New("v1beta1 topology reconciler requires API reader and scheme")
	}
	return builder.ControllerManagedBy(mgr).
		For(&attacknetv1beta1.StacksNetwork{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&appsv1.StatefulSet{}).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			return r.networksUsingTelemetryService(ctx, object.GetNamespace(), object.GetName())
		})).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			return r.networksUsingTelemetryService(ctx, object.GetNamespace(), object.GetLabels()[discoveryv1.LabelServiceName])
		})).
		Watches(&attacknetv1beta1.BurnchainPolicy{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			policy, ok := object.(*attacknetv1beta1.BurnchainPolicy)
			if !ok || policy.Spec.NetworkRef == "" {
				return nil
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.NetworkRef}}}
		})).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			name := object.GetLabels()[networkLabel]
			if name == "" {
				return nil
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
		})).
		WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).
		Complete(r)
}

// networksUsingTelemetryService maps a Service or EndpointSlice event to the
// networks whose readiness depends on it.
func (r *V1Beta1Reconciler) networksUsingTelemetryService(ctx context.Context, namespace, serviceName string) []reconcile.Request {
	if serviceName == "" {
		return nil
	}
	networks := &attacknetv1beta1.StacksNetworkList{}
	if err := r.List(ctx, networks, client.InNamespace(namespace)); err != nil {
		log.FromContext(ctx).Error(err, "list StacksNetworks for telemetry dependency event", "service", serviceName)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(networks.Items))
	for index := range networks.Items {
		for _, dependency := range v1Beta1TelemetryDependencies(&networks.Items[index]) {
			if dependency.name == serviceName {
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: networks.Items[index].Name}})
				break
			}
		}
	}
	sort.Slice(requests, func(left, right int) bool { return requests[left].Name < requests[right].Name })
	return requests
}
