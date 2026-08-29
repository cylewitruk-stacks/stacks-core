package burnchainpolicy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

const (
	requeueApplying = time.Second
	requeueReady    = 5 * time.Second
)

// Reconciler converges BurnchainPolicy resources into one credential-free clock Deployment.
type Reconciler struct {
	client.Client
	APIReader      client.Reader
	Scheme         *runtime.Scheme
	ClockImage     string
	ClockImagePull corev1.PullPolicy
	StatusReader   StatusReader
	Now            func() time.Time
}

// Reconcile admits Bitcoin identity, applies policy resources, and observes acknowledgement.
func (reconciler *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := reconciler.Get(ctx, request.NamespacedName, policy); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if !policy.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, nil
	}
	now := metav1.NewTime(reconciler.now())
	network, bitcoinActor, err := reconciler.admitNetwork(ctx, policy)
	if err != nil {
		return reconciler.recordFailure(ctx, policy, now, "NetworkNotReady", err)
	}
	if policy.Status.AdmittedNetworkUID == "" {
		status := *policy.Status.DeepCopy()
		status.ObservedGeneration = policy.Generation
		status.AdmittedNetworkUID = string(network.UID)
		status.AdmittedBitcoinUID = bitcoinActor.StatefulSetUID
		status.AdmittedBitcoinImageID = bitcoinActor.RuntimeImageID
		status.Phase, status.Reason, status.Message = "Admitted", "NetworkIdentityAdmitted", "Bitcoin actor identity admitted; policy resources have not yet been created"
		status.LastAttemptAt = &now
		status.ConsecutiveFailures = 0
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		return reconcile.Result{Requeue: true}, reconciler.updateStatus(ctx, policy, status)
	}
	if policy.Status.AdmittedNetworkUID != string(network.UID) || policy.Status.AdmittedBitcoinUID != bitcoinActor.StatefulSetUID || policy.Status.AdmittedBitcoinImageID != bitcoinActor.RuntimeImageID {
		return reconciler.recordFailure(ctx, policy, now, "NetworkIdentityChanged", errors.New("admitted network or Bitcoin StatefulSet identity changed; recreate BurnchainPolicy"))
	}
	currentConfigMap, err := reconciler.currentConfigMap(ctx, policy)
	if err != nil {
		return reconciler.recordFailure(ctx, policy, now, "PolicyReadFailed", err)
	}
	observed, observationErr := reconciler.observeClock(ctx, policy)
	runtimePolicy, err := compileRuntime(policy, currentConfigMap, observed)
	if err != nil {
		return reconciler.recordFailure(ctx, policy, now, "InvalidPolicy", err)
	}
	bitcoinPort := int32(0)
	for _, node := range network.Spec.Burnchain.Nodes {
		if node.Name == policy.Spec.BitcoinNodeRef {
			bitcoinPort = burnchaintopology.EffectiveRPCPort(node)
			break
		}
	}
	if bitcoinPort == 0 {
		return reconciler.recordFailure(ctx, policy, now, "InvalidTopology", errors.New("admitted Bitcoin node disappeared from topology"))
	}
	configuration := resourceConfig{
		Image: reconciler.ClockImage, ImagePullPolicy: reconciler.ClockImagePull,
		BitcoinService: bitcoinActor.ServiceName, BitcoinRPCPort: bitcoinPort,
		Runtime: runtimePolicy, Policy: policy, Network: network, Scheme: reconciler.Scheme,
	}
	configMap, err := configuration.configMap()
	if err == nil {
		err = reconciler.applyConfigMap(ctx, policy, configMap)
	}
	var service *corev1.Service
	if err == nil {
		service, err = configuration.service()
	}
	if err == nil {
		err = reconciler.applyService(ctx, policy, service)
	}
	var deployment *appsv1.Deployment
	if err == nil {
		deployment, err = configuration.deployment()
	}
	if err == nil {
		err = reconciler.applyDeployment(ctx, policy, deployment)
	}
	if err != nil {
		return reconciler.recordFailure(ctx, policy, now, "ApplyFailed", err)
	}
	status := *policy.Status.DeepCopy()
	status.ObservedGeneration, status.ConsecutiveFailures = policy.Generation, 0
	if observed != nil && observed.BitcoinHeight != nil {
		if *observed.BitcoinHeight > uint64(^uint64(0)>>1) {
			return reconciler.recordFailure(ctx, policy, now, "InvalidClockStatus", fmt.Errorf("observed Bitcoin height exceeds the supported status range"))
		}
		status.ObservedHeight = int64(*observed.BitcoinHeight)
	}
	if observed != nil {
		status.BitcoinObservationError = observed.ObservationError
		if observed.ChainInfo != nil {
			status.ObservedHeight = observed.ChainInfo.Blocks
			status.ObservedHeaders = observed.ChainInfo.Headers
			status.LastBlockHash = observed.ChainInfo.BestBlockHash
			status.ObservedChainwork = observed.ChainInfo.Chainwork
			observedAt := metav1.NewTime(observed.UpdatedAt.UTC())
			status.BitcoinObservationAt = &observedAt
		}
		if observed.ChainInfo != nil {
			status.ObservedChainTips = make([]attacknetv1beta1.BurnchainChainTipStatus, 0, len(observed.ChainTips))
			for _, tip := range observed.ChainTips {
				status.ObservedChainTips = append(status.ObservedChainTips, attacknetv1beta1.BurnchainChainTipStatus{
					Height: tip.Height, Hash: tip.Hash, BranchLen: tip.BranchLen, Status: tip.Status,
				})
			}
			status.ObservedPeers = make([]attacknetv1beta1.BurnchainPeerStatus, 0, len(observed.Peers))
			for _, peer := range observed.Peers {
				status.ObservedPeers = append(status.ObservedPeers, attacknetv1beta1.BurnchainPeerStatus{
					ID: peer.ID, Address: peer.Address, Inbound: peer.Inbound, ConnectionType: peer.ConnectionType,
					LastBlock: peer.LastBlock, LastTransaction: peer.LastTransaction,
				})
			}
		}
	}
	if observationErr != nil {
		status.Phase, status.Reason, status.Message = "Applying", "ClockStatusUnavailable", boundedMessage(observationErr.Error())
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		setAttemptIfChanged(&status, policy.Status, now)
		return reconcile.Result{RequeueAfter: requeueApplying}, reconciler.updateStatus(ctx, policy, status)
	}
	if observed == nil || observed.PolicyGeneration == nil || *observed.PolicyGeneration != runtimePolicy.policy.Generation {
		status.Phase, status.Reason, status.Message = "Applying", "PolicyNotAcknowledged", fmt.Sprintf("Waiting for runtime policy generation %d", runtimePolicy.policy.Generation)
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		setAttemptIfChanged(&status, policy.Status, now)
		return reconcile.Result{RequeueAfter: requeueApplying}, reconciler.updateStatus(ctx, policy, status)
	}
	if observed.PolicyMode != runtimePolicy.policy.Mode ||
		(runtimePolicy.flashID == "" && runtimePolicy.policy.Mode == burnchain.ModePause && observed.State != "paused") {
		status.Phase, status.Reason, status.Message = "Applying", "PolicyStateNotAcknowledged", fmt.Sprintf("Waiting for runtime policy generation %d to enter %s mode", runtimePolicy.policy.Generation, runtimePolicy.policy.Mode)
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		setAttemptIfChanged(&status, policy.Status, now)
		return reconcile.Result{RequeueAfter: requeueApplying}, reconciler.updateStatus(ctx, policy, status)
	}
	wasReady := status.Phase == "Ready" && status.AppliedPolicyDigest == runtimePolicy.digest
	status.AppliedPolicyDigest = runtimePolicy.digest
	if observed.State == "degraded" {
		status.Phase, status.Reason, status.Message = "Degraded", "ClockDegraded", boundedMessage(observed.Detail)
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		setAttemptIfChanged(&status, policy.Status, now)
		return reconcile.Result{RequeueAfter: requeueApplying}, reconciler.updateStatus(ctx, policy, status)
	}
	if runtimePolicy.flashID != "" && !runtimePolicy.flashDone {
		status.Phase, status.Reason, status.Message = "Bursting", "FlashInProgress", fmt.Sprintf("Mining toward Bitcoin height %d", runtimePolicy.policy.BurstTargetHeight)
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		setAttemptIfChanged(&status, policy.Status, now)
		return reconcile.Result{RequeueAfter: requeueApplying}, reconciler.updateStatus(ctx, policy, status)
	}
	if runtimePolicy.flashID != "" && runtimePolicy.flashDone {
		status.AppliedFlashID = runtimePolicy.flashID
		status.Phase, status.Reason, status.Message = "Applying", "FlashComplete", "Flash target reached; restoring steady-state cadence"
		setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, status.Reason, status.Message)
		setAttemptIfChanged(&status, policy.Status, now)
		return reconcile.Result{Requeue: true}, reconciler.updateStatus(ctx, policy, status)
	}
	status.Phase, status.Reason, status.Message = "Ready", "PolicyApplied", fmt.Sprintf("Runtime policy generation %d is applied", runtimePolicy.policy.Generation)
	if !wasReady || status.LastSuccessAt == nil {
		status.LastSuccessAt = &now
	}
	setReadyCondition(&status, metav1.ConditionTrue, policy.Generation, status.Reason, status.Message)
	setAttemptIfChanged(&status, policy.Status, now)
	return reconcile.Result{RequeueAfter: requeueReady}, reconciler.updateStatus(ctx, policy, status)
}

func (reconciler *Reconciler) admitNetwork(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy) (*attacknetv1beta1.StacksNetwork, *attacknetv1beta1.ActorStatus, error) {
	if err := validatePolicy(policy); err != nil {
		return nil, nil, err
	}
	network := &attacknetv1beta1.StacksNetwork{}
	key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.NetworkRef}
	if err := reconciler.APIReader.Get(ctx, key, network); err != nil {
		return nil, nil, fmt.Errorf("read StacksNetwork: %w", err)
	}
	if !network.DeletionTimestamp.IsZero() || network.Status.ObservedGeneration != network.Generation {
		return nil, nil, fmt.Errorf("StacksNetwork %s has not observed its current generation", network.Name)
	}
	policyName, err := burnchaintopology.PolicyName(network, policy.Spec.BitcoinNodeRef)
	if err != nil {
		return nil, nil, err
	}
	if policyName != policy.Name {
		return nil, nil, fmt.Errorf("StacksNetwork %s Bitcoin node %s selects BurnchainPolicy %s, not %s", network.Name, policy.Spec.BitcoinNodeRef, policyName, policy.Name)
	}
	for index := range network.Status.Actors {
		actor := &network.Status.Actors[index]
		if actor.Name == policy.Spec.BitcoinNodeRef && actor.Role == "burnchain" && actor.IdentityReady && actor.ServiceName != "" && actor.StatefulSetUID != "" && inventory.HasImmutableImageID(actor.RuntimeImageID) {
			return network, actor, nil
		}
	}
	return nil, nil, fmt.Errorf("Bitcoin actor %s has no admitted runtime identity", policy.Spec.BitcoinNodeRef)
}

func (reconciler *Reconciler) currentConfigMap(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy) (*corev1.ConfigMap, error) {
	current := &corev1.ConfigMap{}
	err := reconciler.Get(ctx, types.NamespacedName{Namespace: policy.Namespace, Name: resourceConfig{Policy: policy}.resourceName()}, current)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runtime policy ConfigMap: %w", err)
	}
	if err := assertOwned(policy, current); err != nil {
		return nil, err
	}
	return current, nil
}

func (reconciler *Reconciler) observeClock(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy) (*burnchain.Status, error) {
	pods := &corev1.PodList{}
	if err := reconciler.APIReader.List(ctx, pods, client.InNamespace(policy.Namespace), client.MatchingLabels{labelPolicy: policy.Name, labelComponent: componentClock}); err != nil {
		return nil, fmt.Errorf("list clock Pods: %w", err)
	}
	var candidate *corev1.Pod
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.DeletionTimestamp.IsZero() && pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			if candidate != nil {
				return nil, fmt.Errorf("multiple Ready clock Pods exist")
			}
			candidate = pod
		}
	}
	if candidate == nil {
		return nil, fmt.Errorf("clock Pod is not running")
	}
	status, err := reconciler.StatusReader.Read(ctx, candidate.Status.PodIP)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (reconciler *Reconciler) applyConfigMap(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy, desired *corev1.ConfigMap) error {
	current := &corev1.ConfigMap{}
	key := client.ObjectKeyFromObject(desired)
	err := reconciler.Get(ctx, key, current)
	if apierrors.IsNotFound(err) {
		return reconciler.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	if err := assertOwned(policy, current); err != nil {
		return err
	}
	base := current.DeepCopy()
	current.Labels, current.Annotations, current.OwnerReferences = desired.Labels, desired.Annotations, desired.OwnerReferences
	current.Data, current.BinaryData = desired.Data, nil
	if reflect.DeepEqual(base, current) {
		return nil
	}
	return reconciler.Patch(ctx, current, client.MergeFrom(base))
}

func (reconciler *Reconciler) applyDeployment(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy, desired *appsv1.Deployment) error {
	current := &appsv1.Deployment{}
	key := client.ObjectKeyFromObject(desired)
	err := reconciler.Get(ctx, key, current)
	if apierrors.IsNotFound(err) {
		return reconciler.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	if err := assertOwned(policy, current); err != nil {
		return err
	}
	if !apiequality.Semantic.DeepEqual(current.Spec.Selector, desired.Spec.Selector) {
		return fmt.Errorf("clock Deployment selector is immutable; recreate BurnchainPolicy")
	}
	base := current.DeepCopy()
	current.Labels, current.Annotations, current.OwnerReferences = desired.Labels, desired.Annotations, desired.OwnerReferences
	current.Spec.Replicas, current.Spec.Strategy = desired.Spec.Replicas, desired.Spec.Strategy
	current.Spec.Template, current.Spec.RevisionHistoryLimit, current.Spec.ProgressDeadlineSeconds = desired.Spec.Template, desired.Spec.RevisionHistoryLimit, desired.Spec.ProgressDeadlineSeconds
	if reflect.DeepEqual(base, current) {
		return nil
	}
	return reconciler.Patch(ctx, current, client.MergeFrom(base))
}

func (reconciler *Reconciler) applyService(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy, desired *corev1.Service) error {
	current := &corev1.Service{}
	key := client.ObjectKeyFromObject(desired)
	err := reconciler.Get(ctx, key, current)
	if apierrors.IsNotFound(err) {
		return reconciler.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	if err := assertOwned(policy, current); err != nil {
		return err
	}
	base := current.DeepCopy()
	current.Labels, current.Annotations, current.OwnerReferences = desired.Labels, desired.Annotations, desired.OwnerReferences
	current.Spec.Type, current.Spec.Selector, current.Spec.Ports = desired.Spec.Type, desired.Spec.Selector, desired.Spec.Ports
	current.Spec.ExternalIPs, current.Spec.LoadBalancerSourceRanges = nil, nil
	current.Spec.ExternalName, current.Spec.LoadBalancerIP = "", ""
	current.Spec.PublishNotReadyAddresses = false
	if reflect.DeepEqual(base, current) {
		return nil
	}
	return reconciler.Patch(ctx, current, client.MergeFrom(base))
}

func (reconciler *Reconciler) recordFailure(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy, now metav1.Time, reason string, failure error) (reconcile.Result, error) {
	previous := *policy.Status.DeepCopy()
	status := *policy.Status.DeepCopy()
	status.ObservedGeneration, status.Phase, status.Reason = policy.Generation, "Degraded", reason
	status.Message = boundedMessage(failure.Error())
	setReadyCondition(&status, metav1.ConditionFalse, policy.Generation, reason, status.Message)
	coreChanged := previous.ObservedGeneration != status.ObservedGeneration || previous.Phase != status.Phase || previous.Reason != status.Reason || previous.Message != status.Message
	attemptDue := previous.LastAttemptAt == nil || now.Sub(previous.LastAttemptAt.Time) >= requeueApplying
	if coreChanged || attemptDue {
		status.LastAttemptAt = &now
		status.ConsecutiveFailures = previous.ConsecutiveFailures + 1
	} else {
		status.LastAttemptAt = previous.LastAttemptAt
		status.ConsecutiveFailures = previous.ConsecutiveFailures
	}
	if err := reconciler.updateStatus(ctx, policy, status); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: requeueApplying}, nil
}

func (reconciler *Reconciler) updateStatus(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy, desired attacknetv1beta1.BurnchainPolicyStatus) error {
	if reflect.DeepEqual(policy.Status, desired) {
		return nil
	}
	base := policy.DeepCopy()
	policy.Status = desired
	return reconciler.Status().Patch(ctx, policy, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func (reconciler *Reconciler) now() time.Time {
	if reconciler.Now != nil {
		return reconciler.Now().UTC()
	}
	return time.Now().UTC()
}

func (reconciler *Reconciler) mapPod(_ context.Context, object client.Object) []reconcile.Request {
	name := object.GetLabels()[labelPolicy]
	if name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
}

// SetupWithManager registers the BurnchainPolicy controller and owned watches.
func (reconciler *Reconciler) SetupWithManager(mgr manager.Manager, concurrency int) error {
	if reconciler.APIReader == nil || reconciler.Scheme == nil || reconciler.StatusReader == nil || reconciler.ClockImage == "" {
		return fmt.Errorf("BurnchainPolicy reconciler requires API reader, scheme, status reader, and clock image")
	}
	return builder.ControllerManagedBy(mgr).For(&attacknetv1beta1.BurnchainPolicy{}).
		Owns(&corev1.ConfigMap{}).Owns(&corev1.Service{}).Owns(&appsv1.Deployment{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(reconciler.mapPod)).
		WithOptions(controller.Options{MaxConcurrentReconciles: concurrency}).Complete(reconciler)
}

func assertOwned(policy *attacknetv1beta1.BurnchainPolicy, object client.Object) error {
	owner := metav1.GetControllerOf(object)
	if owner == nil || owner.UID != policy.UID || owner.Name != policy.Name || owner.Kind != "BurnchainPolicy" {
		return fmt.Errorf("resource %s/%s is not controlled by BurnchainPolicy UID %s", object.GetNamespace(), object.GetName(), policy.UID)
	}
	return nil
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func setReadyCondition(status *attacknetv1beta1.BurnchainPolicyStatus, value metav1.ConditionStatus, generation int64, reason, message string) {
	meta.SetStatusCondition(&status.Conditions, condition(value, reason, boundedMessage(message), generation))
}

func boundedMessage(message string) string {
	if len(message) > 1000 {
		return message[:1000]
	}
	return message
}

func setAttemptIfChanged(status *attacknetv1beta1.BurnchainPolicyStatus, previous attacknetv1beta1.BurnchainPolicyStatus, now metav1.Time) {
	status.LastAttemptAt = previous.LastAttemptAt
	if !reflect.DeepEqual(*status, previous) {
		status.LastAttemptAt = &now
	}
}
