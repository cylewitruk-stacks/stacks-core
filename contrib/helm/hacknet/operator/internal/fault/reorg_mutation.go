package fault

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	kptr "k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchainworker"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

const (
	reorgApprovalAnnotation      = "testing.stacks.org/reorg-approval"
	reorgPreparationAnnotation   = "testing.stacks.org/reorg-preparation"
	reorgBoundaryAnnotation      = "testing.stacks.org/reorg-boundary-assessment"
	reorgPolicyNameAnnotation    = "testing.stacks.org/reorg-policy"
	reorgPolicyUIDAnnotation     = "testing.stacks.org/reorg-policy-uid"
	reorgPolicySpecAnnotation    = "testing.stacks.org/reorg-policy-spec-digest"
	reorgOriginalPauseAnnotation = "testing.stacks.org/reorg-original-paused"
	reorgWorkerPort              = int32(8090)
	maximumReorgStatusBytes      = 1 << 20
)

var errBurnchainReorgWorkerRemovalPending = errors.New("burnchain reorg worker removal is pending")

type reorgRecoveryContract struct {
	PolicyName       string `json:"policyName"`
	PolicyUID        string `json:"policyUid"`
	StableSpecDigest string `json:"stableSpecDigest"`
	OriginalPaused   bool   `json:"originalPaused"`
}

func (r *V1Beta1Reconciler) burnchainReorgCapabilities(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, action CompiledAction, targets []attacknetv1alpha1.ResolvedTarget) ([]capabilityObservation, error) {
	if len(targets) != 1 || targets[0].Role != "burnchain" {
		return nil, errors.New("burnchain reorg requires one admitted Bitcoin target")
	}
	policy, assessment, err := r.readReorgPolicy(ctx, campaign, network, action)
	observation := capabilityObservation{
		Actor: targets[0].Actor, PodUID: targets[0].PodUID, Source: "attacknet-run-operator/v1",
		ObservedAt: r.now().Format(time.RFC3339Nano), Platform: "bitcoin-core-regtest", Architecture: "semantic-rpc/v1",
		Supported: err == nil,
	}
	if err != nil {
		observation.Reason = err.Error()
		return []capabilityObservation{observation}, nil
	}
	observation.Reason = fmt.Sprintf("policy %s UID %s is Ready; boundaryKnown=%t epoch=%t rewardCycle=%t prepare=%t", policy.Name, policy.UID, assessment.Known, assessment.CrossesEpoch, assessment.CrossesRewardCycle, assessment.CrossesRewardPreparePhase)
	return []capabilityObservation{observation}, nil
}

func (r *V1Beta1Reconciler) readReorgPolicy(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, action CompiledAction) (*attacknetv1beta1.BurnchainPolicy, burnchain.BoundaryAssessment, error) {
	policy := &attacknetv1beta1.BurnchainPolicy{}
	name := network.Spec.Burnchain.PolicyRef.Name
	if name == "" {
		return nil, burnchain.BoundaryAssessment{}, errors.New("StacksNetwork has no burnchain policyRef")
	}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: name}, policy); err != nil {
		return nil, burnchain.BoundaryAssessment{}, fmt.Errorf("read BurnchainPolicy %s: %w", name, err)
	}
	actor, _, _ := unstructured.NestedString(action.Resource.Object, "spec", "actor")
	if policy.Spec.NetworkRef != network.Name || policy.Spec.BitcoinNodeRef != actor {
		return nil, burnchain.BoundaryAssessment{}, fmt.Errorf("BurnchainPolicy %s does not bind target %s", name, actor)
	}
	if policy.Status.ObservedGeneration != policy.Generation || policy.Status.Phase != "Ready" {
		return nil, burnchain.BoundaryAssessment{}, fmt.Errorf("BurnchainPolicy %s is not Ready at generation %d", name, policy.Generation)
	}
	if policy.Spec.Flash != nil && policy.Spec.Flash.ID != policy.Status.AppliedFlashID {
		return nil, burnchain.BoundaryAssessment{}, fmt.Errorf("BurnchainPolicy %s has pending flash %s", name, policy.Spec.Flash.ID)
	}
	request := actionSpecReorg(campaign, action.Resource.GetLabels()["testing.stacks.org/stage"], action.ID)
	if request == nil {
		return nil, burnchain.BoundaryAssessment{}, errors.New("reorg request disappeared")
	}
	if int(request.DestinationIndex) >= len(policy.Spec.Destinations) {
		return nil, burnchain.BoundaryAssessment{}, fmt.Errorf("destination index %d is outside BurnchainPolicy destinations", request.DestinationIndex)
	}
	if policy.Status.ObservedHeight < int64(request.Depth) {
		return nil, burnchain.BoundaryAssessment{}, fmt.Errorf("reorg depth %d exceeds observed Bitcoin height %d", request.Depth, policy.Status.ObservedHeight)
	}
	from := policy.Status.ObservedHeight - int64(request.Depth) + 1
	to := policy.Status.ObservedHeight - int64(request.Depth) + int64(request.ReplacementBlocks)
	assessment := burnchain.AssessBoundaries(from, to, protocolSchedule(policy.Spec.ProtocolSchedule))
	if err := validateReorgBoundarySafety(assessment, campaign.Spec.Safety); err != nil {
		return nil, assessment, err
	}
	return policy, assessment, nil
}

func (r *V1Beta1Reconciler) createBurnchainReorgMutation(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, action CompiledAction, status *attacknetv1beta1.FaultActionStatus) (client.Object, error) {
	key := client.ObjectKey{Namespace: campaign.Namespace, Name: action.Resource.GetName()}
	existing := &corev1.Pod{}
	existingErr := r.APIReader.Get(ctx, key, existing)
	hasExisting := existingErr == nil
	if existingErr != nil && !apierrors.IsNotFound(existingErr) {
		return nil, existingErr
	}
	var policy *attacknetv1beta1.BurnchainPolicy
	var err error
	if hasExisting {
		policy, err = r.readExistingReorgPolicy(ctx, campaign, network, action, existing)
	} else {
		policy, _, err = r.readReorgPolicy(ctx, campaign, network, action)
	}
	if err != nil {
		return nil, err
	}
	if r.ReorgWorkerImage == "" {
		return nil, errors.New("trusted burnchain reorg worker image is not configured")
	}
	stableDigest, err := stableBurnchainPolicyDigest(policy.Spec)
	if err != nil {
		return nil, err
	}
	originalPaused := policy.Spec.Paused
	if hasExisting {
		originalPaused, err = strconv.ParseBool(existing.Annotations[reorgOriginalPauseAnnotation])
		if err != nil {
			return nil, errors.New("existing reorg worker has an invalid original pause contract")
		}
	}
	request := actionSpecReorg(campaign, action.Resource.GetLabels()["testing.stacks.org/stage"], action.ID)
	destination := policy.Spec.Destinations[request.DestinationIndex]
	workerRequest := burnchain.ReorgRequest{
		Depth: request.Depth, ReplacementBlocks: request.ReplacementBlocks,
		ReplacementInterval: request.ReplacementInterval.Duration,
		Wallet:              destination.WalletName, Address: destination.Address,
	}
	requestJSON, err := json.Marshal(workerRequest)
	if err != nil {
		return nil, err
	}
	service, port, err := bitcoinEndpoint(network, policy.Spec.BitcoinNodeRef)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{
		NetworkLabel: network.Name, "testing.stacks.org/campaign": campaign.Name,
		"testing.stacks.org/stage":  action.Resource.GetLabels()["testing.stacks.org/stage"],
		"testing.stacks.org/action": action.ID, "app.kubernetes.io/component": "burnchain-reorg-worker",
	}
	annotations := map[string]string{
		reorgApprovalAnnotation: "", reorgPreparationAnnotation: "", reorgPolicyNameAnnotation: policy.Name,
		reorgPolicyUIDAnnotation: string(policy.UID), reorgPolicySpecAnnotation: stableDigest,
		reorgOriginalPauseAnnotation: strconv.FormatBool(originalPaused),
	}
	environment := []corev1.EnvVar{
		{Name: "ATTACKNET_REORG_REQUEST_JSON", Value: string(requestJSON)},
		{Name: "ATTACKNET_REORG_PREPARATION_FILE", Value: "/var/run/attacknet-reorg/preparation"},
		{Name: "ATTACKNET_REORG_APPROVAL_FILE", Value: "/var/run/attacknet-reorg/approval"},
		{Name: "BITCOIN_RPC_URL", Value: fmt.Sprintf("http://%s:%d", service, port)},
		{Name: "BITCOIN_RPC_USERNAME", Value: "devnet"}, {Name: "BITCOIN_RPC_PASSWORD", Value: "devnet"},
	}
	if policy.Spec.RPC.UsernameSecretRef != nil && policy.Spec.RPC.PasswordSecretRef != nil {
		environment[4].Value, environment[5].Value = "", ""
		environment[4].ValueFrom = secretEnvSource(policy.Spec.RPC.UsernameSecretRef)
		environment[5].ValueFrom = secretEnvSource(policy.Spec.RPC.PasswordSecretRef)
	}
	grace, enableLinks := int64(10), false
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: action.Resource.GetName(), Namespace: campaign.Namespace, Labels: labels, Annotations: annotations},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: kptr.To(false), EnableServiceLinks: &enableLinks,
			RestartPolicy: corev1.RestartPolicyNever, TerminationGracePeriodSeconds: &grace,
			SecurityContext:  &corev1.PodSecurityContext{RunAsNonRoot: kptr.To(true), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			ImagePullSecrets: append([]corev1.LocalObjectReference(nil), network.Spec.Defaults.ImagePullSecrets...),
			Containers: []corev1.Container{{
				Name: "worker", Image: r.ReorgWorkerImage, ImagePullPolicy: r.ReorgWorkerPull,
				Args: []string{"burnchain-reorg-worker"}, Env: environment,
				Ports:           []corev1.ContainerPort{{Name: "status", ContainerPort: reorgWorkerPort}},
				ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/status", Port: intstr.FromInt32(reorgWorkerPort)}}, PeriodSeconds: 1, TimeoutSeconds: 1},
				Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("24Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("128Mi")}},
				SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: kptr.To(false), ReadOnlyRootFilesystem: kptr.To(true), RunAsNonRoot: kptr.To(true), RunAsUser: kptr.To[int64](65532), RunAsGroup: kptr.To[int64](65532), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
				VolumeMounts:    []corev1.VolumeMount{{Name: "approval", MountPath: "/var/run/attacknet-reorg", ReadOnly: true}, {Name: "tmp", MountPath: "/tmp"}},
			}},
			Volumes: []corev1.Volume{
				{Name: "approval", VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{
					{Path: "preparation", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.annotations['" + reorgPreparationAnnotation + "']"}},
					{Path: "approval", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.annotations['" + reorgApprovalAnnotation + "']"}},
				}}}},
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
		},
	}
	// Apply the same built-in defaults the API server will add so restart-time
	// adoption can compare the complete admitted execution contract strictly.
	r.Scheme.Default(pod)
	if err := ownership.SetControllerReference(campaign, pod, r.Scheme); err != nil {
		return nil, err
	}
	created := false
	if !hasExisting {
		created = true
	}
	if !hasExisting {
		err = r.Create(ctx, pod)
	}
	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		created = false
	}
	observed := &corev1.Pod{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(pod), observed); err != nil {
		if created {
			_ = client.IgnoreNotFound(r.Delete(ctx, pod))
		}
		return nil, err
	}
	if controllerOwnerUID(observed) != string(campaign.UID) || !burnchainReorgDesiredMatches(pod, observed) {
		if created {
			_ = client.IgnoreNotFound(r.Delete(ctx, observed))
		}
		return nil, errors.New("refusing to adopt burnchain reorg worker with a different owner or execution contract")
	}
	return observed, nil
}

func (r *V1Beta1Reconciler) readExistingReorgPolicy(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, action CompiledAction, pod *corev1.Pod) (*attacknetv1beta1.BurnchainPolicy, error) {
	if controllerOwnerUID(pod) != string(campaign.UID) {
		return nil, errors.New("refusing to adopt burnchain reorg worker not owned by the campaign")
	}
	policyName := network.Spec.Burnchain.PolicyRef.Name
	if policyName == "" || pod.Annotations[reorgPolicyNameAnnotation] != policyName {
		return nil, errors.New("existing reorg worker does not bind the admitted burnchain policy")
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: policyName}, policy); err != nil {
		return nil, fmt.Errorf("read existing reorg BurnchainPolicy: %w", err)
	}
	contract := reorgRecoveryContract{
		PolicyName: policyName, PolicyUID: pod.Annotations[reorgPolicyUIDAnnotation],
		StableSpecDigest: pod.Annotations[reorgPolicySpecAnnotation],
	}
	if err := validateReorgPolicyContract(policy, contract); err != nil {
		return nil, err
	}
	actor, _, _ := unstructured.NestedString(action.Resource.Object, "spec", "actor")
	originalPaused, err := strconv.ParseBool(pod.Annotations[reorgOriginalPauseAnnotation])
	if err != nil {
		return nil, errors.New("existing reorg worker has an invalid original pause contract")
	}
	if policy.Spec.NetworkRef != network.Name || policy.Spec.BitcoinNodeRef != actor || policy.Spec.Paused != originalPaused {
		return nil, errors.New("existing reorg worker policy binding or pre-preparation pause state changed")
	}
	request := actionSpecReorg(campaign, action.Resource.GetLabels()["testing.stacks.org/stage"], action.ID)
	if request == nil || int(request.DestinationIndex) >= len(policy.Spec.Destinations) {
		return nil, errors.New("existing reorg worker request no longer resolves against its policy")
	}
	return policy, nil
}

func burnchainReorgDesiredMatches(desired, observed *corev1.Pod) bool {
	if desired.Name != observed.Name || desired.Namespace != observed.Namespace {
		return false
	}
	for key, value := range desired.Labels {
		if observed.Labels[key] != value {
			return false
		}
	}
	for _, key := range []string{reorgPolicyNameAnnotation, reorgPolicyUIDAnnotation, reorgPolicySpecAnnotation, reorgOriginalPauseAnnotation} {
		if desired.Annotations[key] != observed.Annotations[key] {
			return false
		}
	}
	if _, err := strconv.ParseBool(observed.Annotations[reorgOriginalPauseAnnotation]); err != nil {
		return false
	}
	// Scheduler placement is the only execution-spec field allowed to differ.
	// Built-in Pod defaults were applied before creation, so every other field is
	// compared strictly and an added sidecar or privilege cannot be adopted.
	current := observed.Spec.DeepCopy()
	current.NodeName = ""
	wanted := desired.Spec.DeepCopy()
	wanted.NodeName = ""
	return apiequality.Semantic.DeepEqual(wanted, current)
}

func (r *V1Beta1Reconciler) burnchainReorgInjected(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus, pod *corev1.Pod) (bool, error) {
	workerStatus, err := r.readReorgWorkerStatus(ctx, pod)
	if err != nil {
		return false, nil
	}
	switch workerStatus.Phase {
	case "WaitingForPreparation":
		if err := r.approveReorgPreparation(ctx, campaign, status, pod); err != nil {
			return false, err
		}
		return false, nil
	case "Preparing", "Executing":
		return false, nil
	case "Prepared":
		if workerStatus.Prepared == nil || workerStatus.Prepared.Digest == "" {
			return false, errors.New("reorg worker reported Prepared without a digest")
		}
		if err := r.approvePreparedReorg(ctx, campaign, spec, status, pod, workerStatus.Prepared); err != nil {
			return false, err
		}
		return false, nil
	case "Succeeded":
		if workerStatus.Result == nil || !workerStatus.Result.CanonicalProven {
			return false, errors.New("reorg worker succeeded without canonical branch proof")
		}
		return true, nil
	case "Failed":
		if err := r.recordBurnchainReorgFailure(status, workerStatus); err != nil {
			return false, err
		}
		return false, fmt.Errorf("reorg worker failed: %s", workerStatus.Failure)
	default:
		return false, nil
	}
}

func (r *V1Beta1Reconciler) approveReorgPreparation(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, status *attacknetv1beta1.FaultActionStatus, pod *corev1.Pod) error {
	contract, err := recoveryContract(status)
	if err != nil {
		return err
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: contract.PolicyName}, policy); err != nil {
		return err
	}
	if err := validateReorgPolicyContract(policy, contract); err != nil {
		return err
	}
	if !policy.Spec.Paused {
		if contract.OriginalPaused {
			return errors.New("BurnchainPolicy lost its admitted paused state before reorg preparation")
		}
		base := policy.DeepCopy()
		policy.Spec.Paused = true
		if err := r.Patch(ctx, policy, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("pause BurnchainPolicy for reorg preparation: %w", err)
		}
		return nil
	}
	if policy.Status.ObservedGeneration != policy.Generation || policy.Status.Phase != "Ready" {
		return nil
	}
	token := policy.Status.AppliedPolicyDigest
	if !strings.HasPrefix(token, "sha256:") || len(token) != len("sha256:")+64 {
		return errors.New("paused BurnchainPolicy has no immutable applied digest")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(token, "sha256:")); err != nil {
		return errors.New("paused BurnchainPolicy applied digest is malformed")
	}
	if current := pod.Annotations[reorgPreparationAnnotation]; current != "" && current != token {
		return errors.New("reorg worker preparation annotation changed")
	} else if current == token {
		return nil
	}
	base := pod.DeepCopy()
	pod.Annotations[reorgPreparationAnnotation] = token
	return r.Patch(ctx, pod, client.MergeFrom(base))
}

func (r *V1Beta1Reconciler) recordBurnchainReorgFailure(status *attacknetv1beta1.FaultActionStatus, workerStatus burnchainworker.Status) error {
	preparedDigest := ""
	var branchEvidence any
	if workerStatus.Result != nil {
		preparedDigest = workerStatus.Result.PreparedDigest
		branchEvidence = workerStatus.Result
	} else if workerStatus.Prepared != nil {
		preparedDigest = workerStatus.Prepared.Digest
		branchEvidence = workerStatus.Prepared
	}
	actor := ""
	if len(status.ResolvedTargets) > 0 {
		actor = status.ResolvedTargets[0].Actor
	}
	actual, err := rawAPIJSON(map[string]any{
		"schemaVersion": workerStatus.SchemaVersion, "phase": workerStatus.Phase,
		"preparedDigest": preparedDigest, "failure": workerStatus.Failure,
		"observedAt": r.now(),
	})
	if err != nil {
		return err
	}
	result, err := rawAPIJSON(map[string]any{
		"assertion": "BurnchainReorgProven", "outcome": "Inconclusive",
		"actor": actor, "preparedDigest": preparedDigest,
		"failure": workerStatus.Failure, "evidence": branchEvidence, "observedAt": r.now(),
	})
	if err != nil {
		return err
	}
	status.ActualInjection = &actual
	status.EffectResults = []apixv1.JSON{result}
	return nil
}

func (r *V1Beta1Reconciler) approvePreparedReorg(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus, pod *corev1.Pod, prepared *burnchain.PreparedReorg) error {
	contract, err := recoveryContract(status)
	if err != nil {
		return err
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: contract.PolicyName}, policy); err != nil {
		return err
	}
	if err := validateReorgPolicyContract(policy, contract); err != nil {
		return err
	}
	if !policy.Spec.Paused || policy.Status.ObservedGeneration != policy.Generation || policy.Status.Phase != "Ready" {
		return nil
	}
	from := prepared.Original.Blocks - int64(spec.Fault.BurnchainReorg.Depth) + 1
	to := prepared.Original.Blocks - int64(spec.Fault.BurnchainReorg.Depth) + int64(spec.Fault.BurnchainReorg.ReplacementBlocks)
	assessment := burnchain.AssessBoundaries(from, to, protocolSchedule(policy.Spec.ProtocolSchedule))
	if err := validateReorgBoundarySafety(assessment, campaign.Spec.Safety); err != nil {
		return err
	}
	boundaryJSON, err := json.Marshal(assessment)
	if err != nil {
		return err
	}
	if current := pod.Annotations[reorgApprovalAnnotation]; current != "" && current != prepared.Digest {
		return errors.New("reorg worker approval annotation changed")
	} else if current == prepared.Digest {
		if pod.Annotations[reorgBoundaryAnnotation] != string(boundaryJSON) {
			return errors.New("reorg boundary assessment changed after approval")
		}
		return nil
	}
	base := pod.DeepCopy()
	pod.Annotations[reorgApprovalAnnotation] = prepared.Digest
	pod.Annotations[reorgBoundaryAnnotation] = string(boundaryJSON)
	return r.Patch(ctx, pod, client.MergeFrom(base))
}

func (r *V1Beta1Reconciler) captureBurnchainReorgDuring(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, _ *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus) (bool, error) {
	pod, err := r.getBetaMutation(ctx, campaign, nil, status)
	if err != nil || pod == nil {
		return false, err
	}
	workerStatus, err := r.readReorgWorkerStatus(ctx, pod.(*corev1.Pod))
	if err != nil {
		return false, err
	}
	if workerStatus.Result == nil || !workerStatus.Result.CanonicalProven {
		return false, nil
	}
	boundary := burnchain.BoundaryAssessment{}
	workerPod := pod.(*corev1.Pod)
	if err := json.Unmarshal([]byte(workerPod.Annotations[reorgBoundaryAnnotation]), &boundary); err != nil {
		return false, errors.New("reorg worker has no valid approved boundary assessment")
	}
	actual, err := rawAPIJSON(map[string]any{
		"schemaVersion": workerStatus.SchemaVersion, "phase": workerStatus.Phase,
		"preparedDigest":     workerStatus.Result.PreparedDigest,
		"canonicalProven":    workerStatus.Result.CanonicalProven,
		"finalTip":           workerStatus.Result.Final.BestBlockHash,
		"finalHeight":        workerStatus.Result.Final.Blocks,
		"boundaryAssessment": boundary,
		"observedAt":         r.now(),
	})
	if err != nil {
		return false, err
	}
	status.ActualInjection = &actual
	result, err := rawAPIJSON(map[string]any{
		"assertion": "BurnchainReorgProven", "outcome": "Proven", "actor": status.ResolvedTargets[0].Actor,
		"preparedDigest": workerStatus.Result.PreparedDigest, "originalTip": workerStatus.Result.Original.BestBlockHash,
		"replacementTip": workerStatus.Result.Final.BestBlockHash, "originalHeight": workerStatus.Result.Original.Blocks,
		"finalHeight": workerStatus.Result.Final.Blocks, "boundaryAssessment": boundary,
		"observedAt": r.now(), "evidence": workerStatus.Result,
	})
	if err != nil {
		return false, err
	}
	status.EffectResults = []apixv1.JSON{result}
	return true, nil
}

func (r *V1Beta1Reconciler) captureBurnchainReorgRecovery(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, status *attacknetv1beta1.FaultActionStatus) (bool, error) {
	recovered, err := r.burnchainPolicyRecovered(ctx, campaign, status)
	if err != nil || !recovered {
		return false, err
	}
	value, err := rawAPIJSON(map[string]any{"assertion": "BurnchainPolicyRestored", "outcome": "Proven", "observedAt": r.now()})
	if err != nil {
		return false, err
	}
	status.RecoveryResults = []apixv1.JSON{value}
	return true, nil
}

func (r *V1Beta1Reconciler) removeBurnchainReorgWorker(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, status *attacknetv1beta1.FaultActionStatus, pod *corev1.Pod) error {
	if controllerOwnerUID(pod) != string(campaign.UID) {
		return errors.New("refusing to delete a reorg worker not owned by the campaign")
	}
	// An approval token permits mutation at any moment, even if the most recent
	// status observation still says Prepared. Preserve the worker until it has
	// published a terminal result so cancellation cannot strand a partial branch.
	if pod.Annotations[reorgApprovalAnnotation] != "" {
		workerStatus, err := r.readReorgWorkerStatus(ctx, pod)
		if err != nil {
			return fmt.Errorf("%w: terminal status is not observable: %v", errBurnchainReorgWorkerRemovalPending, err)
		}
		if workerStatus.Phase != "Succeeded" && workerStatus.Phase != "Failed" {
			return fmt.Errorf("%w: worker phase is %s", errBurnchainReorgWorkerRemovalPending, workerStatus.Phase)
		}
	}
	if err := client.IgnoreNotFound(r.Delete(ctx, pod)); err != nil {
		return err
	}
	observed := &corev1.Pod{}
	err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(pod), observed)
	if err == nil {
		return errBurnchainReorgWorkerRemovalPending
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	// Restore cadence only after the process capable of mutating Bitcoin is
	// absent. This ordering prevents mining from resuming concurrently with an
	// in-flight replacement or its cleanup path.
	return r.restoreBurnchainPolicy(ctx, campaign, status)
}

func (r *V1Beta1Reconciler) readReorgWorkerStatus(ctx context.Context, pod *corev1.Pod) (burnchainworker.Status, error) {
	if pod.Status.PodIP == "" {
		return burnchainworker.Status{}, errors.New("reorg worker has no Pod IP")
	}
	client := r.ReorgHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s:%d/status", pod.Status.PodIP, reorgWorkerPort), nil)
	if err != nil {
		return burnchainworker.Status{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return burnchainworker.Status{}, err
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, maximumReorgStatusBytes+1))
	if err != nil || len(contents) > maximumReorgStatusBytes || response.StatusCode != http.StatusOK {
		return burnchainworker.Status{}, errors.New("reorg worker status is unavailable or exceeds its bound")
	}
	var status burnchainworker.Status
	if err := json.Unmarshal(contents, &status); err != nil {
		return status, err
	}
	return status, nil
}

func burnchainReorgPodContract(object client.Object) (any, error) {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("BurnchainReorgWorker mutation is %T, want Pod", object)
	}
	annotations := map[string]string{}
	for key, value := range pod.Annotations {
		if key != reorgPreparationAnnotation && key != reorgApprovalAnnotation && key != reorgBoundaryAnnotation {
			annotations[key] = value
		}
	}
	// nodeName is assigned by the Kubernetes scheduler after admission. It is
	// runtime placement evidence, not part of the worker execution contract;
	// retaining it would report every normally scheduled worker as tampered.
	// All user-controlled and admission-defaulted Pod fields remain bound.
	spec := pod.Spec.DeepCopy()
	spec.NodeName = ""
	return map[string]any{"uid": pod.UID, "name": pod.Name, "namespace": pod.Namespace, "labels": pod.Labels, "annotations": annotations, "spec": spec}, nil
}

func betaRecoveryContract(kind string, object client.Object) (*apixv1.JSON, error) {
	if kind != "BurnchainReorgWorker" {
		return nil, nil
	}
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("BurnchainReorgWorker mutation is %T, want Pod", object)
	}
	original, err := strconv.ParseBool(pod.Annotations[reorgOriginalPauseAnnotation])
	if err != nil {
		return nil, errors.New("reorg worker has invalid original pause contract")
	}
	contract := reorgRecoveryContract{
		PolicyName: pod.Annotations[reorgPolicyNameAnnotation], PolicyUID: pod.Annotations[reorgPolicyUIDAnnotation],
		StableSpecDigest: pod.Annotations[reorgPolicySpecAnnotation], OriginalPaused: original,
	}
	value, err := rawAPIJSON(contract)
	return &value, err
}

func (r *V1Beta1Reconciler) restoreBurnchainPolicy(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, status *attacknetv1beta1.FaultActionStatus) error {
	contract, err := recoveryContract(status)
	if err != nil {
		return err
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: contract.PolicyName}, policy); err != nil {
		return err
	}
	if string(policy.UID) != contract.PolicyUID {
		return errors.New("BurnchainPolicy UID changed during reorg")
	}
	return r.restorePolicyObject(ctx, policy, contract.StableSpecDigest, contract.OriginalPaused)
}

func (r *V1Beta1Reconciler) restorePolicyObject(ctx context.Context, policy *attacknetv1beta1.BurnchainPolicy, digest string, paused bool) error {
	stable, err := stableBurnchainPolicyDigest(policy.Spec)
	if err != nil {
		return err
	}
	if stable != digest {
		return errors.New("BurnchainPolicy execution contract changed during reorg")
	}
	if policy.Spec.Paused == paused {
		return nil
	}
	base := policy.DeepCopy()
	policy.Spec.Paused = paused
	return r.Patch(ctx, policy, client.MergeFrom(base))
}

func (r *V1Beta1Reconciler) burnchainPolicyRecovered(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, status *attacknetv1beta1.FaultActionStatus) (bool, error) {
	contract, err := recoveryContract(status)
	if err != nil {
		return false, err
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: contract.PolicyName}, policy); err != nil {
		return false, err
	}
	if string(policy.UID) != contract.PolicyUID {
		return false, errors.New("BurnchainPolicy UID changed during reorg")
	}
	stable, err := stableBurnchainPolicyDigest(policy.Spec)
	if err != nil || stable != contract.StableSpecDigest {
		return false, errors.New("BurnchainPolicy spec changed during reorg")
	}
	return policy.Spec.Paused == contract.OriginalPaused && policy.Status.ObservedGeneration == policy.Generation && policy.Status.Phase == "Ready", nil
}

func recoveryContract(status *attacknetv1beta1.FaultActionStatus) (reorgRecoveryContract, error) {
	if status.Mutation == nil || status.Mutation.RecoveryContract == nil {
		return reorgRecoveryContract{}, errors.New("reorg recovery contract is missing")
	}
	var contract reorgRecoveryContract
	if err := json.Unmarshal(status.Mutation.RecoveryContract.Raw, &contract); err != nil {
		return contract, err
	}
	if contract.PolicyName == "" || contract.PolicyUID == "" || contract.StableSpecDigest == "" {
		return contract, errors.New("reorg recovery contract is incomplete")
	}
	return contract, nil
}

func stableBurnchainPolicyDigest(spec attacknetv1beta1.BurnchainPolicySpec) (string, error) {
	spec.Paused = false
	return canonical.ArtifactDigest(spec)
}

func validateReorgPolicyContract(policy *attacknetv1beta1.BurnchainPolicy, contract reorgRecoveryContract) error {
	if string(policy.UID) != contract.PolicyUID {
		return errors.New("BurnchainPolicy UID changed during reorg")
	}
	digest, err := stableBurnchainPolicyDigest(policy.Spec)
	if err != nil {
		return err
	}
	if digest != contract.StableSpecDigest {
		return errors.New("BurnchainPolicy execution contract changed during reorg")
	}
	return nil
}

func actionSpecReorg(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string) *attacknetv1beta1.BurnchainReorgFaultSpec {
	for stageIndex := range campaign.Spec.Stages {
		if campaign.Spec.Stages[stageIndex].ID != stageID {
			continue
		}
		for actionIndex := range campaign.Spec.Stages[stageIndex].Faults {
			action := &campaign.Spec.Stages[stageIndex].Faults[actionIndex]
			if action.ID == actionID {
				return action.Fault.BurnchainReorg
			}
		}
	}
	return nil
}

func protocolSchedule(value *attacknetv1beta1.BurnchainProtocolSchedule) *burnchain.ProtocolSchedule {
	if value == nil {
		return nil
	}
	result := &burnchain.ProtocolSchedule{}
	for _, epoch := range value.Epochs {
		result.Epochs = append(result.Epochs, burnchain.EpochBoundary{Name: epoch.Name, StartHeight: epoch.StartHeight})
	}
	if value.RewardCycle != nil {
		result.RewardCycle = &burnchain.RewardSchedule{FirstHeight: value.RewardCycle.FirstHeight, CycleLength: value.RewardCycle.CycleLength, PrepareLength: value.RewardCycle.PrepareLength}
	}
	return result
}

func validateReorgBoundarySafety(assessment burnchain.BoundaryAssessment, safety attacknetv1beta1.FaultSafety) error {
	if !assessment.Known {
		if !safety.AllowEpochBoundaryCrossing || !safety.AllowRewardCycleBoundaryCrossing {
			return errors.New("unknown protocol schedule requires explicit epoch and reward-cycle boundary opt-ins")
		}
		return nil
	}
	if assessment.CrossesEpoch && !safety.AllowEpochBoundaryCrossing {
		return fmt.Errorf("reorg crosses epoch boundaries %v without opt-in", assessment.EpochBoundaries)
	}
	if (assessment.CrossesRewardCycle || assessment.CrossesRewardPreparePhase) && !safety.AllowRewardCycleBoundaryCrossing {
		return errors.New("reorg crosses a reward-cycle or prepare-phase boundary without opt-in")
	}
	return nil
}

func bitcoinEndpoint(network *attacknetv1beta1.StacksNetwork, actor string) (string, int32, error) {
	service := ""
	for _, status := range network.Status.Actors {
		if status.Name == actor {
			service = status.ServiceName
			break
		}
	}
	port := int32(18443)
	for _, node := range network.Spec.Burnchain.Nodes {
		if node.Name == actor {
			if node.RPCPort > 0 {
				port = node.RPCPort
			}
			break
		}
	}
	if service == "" {
		return "", 0, fmt.Errorf("Bitcoin actor %s has no admitted service", actor)
	}
	return service, port, nil
}

func secretEnvSource(reference *attacknetv1beta1.SecretKeyReference) *corev1.EnvVarSource {
	return &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: reference.Name}, Key: reference.Key}}
}
