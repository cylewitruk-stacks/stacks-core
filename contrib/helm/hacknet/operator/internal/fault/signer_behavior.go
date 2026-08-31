package fault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/probeattribution"
)

type signerBehaviorSample struct {
	KeyID         string
	Evaluations   int64
	Matches       int64
	SessionActive bool
	PayloadDigest string
	Raw           string
}

type signerBehaviorSessionDocument struct {
	Action        string `json:"action"`
	Actor         string `json:"actor"`
	CampaignUID   string `json:"campaignUid"`
	PolicyDigest  string `json:"policyDigest"`
	SchemaVersion string `json:"schemaVersion"`
}

const maximumSignerBehaviorReportBytes = 4 * 1024

func (r *V1Beta1Reconciler) signerBehaviorCapabilities(ctx context.Context, network *attacknetv1beta1.StacksNetwork, request *attacknetv1beta1.FaultActionSpec, targets []attacknetv1alpha1.ResolvedTarget) ([]capabilityObservation, error) {
	if request == nil || request.Fault.SignerBehavior == nil {
		return nil, errors.New("signer-behavior action is missing its typed request")
	}
	result := make([]capabilityObservation, 0, len(targets))
	for _, target := range targets {
		observation := capabilityObservation{Actor: target.Actor, PodUID: target.PodUID, Source: "attacknet-run-operator/v1", ObservedAt: r.now().Format(time.RFC3339Nano), Platform: "testing-signer-policy", Architecture: "signed-external-observer"}
		status := betaActorStatus(network, target.Actor)
		observer := betaActorStatus(network, adversarial.ObserverName(target.Actor))
		policy, digest, policyErr := adversarial.ResolveSigner(network, target.Actor)
		observation.Supported = policyErr == nil && policy.Behavior == request.Fault.Action && digest == request.Fault.SignerBehavior.PolicyDigest && status != nil && status.IdentityReady && status.AdversarialPolicyDigest == digest && observer != nil && observer.IdentityReady && observer.AdversarialPolicyDigest == digest
		observation.Reason = "target and isolated observer identities carry the requested policy digest"
		if !observation.Supported {
			observation.Reason = "target policy action, digest, or isolated observer identity does not match the request"
			if policyErr != nil {
				observation.Reason = policyErr.Error()
			}
		}
		result = append(result, observation)
	}
	return result, nil
}

func betaActorStatus(network *attacknetv1beta1.StacksNetwork, name string) *attacknetv1beta1.ActorStatus {
	for index := range network.Status.Actors {
		if network.Status.Actors[index].Name == name {
			return &network.Status.Actors[index]
		}
	}
	return nil
}

func (r *V1Beta1Reconciler) captureSignerBehavior(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, spec *attacknetv1beta1.FaultActionSpec, target attacknetv1alpha1.ResolvedTarget, expectedKeyID string) (signerBehaviorSample, error) {
	if r.APIReader == nil {
		return signerBehaviorSample{}, errors.New("signer-behavior observation requires an uncached API reader")
	}
	view, err := inventory.ReadBetaLiveView(ctx, r.APIReader, client.ObjectKeyFromObject(network))
	if err != nil {
		return signerBehaviorSample{}, err
	}
	liveNetwork := view.Network
	if liveNetwork.UID != network.UID || liveNetwork.Status.InventoryDigest == "" || liveNetwork.Status.InventoryDigest != network.Status.InventoryDigest {
		return signerBehaviorSample{}, errors.New("network identity changed before signed observation")
	}
	expected, err := inventory.BetaPublished(network)
	if err != nil {
		return signerBehaviorSample{}, fmt.Errorf("verify admitted signer-behavior inventory: %w", err)
	}
	if campaign.Status.Admission != nil {
		expected = campaign.Status.Admission.NetworkInventory
	}
	if differences := inventory.BetaCompareLive(expected, liveNetwork, view.Pods, nil); len(differences) != 0 {
		return signerBehaviorSample{}, fmt.Errorf("live actor identity diverged before signed observation (%d difference(s)); first: %s", len(differences), differences[0].Message)
	}
	targetStatus := betaActorStatus(liveNetwork, target.Actor)
	if targetStatus == nil || !targetStatus.IdentityReady || targetStatus.PodUID != target.PodUID || targetStatus.AdversarialPolicyDigest != spec.Fault.SignerBehavior.PolicyDigest {
		return signerBehaviorSample{}, errors.New("target live identity does not match the admitted adversarial policy")
	}
	observerName := adversarial.ObserverName(target.Actor)
	observerStatus := betaActorStatus(liveNetwork, observerName)
	if observerStatus == nil || !observerStatus.IdentityReady || observerStatus.AdversarialPolicyDigest != spec.Fault.SignerBehavior.PolicyDigest {
		return signerBehaviorSample{}, fmt.Errorf("observer %s is not admitted for policy %s", observerName, spec.Fault.SignerBehavior.PolicyDigest)
	}
	observerPods := make([]corev1.Pod, 0, 1)
	for _, pod := range view.Pods {
		if pod.Labels[ActorLabel] == observerName {
			observerPods = append(observerPods, pod)
		}
	}
	if len(observerPods) != 1 || string(observerPods[0].UID) != observerStatus.PodUID || !podIsReady(observerPods[0]) {
		return signerBehaviorSample{}, errors.New("observer live Pod identity is not singular and Ready")
	}
	observerPod := observerPods[0]
	observer := attacknetv1alpha1.ResolvedTarget{Actor: observerName, Role: "observer", Pod: observerPod.Name, PodUID: string(observerPod.UID), PodIP: observerPod.Status.PodIP, Node: observerPod.Spec.NodeName}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return signerBehaviorSample{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	probe := r.Probes
	if probe == nil {
		probe = HTTPProbeClient{}
	}
	started := r.now().Add(-time.Second)
	response, err := probe.Probe(ctx, observer, map[string]any{"kind": "signerBehavior", "peer": target.Actor, "port": "metrics", "behavior": spec.Fault.Action, "nonce": nonce})
	if err != nil {
		return signerBehaviorSample{}, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return signerBehaviorSample{}, err
	}
	if len(encoded) > maximumSignerBehaviorReportBytes {
		return signerBehaviorSample{}, fmt.Errorf("signed signer-behavior report exceeds %d bytes", maximumSignerBehaviorReportBytes)
	}
	verified, err := probeattribution.Verify(encoded, probeattribution.Expectation{Actor: observerName, TargetActor: target.Actor, PolicyDigest: spec.Fault.SignerBehavior.PolicyDigest, Nonce: nonce, KeyID: expectedKeyID, NotBefore: started, NotAfter: r.now().Add(time.Second)})
	if err != nil {
		return signerBehaviorSample{}, err
	}
	var observation struct {
		Probe             string `json:"probe"`
		TargetActor       string `json:"targetActor"`
		Behavior          string `json:"behavior"`
		PolicyMatches     int64  `json:"policyMatches"`
		PolicyEvaluations int64  `json:"policyEvaluations"`
		SessionActive     bool   `json:"sessionActive"`
		ContentTrust      string `json:"contentTrust"`
	}
	if err := json.Unmarshal(verified.Response.Observation, &observation); err != nil {
		return signerBehaviorSample{}, err
	}
	if observation.Probe != "signer-behavior" || observation.TargetActor != target.Actor || observation.Behavior != spec.Fault.Action || observation.PolicyMatches < 0 || observation.PolicyEvaluations < observation.PolicyMatches || observation.ContentTrust != "actor-self-reported" {
		return signerBehaviorSample{}, errors.New("signed signer-behavior observation has an invalid content contract")
	}
	return signerBehaviorSample{KeyID: verified.Response.Attestation.KeyID, Evaluations: observation.PolicyEvaluations, Matches: observation.PolicyMatches, SessionActive: observation.SessionActive, PayloadDigest: verified.PayloadDigest, Raw: string(encoded)}, nil
}

func signerBehaviorResult(assertion, outcome, actor, reason string, sample signerBehaviorSample, observedAt time.Time) apixv1.JSON {
	value, _ := json.Marshal(map[string]any{"assertion": assertion, "outcome": outcome, "actor": actor, "reason": reason, "observerKeyId": sample.KeyID, "reportDigest": sample.PayloadDigest, "policyEvaluations": sample.Evaluations, "policyMatches": sample.Matches, "sessionActive": sample.SessionActive, "observedAt": observedAt})
	return apixv1.JSON{Raw: value}
}

func signerBehaviorArtifactKey(stageID, actionID, phase, actor string) string {
	return stageID + "/" + actionID + "/" + phase + "/" + actor + "SignedJson"
}

func decodeSignerBehaviorSample(raw string) (signerBehaviorSample, error) {
	var response probeattribution.Response
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		return signerBehaviorSample{}, err
	}
	var observation struct {
		PolicyEvaluations int64 `json:"policyEvaluations"`
		PolicyMatches     int64 `json:"policyMatches"`
		SessionActive     bool  `json:"sessionActive"`
	}
	if err := json.Unmarshal(response.Observation, &observation); err != nil {
		return signerBehaviorSample{}, err
	}
	return signerBehaviorSample{KeyID: response.Attestation.KeyID, Evaluations: observation.PolicyEvaluations, Matches: observation.PolicyMatches, SessionActive: observation.SessionActive, Raw: raw}, nil
}

func (r *V1Beta1Reconciler) captureSignerBehaviorDuring(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, stageID string, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus, campaignStatus *attacknetv1beta1.FaultCampaignStatus) (bool, error) {
	status.EffectResults = nil
	proven := 0
	for _, target := range legacyTargets(status.ResolvedTargets) {
		baselineRaw := campaignStatus.ProbeArtifacts[signerBehaviorArtifactKey(stageID, status.ID, "before", target.Actor)]
		baseline, err := decodeSignerBehaviorSample(baselineRaw)
		if err != nil {
			return false, fmt.Errorf("decode signer-behavior baseline for %s: %w", target.Actor, err)
		}
		sample, err := r.captureSignerBehavior(ctx, campaign, network, spec, target, baseline.KeyID)
		if err != nil {
			return false, err
		}
		campaignStatus.ProbeArtifacts[signerBehaviorArtifactKey(stageID, status.ID, "during", target.Actor)] = sample.Raw
		outcome, reason := "Inconclusive", "signed observer report contains no new policy match"
		if sample.SessionActive && sample.Matches > baseline.Matches {
			outcome, reason = "Proven", "signed observer report records a bounded policy-match increase"
			proven++
		}
		status.EffectResults = append(status.EffectResults, signerBehaviorResult("SignerBehaviorObserved", outcome, target.Actor, reason, sample, r.now()))
	}
	return proven == len(status.ResolvedTargets) && assertionsSatisfied(betaAssertionsToAlpha(betaScopedAssertions(campaign, stageID, status.ID, true)), status.EffectResults), nil
}

func (r *V1Beta1Reconciler) captureSignerBehaviorRecovery(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork, stageID string, spec *attacknetv1beta1.FaultActionSpec, status *attacknetv1beta1.FaultActionStatus, campaignStatus *attacknetv1beta1.FaultCampaignStatus) (bool, error) {
	status.RecoveryResults = nil
	for _, target := range legacyTargets(status.ResolvedTargets) {
		duringRaw := campaignStatus.ProbeArtifacts[signerBehaviorArtifactKey(stageID, status.ID, "during", target.Actor)]
		during, err := decodeSignerBehaviorSample(duringRaw)
		if err != nil {
			return false, err
		}
		sample, err := r.captureSignerBehavior(ctx, campaign, network, spec, target, during.KeyID)
		if err != nil {
			return false, err
		}
		if sample.Matches < during.Matches || sample.Evaluations < during.Evaluations {
			return false, errors.New("signer-behavior counters regressed across the observation window")
		}
		campaignStatus.ProbeArtifacts[signerBehaviorArtifactKey(stageID, status.ID, "after", target.Actor)] = sample.Raw
		outcome, reason := "Inconclusive", "signer still reports an active behavior session"
		if !sample.SessionActive {
			outcome, reason = "Proven", "signer reports the session closed and observer identity remained stable"
		}
		status.RecoveryResults = append(status.RecoveryResults, signerBehaviorResult("SignerBehaviorWindowClosed", outcome, target.Actor, reason, sample, r.now()))
	}
	return assertionsSatisfied(betaAssertionsToAlpha(betaScopedAssertions(campaign, stageID, status.ID, true)), status.EffectResults) && assertionsSatisfied(betaAssertionsToAlpha(betaScopedAssertions(campaign, stageID, status.ID, false)), status.RecoveryResults), nil
}

func betaAssertionsToAlpha(values []attacknetv1beta1.CampaignAssertion) []attacknetv1alpha1.CampaignAssertion {
	result := make([]attacknetv1alpha1.CampaignAssertion, len(values))
	for index, value := range values {
		result[index] = attacknetv1alpha1.CampaignAssertion{Type: value.Type, Actor: value.Actor, TimeoutSeconds: value.TimeoutSeconds}
	}
	return result
}
