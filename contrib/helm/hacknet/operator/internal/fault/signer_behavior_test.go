package fault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/probeattribution"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
)

type signedBehaviorProbe struct {
	private     ed25519.PrivateKey
	publicDER   []byte
	now         time.Time
	evaluations int64
	matches     int64
	active      bool
	policy      string
	padding     string
}

func newSignedBehaviorProbe(t *testing.T, now time.Time, policy string) *signedBehaviorProbe {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return &signedBehaviorProbe{private: private, publicDER: publicDER, now: now, policy: policy}
}

func (probe *signedBehaviorProbe) Probe(_ context.Context, target attacknetv1alpha1.ResolvedTarget, request map[string]any) (map[string]any, error) {
	nonce, _ := request["nonce"].(string)
	behavior, _ := request["behavior"].(string)
	peer, _ := request["peer"].(string)
	payload := map[string]any{
		"schemaVersion": probeattribution.ResponseSchema,
		"actor":         target.Actor,
		"kind":          "signerBehavior",
		"nonce":         nonce,
		"observedAt":    probe.now.Format(time.RFC3339Nano),
		"targetActor":   peer,
		"policyDigest":  probe.policy,
		"observation": map[string]any{
			"actor": target.Actor, "probe": "signer-behavior", "status": "ok",
			"targetActor": peer, "behavior": behavior, "policyMatches": probe.matches,
			"policyEvaluations": probe.evaluations,
			"sessionActive":     probe.active,
			"contentTrust":      "actor-self-reported", "sampleWindowMs": 1, "padding": probe.padding,
		},
	}
	signed, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	keyDigest := sha256.Sum256(probe.publicDER)
	payload["attestation"] = map[string]any{
		"schemaVersion": probeattribution.AttestationSchema,
		"algorithm":     "Ed25519",
		"keyId":         "sha256:" + hex.EncodeToString(keyDigest[:]),
		"publicKey":     base64.StdEncoding.EncodeToString(probe.publicDER),
		"signedPayload": base64.StdEncoding.EncodeToString(signed),
		"signature":     base64.StdEncoding.EncodeToString(ed25519.Sign(probe.private, signed)),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal(encoded, &result)
	return result, err
}

func TestSignedBehaviorObservationBindsLiveTargetAndStableObserverKey(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	scheme := betaFaultScheme(t)
	network, campaign, target, objects := adversarialObservationFixture(t)
	direct := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	spec := &campaign.Spec.Stages[0].Faults[0]
	probe := newSignedBehaviorProbe(t, now, spec.Fault.SignerBehavior.PolicyDigest)
	reconciler := &V1Beta1Reconciler{APIReader: direct, Probes: probe, Now: func() time.Time { return now }}

	baseline, err := reconciler.captureSignerBehavior(context.Background(), campaign, network, spec, target, "")
	if err != nil {
		t.Fatal(err)
	}
	probe.matches++
	probe.evaluations++
	probe.active = true
	during, err := reconciler.captureSignerBehavior(context.Background(), campaign, network, spec, target, baseline.KeyID)
	if err != nil || during.Matches != 1 || during.KeyID != baseline.KeyID {
		t.Fatalf("signed observation did not preserve its identity and counter: sample=%#v err=%v", during, err)
	}

	reconciler.Probes = newSignedBehaviorProbe(t, now, spec.Fault.SignerBehavior.PolicyDigest)
	if _, err := reconciler.captureSignerBehavior(context.Background(), campaign, network, spec, target, baseline.KeyID); err == nil || !strings.Contains(err.Error(), "public-key identity") {
		t.Fatalf("observer key replacement was not rejected: %v", err)
	}

	replacementObjects := append([]client.Object(nil), objects...)
	for index, object := range replacementObjects {
		pod, ok := object.(*corev1.Pod)
		if ok && pod.Labels[ActorLabel] == "signer-1" {
			replacement := pod.DeepCopy()
			replacement.UID = "replacement-signer-pod-uid"
			replacementObjects[index] = replacement
		}
	}
	reconciler.APIReader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(replacementObjects...).Build()
	if _, err := reconciler.captureSignerBehavior(context.Background(), campaign, network, spec, target, ""); err == nil || !strings.Contains(err.Error(), "live actor identity diverged") {
		t.Fatalf("uncached target Pod replacement was not rejected: %v", err)
	}

	reconciler.APIReader = direct
	reconciler.Probes = probe
	probe.padding = strings.Repeat("x", maximumSignerBehaviorReportBytes)
	if _, err := reconciler.captureSignerBehavior(context.Background(), campaign, network, spec, target, ""); err == nil || !strings.Contains(err.Error(), "report exceeds") {
		t.Fatalf("unbounded signed report was accepted: %v", err)
	}
}

func TestSignerBehaviorSessionActivatesAndRecoversOneIdentityBoundPod(t *testing.T) {
	scheme := betaFaultScheme(t)
	_, campaign, target, objects := adversarialObservationFixture(t)
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	reconciler := &V1Beta1Reconciler{Client: base, APIReader: base}
	spec := &campaign.Spec.Stages[0].Faults[0]
	resolved := attacknetv1beta1.ResolvedTarget{
		Actor: target.Actor, Role: target.Role, Pod: target.Pod, PodUID: target.PodUID,
		PodIP: target.PodIP, Node: target.Node, RequestedImage: target.RequestedImage,
		ResolvedImageID: target.ResolvedImageID,
	}
	status := &attacknetv1beta1.FaultActionStatus{ID: spec.ID, ResolvedTargets: []attacknetv1beta1.ResolvedTarget{resolved}}
	action := CompiledAction{ID: spec.ID, Resource: &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"action": spec.Fault.Action, "actors": []any{target.Actor},
			"policyDigest": spec.Fault.SignerBehavior.PolicyDigest,
		},
	}}}

	pod, err := reconciler.activateSignerBehaviorSession(context.Background(), campaign, action, status)
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := signerBehaviorSessionMatches(pod.Annotations[adversarial.SessionAnnotation], campaign, spec, status); err != nil || !matches {
		t.Fatalf("admitted session does not bind the campaign action: matches=%t err=%v", matches, err)
	}
	contract, err := betaMutationContract("SignerBehaviorSession", pod, status)
	if err != nil {
		t.Fatal(err)
	}
	resourceDigest, err := canonical.ArtifactDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	status.Mutation = &attacknetv1beta1.ChaosReference{
		Kind: "SignerBehaviorSession", Name: pod.Name, UID: string(pod.UID), ResourceDigest: resourceDigest,
	}
	if injected, err := reconciler.betaMutationInjected(context.Background(), campaign, spec, status); err != nil || !injected {
		t.Fatalf("session mutation was not observed: injected=%t err=%v", injected, err)
	}

	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	reconciler.Now = func() time.Time { return now }
	injectedAt := metav1.NewTime(now.Add(-spec.Fault.Duration.Duration))
	status.Mutation.InjectedAt = &injectedAt
	status.Phase = "Active"
	stage := &attacknetv1beta1.FaultStageStatus{
		ID: "stage", Phase: "Active", Actions: []attacknetv1beta1.FaultActionStatus{*status.DeepCopy()},
	}
	compiled := &CompiledStage{ID: "stage", Actions: []CompiledAction{action}}
	if err := reconciler.advanceBetaStage(context.Background(), campaign, nil, nil, compiled, stage, &campaign.Status); err != nil {
		t.Fatal(err)
	}
	if stage.Actions[0].Phase != "Recovering" {
		t.Fatalf("duration boundary did not persist recovery before mutation removal: %#v", stage.Actions[0])
	}
	current := &corev1.Pod{}
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: campaign.Namespace, Name: target.Pod}, current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[adversarial.SessionAnnotation] == "" {
		t.Fatal("session annotation was removed before recovery status became durable")
	}
	if err := reconciler.advanceBetaStage(context.Background(), campaign, nil, nil, compiled, stage, &campaign.Status); err != nil {
		t.Fatal(err)
	}
	if recovered, err := reconciler.betaMutationRecovered(context.Background(), campaign, spec, &stage.Actions[0]); err != nil || !recovered {
		t.Fatalf("session mutation did not recover: recovered=%t err=%v", recovered, err)
	}
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: campaign.Namespace, Name: target.Pod}, current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[adversarial.SessionAnnotation] != "" {
		t.Fatalf("session annotation survived recovery: %#v", current.Annotations)
	}
	activeAfterRemoval := stage.Actions[0].DeepCopy()
	activeAfterRemoval.Phase = "Active"
	if _, err := reconciler.betaMutationRecovered(context.Background(), campaign, spec, activeAfterRemoval); err == nil || !strings.Contains(err.Error(), "execution contract changed") {
		t.Fatalf("active session accepted an externally removed annotation: %v", err)
	}
	timedOut := stage.Actions[0].DeepCopy()
	timedOut.Phase = "Inconclusive"
	if err := reconciler.removeBetaMutation(context.Background(), campaign, spec, timedOut); err != nil {
		t.Fatalf("terminal cleanup was not idempotent after session recovery: %v", err)
	}
}

func adversarialObservationFixture(t *testing.T) (*attacknetv1beta1.StacksNetwork, *attacknetv1beta1.FaultCampaign, attacknetv1alpha1.ResolvedTarget, []client.Object) {
	t.Helper()
	everyNth := int32(2)
	policy := &attacknetv1beta1.AdversarialSignerPolicy{
		Profile: "stacks-signer-testing/v1", Behavior: "withhold", MaxMatches: 2, MaxEvaluations: 16,
		PatchDigest: "sha256:" + strings.Repeat("b", 64),
		Selector:    attacknetv1beta1.AdversarialProposalSelector{EveryNth: &everyNth},
		Observer:    attacknetv1beta1.AdversarialObserverSpec{Image: "probe:test"},
		Egress:      attacknetv1beta1.AdversarialEgressSpec{Profile: "restricted"},
	}
	normalized, err := adversarial.Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := adversarial.Digest(normalized)
	if err != nil {
		t.Fatal(err)
	}
	behaviorNetwork := &attacknetv1beta1.StacksNetwork{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork"},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid"), Generation: 1},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Defaults:   attacknetv1beta1.NetworkDefaults{NodeImage: "node:test", SignerImage: "signer:test", BitcoinImage: "bitcoin:test", DependencyImage: "busybox:test"},
			Burnchain:  attacknetv1beta1.BurnchainTopologySpec{PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "clock"}, Nodes: []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin-1", Config: betaConfig("bitcoin")}}},
			SignerSets: []attacknetv1beta1.SignerSetSpec{{Name: "set", Members: []attacknetv1beta1.SignerMemberSpec{{Name: "signer-1", NodeName: "signer-node-1", Index: 1, Weight: 1, BurnchainNodeRef: "bitcoin-1", SignerImage: "signer:testing", SignerConfig: betaConfig("signer"), NodeConfig: betaConfig("node"), Adversarial: policy}}}},
		},
	}
	compiled, err := topology.CompileV1Beta1(behaviorNetwork)
	if err != nil {
		t.Fatal(err)
	}
	statuses := make([]attacknetv1beta1.ActorStatus, 0, len(compiled.Spec.Actors))
	legacyStatuses := make([]attacknetv1alpha1.ActorStatus, 0, len(compiled.Spec.Actors))
	objects := make([]client.Object, 0, len(compiled.Spec.Actors)+1)
	var target attacknetv1alpha1.ResolvedTarget
	for index, actor := range compiled.Spec.Actors {
		image := actor.Image
		if image == "" {
			switch actor.Role {
			case "burnchain":
				image = "bitcoin:test"
			case "signer":
				image = "signer:test"
			default:
				image = "node:test"
			}
		}
		imageID := fmt.Sprintf("containerd://sha256:%064x", index+1)
		resourceName := "network-" + actor.Name
		podName := resourceName + "-0"
		podUID := actor.Name + "-pod-uid"
		egressDigest := ""
		if actor.AdversarialEgressProfile == "restricted" {
			egressDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}
		status := attacknetv1beta1.ActorStatus{Name: actor.Name, Role: actor.Role, ResourceName: resourceName, Image: image, Ready: true, ServiceName: resourceName, StatefulSetUID: actor.Name + "-stateful-uid", CurrentRevision: actor.Name + "-revision", PodName: podName, PodUID: podUID, RuntimeImageID: imageID, AdversarialPolicyDigest: actor.AdversarialPolicyDigest, AdversarialEgressProfile: actor.AdversarialEgressProfile, EgressPolicyDigest: egressDigest, IdentityReady: true}
		statuses = append(statuses, status)
		legacyStatuses = append(legacyStatuses, attacknetv1alpha1.ActorStatus{Name: status.Name, Role: status.Role, ResourceName: status.ResourceName, Image: status.Image, Ready: true, ServiceName: status.ServiceName, StatefulSetUID: status.StatefulSetUID, CurrentRevision: status.CurrentRevision, PodName: status.PodName, PodUID: status.PodUID, RuntimeImageID: status.RuntimeImageID, AdversarialPolicyDigest: status.AdversarialPolicyDigest, AdversarialEgressProfile: status.AdversarialEgressProfile, EgressPolicyDigest: status.EgressPolicyDigest, IdentityReady: true})
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: "test", UID: types.UID(podUID), Labels: map[string]string{NetworkLabel: "network", ActorLabel: actor.Name, RoleLabel: actor.Role}}, Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "actor", Image: image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: fmt.Sprintf("10.0.0.%d", index+1), Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", Ready: true, ImageID: imageID}}}}
		objects = append(objects, pod)
		if actor.Name == "signer-1" {
			resolvedImage := imageID
			requestedImage := image
			target = attacknetv1alpha1.ResolvedTarget{Actor: actor.Name, Role: actor.Role, Pod: podName, PodUID: podUID, PodIP: pod.Status.PodIP, Node: "node-a", RequestedImage: &requestedImage, ResolvedImageID: &resolvedImage}
		}
	}
	behaviorNetwork.Status = attacknetv1beta1.StacksNetworkStatus{ObservedGeneration: 1, Phase: "Ready", InventoryReady: true, Actors: statuses}
	legacy := &attacknetv1alpha1.StacksNetwork{ObjectMeta: *behaviorNetwork.ObjectMeta.DeepCopy(), Spec: compiled.Spec, Status: attacknetv1alpha1.StacksNetworkStatus{ObservedGeneration: 1, InventoryReady: true, Actors: legacyStatuses}}
	payload, err := inventory.Build(legacy)
	if err != nil {
		t.Fatal(err)
	}
	behaviorNetwork.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	behaviorNetwork.Status.BurnchainTopology, err = burnchaintopology.Build(behaviorNetwork, map[string]string{"clock": "clock-uid"})
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("adversarial signer digest was not compiled")
	}
	campaign := betaFaultCampaign("behavior", []attacknetv1beta1.FaultActionSpec{{ID: "withhold", Target: attacknetv1beta1.FaultTarget{Actors: []string{"signer-1"}, Mode: "all"}, Fault: attacknetv1beta1.FaultSpec{Type: "signer-behavior", Action: "withhold", Mode: "all", Duration: metav1.Duration{Duration: 30 * time.Second}, SignerBehavior: &attacknetv1beta1.SignerBehaviorFaultSpec{PolicyDigest: digest}}}})
	objects = append(objects, behaviorNetwork)
	return behaviorNetwork, campaign, target, objects
}
