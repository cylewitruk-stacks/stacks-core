package signerset

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestResolveRequiresExactCanonicalSignerSet(t *testing.T) {
	indexOne, indexTwo := int32(1), int32(2)
	declaredOne, declaredTwo := 4.0, 6.0
	keyOne := "02" + repeat("1", 64)
	keyTwo := "03" + repeat("2", 64)
	actors := []attacknetv1alpha1.ActorSpec{
		{Name: "signer-1", SignerIndex: &indexOne, SignerWeight: &declaredOne, SignerPublicKey: keyOne},
		{Name: "node-1", SignerIndex: &indexOne, SignerWeight: &declaredOne, SignerPublicKey: keyOne},
		{Name: "signer-2", SignerIndex: &indexTwo, SignerWeight: &declaredTwo, SignerPublicKey: keyTwo},
	}
	result, err := Resolve(actors, []ObservedSigner{{SigningKey: keyTwo, Weight: 7}, {SigningKey: keyOne, Weight: 3}}, 42, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.CanonicalThreshold != 7 || result.ObservedTotalWeight != 10 || result.WeightsMatch {
		t.Fatalf("unexpected signer-set result: %#v", result)
	}
	if result.WeightsByActor["node-1"] != 3 || result.WeightsByActor["signer-2"] != 7 {
		t.Fatalf("canonical weights were not projected to actors: %#v", result.WeightsByActor)
	}
	if _, err := Resolve(actors, []ObservedSigner{{SigningKey: keyOne, Weight: 10}}, 42, "node-1"); err == nil {
		t.Fatal("missing canonical signer identity was accepted")
	}
}

func TestResolveRejectsFractionalWeightsAndDuplicateIndexes(t *testing.T) {
	index := int32(1)
	weight := 10.0
	key := "02" + repeat("1", 64)
	actors := []attacknetv1alpha1.ActorSpec{{Name: "signer-1", SignerIndex: &index, SignerWeight: &weight, SignerPublicKey: key}}
	if _, err := Resolve(actors, []ObservedSigner{{SigningKey: key, Weight: 9.5}}, 1, "node"); err == nil {
		t.Fatal("fractional signer weight was accepted")
	}
	if _, err := Resolve(actors, []ObservedSigner{{SigningKey: key, Weight: maxJSONSafeInteger + 1}}, 1, "node"); err == nil {
		t.Fatal("JSON-unsafe signer weight was accepted")
	}
	indexTwo := int32(2)
	keyTwo := "03" + repeat("2", 64)
	actors = append(actors, attacknetv1alpha1.ActorSpec{Name: "signer-2", SignerIndex: &indexTwo, SignerWeight: &weight, SignerPublicKey: keyTwo})
	if _, err := Resolve(actors, []ObservedSigner{{SigningKey: key, Weight: maxJSONSafeInteger}, {SigningKey: keyTwo, Weight: 1}}, 1, "node"); err == nil {
		t.Fatal("JSON-unsafe aggregate signer weight was accepted")
	}
}

func TestHTTPResolverDoesNotQueryRPCForNetworkWithoutSigners(t *testing.T) {
	resolver := &HTTPResolver{}
	network := &attacknetv1alpha1.StacksNetwork{Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{
		{Name: "miner-1", Role: "miner"},
		{Name: "follower-1", Role: "follower"},
	}}}
	result, err := resolver.Resolve(t.Context(), network, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasSigners || result.SignerSetDigest == "" || result.ObservedFrom != "network-spec:no-signers" || !result.WeightsMatch {
		t.Fatalf("unexpected empty signer-set result: %#v", result)
	}
	if len(result.WeightsByActor) != 0 {
		t.Fatalf("zero-signer network received weights: %#v", result.WeightsByActor)
	}
}

func TestPartialSignerBindingCannotUseZeroSignerFastPath(t *testing.T) {
	weight := 10.0
	for _, actor := range []attacknetv1alpha1.ActorSpec{
		{Name: "signer-1", Role: "signer"},
		{Name: "node-1", Role: "follower", SignerWeight: &weight},
		{Name: "node-1", Role: "follower", SignerPublicKey: "02" + repeat("1", 64)},
	} {
		network := &attacknetv1alpha1.StacksNetwork{Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{actor}}}
		if _, err := (&HTTPResolver{}).Resolve(t.Context(), network, nil); err == nil {
			t.Fatalf("partial signer binding used zero-signer fast path: %#v", actor)
		}
	}
}

func TestEndpointUsesTheTopologyDefaultRPCPort(t *testing.T) {
	network := &attacknetv1alpha1.StacksNetwork{Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{{Name: "node-1", Role: "follower"}}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "node-1-0", UID: types.UID("pod-1"), Labels: map[string]string{actorLabel: "node-1"}}, Status: corev1.PodStatus{PodIP: "10.0.0.2", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	actor, _, port, err := endpoint(network, []corev1.Pod{pod})
	if err != nil {
		t.Fatal(err)
	}
	if actor.Name != "node-1" || port != 20443 {
		t.Fatalf("unexpected default RPC endpoint: actor=%s port=%d", actor.Name, port)
	}
}

func repeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
