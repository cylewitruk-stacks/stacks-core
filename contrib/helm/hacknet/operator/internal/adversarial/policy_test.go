package adversarial

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const testPatchDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testPolicy() *attacknetv1beta1.AdversarialSignerPolicy {
	every := int32(3)
	minimum, maximum := int64(10), int64(20)
	return &attacknetv1beta1.AdversarialSignerPolicy{
		Profile: ProfileV1, Behavior: "withhold", MaxMatches: 4, MaxEvaluations: 32,
		PatchDigest: testPatchDigest,
		Selector: attacknetv1beta1.AdversarialProposalSelector{
			EveryNth: &every, SeedOffset: 1, MinStacksHeight: &minimum,
			MaxStacksHeight: &maximum, ProposalHashPrefix: "ab",
		},
		Observer: attacknetv1beta1.AdversarialObserverSpec{Image: "probe:test"},
		Egress:   attacknetv1beta1.AdversarialEgressSpec{Profile: "restricted"},
	}
}

func TestNormalizeAndDigestAreDeterministic(t *testing.T) {
	first, err := Normalize(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Normalize(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := Digest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := Digest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("policy digest changed: %s != %s", firstDigest, secondDigest)
	}
	encoded, err := Encode(first)
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" || first.Algorithm != AlgorithmV1 {
		t.Fatalf("policy was not normalized: %#v", first)
	}
}

func TestNormalizeRejectsUnsafeOrAmbiguousPolicies(t *testing.T) {
	tests := []struct {
		name string
		edit func(*attacknetv1beta1.AdversarialSignerPolicy)
	}{
		{"unknown profile", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.Profile = "future" }},
		{"unbounded matches", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.MaxMatches = 0 }},
		{"evaluations below matches", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.MaxEvaluations = 3 }},
		{"unrestricted without opt in", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.Egress.Profile = "unrestricted" }},
		{"offset without modulus", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.Selector.EveryNth = nil }},
		{"delay absent", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.Behavior = "delay" }},
		{"peer suppression height", func(value *attacknetv1beta1.AdversarialSignerPolicy) { value.Behavior = "suppress-peer-responses" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := testPolicy()
			test.edit(value)
			if _, err := Normalize(value); err == nil {
				t.Fatal("unsafe policy was accepted")
			}
		})
	}
	delay := testPolicy()
	delay.Behavior = "delay"
	delay.Delay = &metav1.Duration{Duration: 1250 * time.Millisecond}
	if _, err := Normalize(delay); err != nil {
		t.Fatalf("bounded delay was rejected: %v", err)
	}
}

func TestEvaluateUsesConjunctiveDeterministicSelectors(t *testing.T) {
	policy, err := Normalize(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if decision := Evaluate(policy, 12, "ab0011", 3, 0); !decision.Matched {
		t.Fatalf("expected match: %#v", decision)
	}
	for _, decision := range []Decision{
		Evaluate(policy, 9, "ab0011", 3, 0),
		Evaluate(policy, 12, "ff0011", 3, 0),
		Evaluate(policy, 12, "ab0011", 2, 0),
		Evaluate(policy, 12, "ab0011", 3, policy.MaxMatches),
		Evaluate(policy, 12, "ab0011", int64(policy.MaxEvaluations)+1, 0),
	} {
		if decision.Matched {
			t.Fatalf("unexpected match: %#v", decision)
		}
	}
}

func TestResolveSignerBindsBehaviorAndDigestToNamedMember(t *testing.T) {
	network := &attacknetv1beta1.StacksNetwork{Spec: attacknetv1beta1.StacksNetworkSpec{
		SignerSets: []attacknetv1beta1.SignerSetSpec{{Name: "active", Members: []attacknetv1beta1.SignerMemberSpec{{Name: "signer-1", Adversarial: testPolicy()}}}},
	}}
	policy, digest, err := ResolveSigner(network, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Digest(policy)
	if err != nil || digest != want || policy.Behavior != "withhold" {
		t.Fatalf("resolved policy was not identity-bound: policy=%#v digest=%q err=%v", policy, digest, err)
	}
	if _, _, err := ResolveSigner(network, "signer-2"); err == nil {
		t.Fatal("undeclared adversarial signer was accepted")
	}
}
