package topology

import (
	"testing"
)

func TestRestrictedEgressAllowsOnlyDeclaredActorsAndDNS(t *testing.T) {
	network := testNetwork()
	network.Spec.Actors[1].Labels = map[string]string{egressProfileLabel: "restricted"}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.NetworkPolicies) != 1 {
		t.Fatalf("got %d NetworkPolicies, want 1", len(resources.NetworkPolicies))
	}
	policy := resources.NetworkPolicies[0]
	digest, err := egressPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Annotations[egressPolicyDigestAnnotation] != digest {
		t.Fatalf("policy annotation does not bind its spec: %#v", policy.Annotations)
	}
	if len(policy.Spec.Egress) != 2 {
		t.Fatalf("got %d egress rules, want dependency + DNS", len(policy.Spec.Egress))
	}
	dependency := policy.Spec.Egress[0].To[0].PodSelector.MatchLabels
	if dependency[networkLabel] != network.Name || dependency[actorLabel] != "signer-1" {
		t.Fatalf("dependency rule is not actor-scoped: %#v", dependency)
	}
	for _, rule := range policy.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				t.Fatal("restricted policy unexpectedly permits a raw CIDR")
			}
		}
	}
}

func TestUnrestrictedEgressDoesNotRenderAFalseBoundary(t *testing.T) {
	network := testNetwork()
	network.Spec.Actors[2].Labels = map[string]string{egressProfileLabel: "unrestricted"}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.NetworkPolicies) != 0 {
		t.Fatalf("unrestricted profile rendered %d policies", len(resources.NetworkPolicies))
	}
}

func TestUnknownEgressProfileFailsClosed(t *testing.T) {
	network := testNetwork()
	network.Spec.Actors[2].Labels = map[string]string{egressProfileLabel: "typo"}
	if _, err := Render(network, testScheme(t)); err == nil {
		t.Fatal("unknown egress profile was accepted")
	}
}

func TestRestrictedEgressDeduplicatesStartupAndRuntimePeers(t *testing.T) {
	network := testNetwork()
	actor := &network.Spec.Actors[1]
	actor.Labels = map[string]string{egressProfileLabel: "restricted"}
	actor.EgressPeers = []string{"signer-1", "follower-1"}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := resources.NetworkPolicies[0]
	if len(policy.Spec.Egress) != 3 {
		t.Fatalf("got %d rules, want two unique actors plus DNS", len(policy.Spec.Egress))
	}
	if policy.Spec.Egress[0].To[0].PodSelector.MatchLabels[actorLabel] != "signer-1" || policy.Spec.Egress[1].To[0].PodSelector.MatchLabels[actorLabel] != "follower-1" {
		t.Fatalf("egress peers are not stable and deduplicated: %#v", policy.Spec.Egress)
	}
}
