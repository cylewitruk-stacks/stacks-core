package burnchaintopology

import (
	"math/rand"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestPolicyServiceNameLeavesRoomForDeploymentRevisionHash(t *testing.T) {
	name := PolicyServiceName(strings.Repeat("p", 63))
	if len(name) > 52 || len(name+"-1234567890") > 63 ||
		name != PolicyServiceName(strings.Repeat("p", 63)) {
		t.Fatalf("invalid stable policy workload name %q", name)
	}
}

func topologyFixture() *attacknetv1beta1.StacksNetwork {
	now := metav1.Now()
	return &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid"), Generation: 4},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Burnchain: attacknetv1beta1.BurnchainTopologySpec{
				PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "clock-a"},
				Nodes: []attacknetv1beta1.BitcoinNodeSpec{
					{Name: "bitcoin-b", PeerRefs: []string{"bitcoin-a"}, PolicyRef: &attacknetv1beta1.NamedObjectReference{Name: "clock-b"}},
					{Name: "bitcoin-a", PeerRefs: []string{"bitcoin-b"}},
				},
			},
			Nodes: []attacknetv1beta1.StacksNodeSpec{
				{Name: "follower-b", Role: attacknetv1beta1.StacksNodeFollower, BurnchainNodeRef: "bitcoin-b"},
				{Name: "miner-a", Role: attacknetv1beta1.StacksNodeMiner, BurnchainNodeRef: "bitcoin-a"},
			},
		},
		Status: attacknetv1beta1.StacksNetworkStatus{
			ObservedGeneration: 4, InventoryReady: true, InventoryObservedAt: &now,
			Actors: []attacknetv1beta1.ActorStatus{
				{Name: "bitcoin-a", Role: "burnchain", ServiceName: "network-bitcoin-a", IdentityReady: true},
				{Name: "bitcoin-b", Role: "burnchain", ServiceName: "network-bitcoin-b", IdentityReady: true},
				{Name: "follower-b", Role: "follower", ServiceName: "network-follower-b", IdentityReady: true},
				{Name: "miner-a", Role: "miner", ServiceName: "network-miner-a", IdentityReady: true},
			},
		},
	}
}

func TestBuildNormalizesGraphAndBindings(t *testing.T) {
	policyUIDs := map[string]string{"clock-a": "clock-a-uid", "clock-b": "clock-b-uid"}
	graph, err := Build(topologyFixture(), policyUIDs)
	if err != nil {
		t.Fatal(err)
	}
	if graph.SchemaVersion != SchemaVersion || graph.Digest == "" || graph.ObservedGeneration != 4 {
		t.Fatalf("incomplete admitted graph: %#v", graph)
	}
	if graph.Nodes[0].Name != "bitcoin-a" || graph.Nodes[0].PolicyRef != "clock-a" || graph.Nodes[0].PolicyUID != "clock-a-uid" || graph.Nodes[0].PeerRefs[0] != "bitcoin-b" {
		t.Fatalf("Bitcoin graph is not normalized: %#v", graph.Nodes)
	}
	if graph.Bindings[0].Actor != "follower-b" || graph.Bindings[0].BitcoinNodeRef != "bitcoin-b" || graph.Bindings[1].Actor != "miner-a" {
		t.Fatalf("Stacks bindings are not normalized: %#v", graph.Bindings)
	}
	reordered := topologyFixture()
	reordered.Spec.Burnchain.Nodes[0], reordered.Spec.Burnchain.Nodes[1] = reordered.Spec.Burnchain.Nodes[1], reordered.Spec.Burnchain.Nodes[0]
	reordered.Status.Actors[0], reordered.Status.Actors[3] = reordered.Status.Actors[3], reordered.Status.Actors[0]
	second, err := Build(reordered, policyUIDs)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Digest != second.Digest {
		t.Fatalf("declaration ordering changed graph digest: %s != %s", graph.Digest, second.Digest)
	}
	restored := topologyFixture()
	restored.Generation = 6
	restored.Status.ObservedGeneration = 6
	third, err := Build(restored, policyUIDs)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Digest != third.Digest || third.ObservedGeneration != 6 {
		t.Fatalf("network generation changed graph identity: %#v != %#v", graph, third)
	}
}

func TestValidateRejectsAmbiguousAndInvalidGraphs(t *testing.T) {
	tests := map[string]func(*attacknetv1beta1.StacksNetwork){
		"unknown peer": func(network *attacknetv1beta1.StacksNetwork) {
			network.Spec.Burnchain.Nodes[0].PeerRefs = []string{"missing"}
		},
		"self peer": func(network *attacknetv1beta1.StacksNetwork) {
			network.Spec.Burnchain.Nodes[0].PeerRefs = []string{"bitcoin-b"}
		},
		"shared policy":   func(network *attacknetv1beta1.StacksNetwork) { network.Spec.Burnchain.Nodes[0].PolicyRef = nil },
		"unknown binding": func(network *attacknetv1beta1.StacksNetwork) { network.Spec.Nodes[0].BurnchainNodeRef = "missing" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			network := topologyFixture()
			mutate(network)
			if err := Validate(network); err == nil {
				t.Fatal("expected invalid graph to be rejected")
			}
		})
	}
}

func TestBuildScopesReadinessToGraphIdentities(t *testing.T) {
	policyUIDs := map[string]string{"clock-a": "clock-a-uid", "clock-b": "clock-b-uid"}
	network := topologyFixture()
	network.Status.Actors[0].IdentityReady = false
	if _, err := Build(network, policyUIDs); err == nil {
		t.Fatal("expected incomplete Bitcoin identity to withhold graph")
	}
	network = topologyFixture()
	network.Status.InventoryReady = false
	network.Status.Actors[2].IdentityReady = false
	if _, err := Build(network, policyUIDs); err != nil {
		t.Fatalf("unrelated Stacks actor availability changed graph identity: %v", err)
	}
	network = topologyFixture()
	if _, err := Build(network, map[string]string{"clock-a": "clock-a-uid"}); err == nil {
		t.Fatal("expected incomplete policy identity to withhold graph")
	}
}

func TestDigestIsOrderIndependentAndBindsPolicyIdentity(t *testing.T) {
	network := topologyFixture()
	network.Spec.Burnchain.Nodes = append(network.Spec.Burnchain.Nodes, attacknetv1beta1.BitcoinNodeSpec{
		Name: "bitcoin-c", PeerRefs: []string{"bitcoin-b", "bitcoin-a"}, PolicyRef: &attacknetv1beta1.NamedObjectReference{Name: "clock-c"},
	})
	network.Spec.Nodes = append(network.Spec.Nodes, attacknetv1beta1.StacksNodeSpec{Name: "follower-c", Role: attacknetv1beta1.StacksNodeFollower, BurnchainNodeRef: "bitcoin-c"})
	network.Status.Actors = append(network.Status.Actors,
		attacknetv1beta1.ActorStatus{Name: "bitcoin-c", Role: "burnchain", ServiceName: "network-bitcoin-c", IdentityReady: true},
		attacknetv1beta1.ActorStatus{Name: "follower-c", Role: "follower", ServiceName: "network-follower-c", IdentityReady: true},
	)
	policyUIDs := map[string]string{"clock-a": "clock-a-uid", "clock-b": "clock-b-uid", "clock-c": "clock-c-uid"}
	baseline, err := Build(network, policyUIDs)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(17))
	for iteration := 0; iteration < 128; iteration++ {
		candidate := network.DeepCopy()
		random.Shuffle(len(candidate.Spec.Burnchain.Nodes), func(left, right int) {
			candidate.Spec.Burnchain.Nodes[left], candidate.Spec.Burnchain.Nodes[right] = candidate.Spec.Burnchain.Nodes[right], candidate.Spec.Burnchain.Nodes[left]
		})
		for index := range candidate.Spec.Burnchain.Nodes {
			random.Shuffle(len(candidate.Spec.Burnchain.Nodes[index].PeerRefs), func(left, right int) {
				candidate.Spec.Burnchain.Nodes[index].PeerRefs[left], candidate.Spec.Burnchain.Nodes[index].PeerRefs[right] = candidate.Spec.Burnchain.Nodes[index].PeerRefs[right], candidate.Spec.Burnchain.Nodes[index].PeerRefs[left]
			})
		}
		random.Shuffle(len(candidate.Spec.Nodes), func(left, right int) {
			candidate.Spec.Nodes[left], candidate.Spec.Nodes[right] = candidate.Spec.Nodes[right], candidate.Spec.Nodes[left]
		})
		random.Shuffle(len(candidate.Status.Actors), func(left, right int) {
			candidate.Status.Actors[left], candidate.Status.Actors[right] = candidate.Status.Actors[right], candidate.Status.Actors[left]
		})
		observed, err := Build(candidate, policyUIDs)
		if err != nil {
			t.Fatal(err)
		}
		if observed.Digest != baseline.Digest {
			t.Fatalf("iteration %d changed digest: %s != %s", iteration, observed.Digest, baseline.Digest)
		}
	}

	changed := map[string]string{"clock-a": "replacement-uid", "clock-b": "clock-b-uid", "clock-c": "clock-c-uid"}
	replacement, err := Build(network, changed)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Digest == baseline.Digest {
		t.Fatal("BurnchainPolicy replacement did not change the admitted graph digest")
	}
}

func TestPublishedRecomputesStatusPayload(t *testing.T) {
	network := topologyFixture()
	graph, err := Build(network, map[string]string{"clock-a": "clock-a-uid", "clock-b": "clock-b-uid"})
	if err != nil {
		t.Fatal(err)
	}
	network.Status.BurnchainTopology = graph
	if _, err := Published(network); err != nil {
		t.Fatalf("valid published graph was rejected: %v", err)
	}
	network.Status.BurnchainTopology.Nodes[0].ServiceName = "fabricated-service"
	if _, err := Published(network); err == nil {
		t.Fatal("published graph accepted payload fields not covered by its digest")
	}
}
