package inventory

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	testingv1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestDigestPreservesExistingCrossRuntimeVector(t *testing.T) {
	payload := Payload{
		SchemaVersion: SchemaVersion, ObservedGeneration: 3,
		Actors: []digestActor{{
			Name: "miner-1", Role: "miner", ServiceName: "demo-miner-1",
			StatefulSetName: "demo-miner-1", StatefulSetUID: "sts-1",
			ControllerRevision: "rev-1", PodName: "demo-miner-1-0", PodUID: "pod-1",
			RequestedImage: "stacks:test", RuntimeImageID: "containerd://sha256:" + repeat("a", 64),
		}},
	}
	digest, err := Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	canonicalDigest, err := canonical.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if digest != canonicalDigest {
		t.Fatalf("inventory digest is not canonical: got %s, want %s", digest, canonicalDigest)
	}
	const expected = "sha256:6c0e760de34bc3e4877a126557f98f2f1b78bf94c8755147a07396130ce63cff"
	if digest != expected {
		t.Fatalf("digest mismatch: got %s, want %s", digest, expected)
	}
}

func TestPublishedSortsActorsAndExcludesObservationMetadata(t *testing.T) {
	network := readyNetwork()
	payload, err := Build(network)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest = digest
	inventory, err := Published(network)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Actors[0].Name != "miner-1" || inventory.Actors[1].Name != "signer-1" {
		t.Fatalf("actors are not canonical: %#v", inventory.Actors)
	}
	original := digest
	network.ResourceVersion = "999"
	now := metav1.Now()
	network.Status.InventoryObservedAt = &now
	payload, err = Build(network)
	if err != nil {
		t.Fatal(err)
	}
	digest, err = Digest(payload)
	if err != nil || digest != original {
		t.Fatalf("observation metadata changed digest: %s, %v", digest, err)
	}
}

func TestConfigDigestIsAnOptionalAdmittedIdentity(t *testing.T) {
	network := readyNetwork()
	payload, err := Build(network)
	if err != nil {
		t.Fatal(err)
	}
	withoutConfig, err := Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.Actors[0].ConfigDigest = "sha256:" + repeat("c", 64)
	payload, err = Build(network)
	if err != nil {
		t.Fatal(err)
	}
	withConfig, err := Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if withConfig == withoutConfig {
		t.Fatal("config identity did not change the admitted inventory digest")
	}
	network.Status.InventoryDigest = withConfig
	expected, err := Published(network)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.Actors[0].ConfigDigest = "sha256:" + repeat("d", 64)
	if differences := CompareLive(expected, network, nil, nil); !hasDifference(differences, "configDigest") {
		t.Fatalf("config substitution was not detected: %#v", differences)
	}
}

func TestCompareLiveAllowsOnlySelectedPodIdentity(t *testing.T) {
	network := readyNetwork()
	payload, _ := Build(network)
	network.Status.InventoryDigest, _ = Digest(payload)
	expected, _ := Published(network)
	pods := []corev1.Pod{readyPod("miner-1", "replacement", "a"), readyPod("signer-1", "pod-signer", "b")}
	if differences := CompareLive(expected, network, pods, map[string]struct{}{"miner-1": {}}); len(differences) != 0 {
		t.Fatalf("allowed replacement diverged: %#v", differences)
	}
	pods[0].Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + repeat("c", 64)
	if differences := CompareLive(expected, network, pods, map[string]struct{}{"miner-1": {}}); len(differences) != 1 || differences[0].Field != "liveRuntimeImageID" {
		t.Fatalf("image substitution was not isolated: %#v", differences)
	}
}

func TestCompareLiveAllowsSelectedPodToBeTemporarilyAbsent(t *testing.T) {
	network := readyNetwork()
	payload, _ := Build(network)
	network.Status.InventoryDigest, _ = Digest(payload)
	expected, _ := Published(network)
	network.Status.InventoryReady = false
	network.Status.InventoryDigest = ""
	for index := range network.Status.Actors {
		if network.Status.Actors[index].Name == "miner-1" {
			network.Status.Actors[index].IdentityReady = false
			network.Status.Actors[index].PodName = ""
			network.Status.Actors[index].PodUID = ""
			network.Status.Actors[index].RuntimeImageID = ""
		}
	}
	pods := []corev1.Pod{readyPod("signer-1", "pod-signer", "b")}
	if differences := CompareLive(expected, network, pods, map[string]struct{}{"miner-1": {}}); len(differences) != 0 {
		t.Fatalf("allowed one-shot replacement window diverged: %#v", differences)
	}
	if differences := CompareLive(expected, network, pods, nil); len(differences) == 0 {
		t.Fatalf("unapproved Pod absence was not detected: %#v", differences)
	}
}

func TestRuntimeImageMatchesOneExactDigest(t *testing.T) {
	digest := "sha256:" + repeat("a", 64)
	if !RuntimeImageMatches("containerd://registry.example/stacks@"+digest, digest) {
		t.Fatal("exact runtime digest was rejected")
	}
	if actual, ok := ImmutableImageID("containerd://registry.example/stacks@" + digest); !ok || actual != digest {
		t.Fatalf("runtime digest extraction returned %q, %t", actual, ok)
	}
	for _, test := range []struct {
		value, expected string
	}{
		{"containerd://sha256:" + repeat("b", 64), digest},
		{"containerd://" + digest + "+sha256:" + repeat("b", 64), digest},
		{"containerd://" + digest, "not-a-digest"},
	} {
		if RuntimeImageMatches(test.value, test.expected) {
			t.Fatalf("ambiguous or invalid identity was accepted: value=%q expected=%q", test.value, test.expected)
		}
	}
}

func readyNetwork() *testingv1.StacksNetwork {
	return &testingv1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "test", Generation: 3, ResourceVersion: "1"},
		Spec: testingv1.StacksNetworkSpec{Actors: []testingv1.ActorSpec{
			{Name: "signer-1", Role: "signer", Image: "signer:test"},
			{Name: "miner-1", Role: "miner", Image: "stacks:test"},
		}},
		Status: testingv1.StacksNetworkStatus{
			ObservedGeneration: 3, InventoryReady: true,
			Actors: []testingv1.ActorStatus{
				actorStatus("signer-1", "signer", "signer:test", "b", "pod-signer"),
				actorStatus("miner-1", "miner", "stacks:test", "a", "pod-miner"),
			},
		},
	}
}

func actorStatus(name, role, image, digest, uid string) testingv1.ActorStatus {
	return testingv1.ActorStatus{
		Name: name, Role: role, ResourceName: "demo-" + name, Image: image,
		IdentityReady: true, ServiceName: "demo-" + name,
		StatefulSetUID: "sts-" + name, CurrentRevision: "rev-" + name,
		PodName: "demo-" + name + "-0", PodUID: uid,
		RuntimeImageID: "containerd://sha256:" + repeat(digest, 64),
	}
}

func readyPod(actor, uid, digest string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-" + actor + "-0", UID: types.UID(uid),
			Labels: map[string]string{"testing.stacks.org/network": "demo", "testing.stacks.org/actor": actor},
		},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "actor", ImageID: "containerd://sha256:" + repeat(digest, 64),
		}}},
	}
}

func repeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}

func hasDifference(differences []testingv1.IdentityDifference, field string) bool {
	for _, difference := range differences {
		if difference.Field == field {
			return true
		}
	}
	return false
}
