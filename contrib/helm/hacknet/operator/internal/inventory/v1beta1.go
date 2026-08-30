package inventory

import (
	"fmt"

	testingv1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	testingv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	corev1 "k8s.io/api/core/v1"
)

// BetaPublished verifies a v1beta1 inventory using the same canonical identity
// engine as the legacy API. The conversion is intentionally mechanical: no
// identity or digest rule is implemented in this adapter.
func BetaPublished(network *testingv1beta1.StacksNetwork) (testingv1beta1.NetworkInventory, error) {
	legacy := betaNetworkAsLegacy(network)
	published, err := Published(legacy)
	if err != nil {
		return testingv1beta1.NetworkInventory{}, err
	}
	if len(network.Spec.Burnchain.Nodes) > 0 {
		graph, err := burnchaintopology.Published(network)
		if err != nil {
			return testingv1beta1.NetworkInventory{}, err
		}
		result := betaInventory(published)
		result.BurnchainTopology = graph
		return result, nil
	}
	return betaInventory(published), nil
}

// BetaCompareLive checks a v1beta1 inventory against direct Pod observations
// through the shared legacy identity comparison engine.
func BetaCompareLive(expected testingv1beta1.NetworkInventory, network *testingv1beta1.StacksNetwork, pods []corev1.Pod, allowedPodChanges map[string]struct{}) []testingv1beta1.IdentityDifference {
	legacyExpected := legacyInventory(expected)
	differences := CompareLive(legacyExpected, betaNetworkAsLegacy(network), pods, allowedPodChanges)
	result := make([]testingv1beta1.IdentityDifference, len(differences))
	for index, difference := range differences {
		result[index] = testingv1beta1.IdentityDifference{
			Scope: difference.Scope, Field: difference.Field, Expected: difference.Expected,
			Current: difference.Current, Message: difference.Message,
		}
	}
	if len(network.Spec.Burnchain.Nodes) > 0 || expected.BurnchainTopology != nil {
		current, err := burnchaintopology.Published(network)
		if err != nil {
			result = append(result, testingv1beta1.IdentityDifference{Scope: "burnchainTopology", Field: "digest", Expected: burnchainDigest(expected.BurnchainTopology), Message: err.Error()})
		} else if expected.BurnchainTopology == nil || expected.BurnchainTopology.Digest != current.Digest {
			result = append(result, testingv1beta1.IdentityDifference{
				Scope: "burnchainTopology", Field: "digest", Expected: burnchainDigest(expected.BurnchainTopology),
				Current: current.Digest, Message: fmt.Sprintf("admitted burnchain topology changed from %s to %s", burnchainDigest(expected.BurnchainTopology), current.Digest),
			})
		}
	}
	return result
}

func burnchainDigest(value *testingv1beta1.AdmittedBurnchainTopology) string {
	if value == nil {
		return ""
	}
	return value.Digest
}

func betaNetworkAsLegacy(network *testingv1beta1.StacksNetwork) *testingv1.StacksNetwork {
	legacy := &testingv1.StacksNetwork{}
	legacy.TypeMeta = network.TypeMeta
	legacy.ObjectMeta = *network.ObjectMeta.DeepCopy()
	legacy.Spec.Actors = betaDeclaredActors(network)
	legacy.Status.ObservedGeneration = network.Status.ObservedGeneration
	legacy.Status.InventoryReady = network.Status.InventoryReady
	legacy.Status.InventoryDigest = network.Status.InventoryDigest
	legacy.Status.InventoryObservedAt = network.Status.InventoryObservedAt
	for _, actor := range network.Status.Actors {
		legacy.Status.Actors = append(legacy.Status.Actors, testingv1.ActorStatus{
			Name: actor.Name, Role: actor.Role, ResourceName: actor.ResourceName, Image: actor.Image,
			Ready: actor.Ready, ReadyReplicas: actor.ReadyReplicas, UpdatedReplicas: actor.UpdatedReplicas,
			Generation: actor.Generation, ObservedGeneration: actor.ObservedGeneration,
			CurrentRevision: actor.CurrentRevision, UpdateRevision: actor.UpdateRevision,
			ServiceName: actor.ServiceName, StatefulSetUID: actor.StatefulSetUID,
			StatefulSetResourceVersion: actor.StatefulSetResourceVersion, PodName: actor.PodName,
			PodUID: actor.PodUID, PodResourceVersion: actor.PodResourceVersion,
			RuntimeImageID: actor.RuntimeImageID, ConfigDigest: actor.ConfigDigest,
			IdentityReady: actor.IdentityReady,
		})
	}
	return legacy
}

func betaDeclaredActors(network *testingv1beta1.StacksNetwork) []testingv1.ActorSpec {
	capacity := len(network.Spec.Burnchain.Nodes) + len(network.Spec.Nodes) + len(network.Spec.RawActors)
	if network.Spec.Enrollment != nil {
		capacity++
	}
	result := make([]testingv1.ActorSpec, 0, capacity)
	for _, actor := range network.Spec.Burnchain.Nodes {
		result = append(result, testingv1.ActorSpec{Name: actor.Name, Role: "burnchain"})
	}
	for _, actor := range network.Spec.Nodes {
		result = append(result, testingv1.ActorSpec{Name: actor.Name, Role: string(actor.Role)})
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			result = append(result,
				testingv1.ActorSpec{Name: member.NodeName, Role: "companion"},
				testingv1.ActorSpec{Name: member.Name, Role: "signer"},
			)
		}
	}
	if network.Spec.Enrollment != nil {
		result = append(result, testingv1.ActorSpec{Name: network.Spec.Enrollment.Name, Role: "infrastructure"})
	}
	for _, actor := range network.Spec.RawActors {
		result = append(result, testingv1.ActorSpec{Name: actor.Name, Role: actor.Role})
	}
	return result
}

func betaInventory(value testingv1.NetworkInventory) testingv1beta1.NetworkInventory {
	result := testingv1beta1.NetworkInventory{
		Digest: value.Digest, ObservedGeneration: value.ObservedGeneration,
		ObservedAt: value.ObservedAt, ResourceVersion: value.ResourceVersion,
		Actors: make([]testingv1beta1.AdmittedActorIdentity, len(value.Actors)),
	}
	for index, actor := range value.Actors {
		result.Actors[index] = testingv1beta1.AdmittedActorIdentity{
			Name: actor.Name, Role: actor.Role, ServiceName: actor.ServiceName,
			StatefulSetName: actor.StatefulSetName, StatefulSetUID: actor.StatefulSetUID,
			ControllerRevision: actor.ControllerRevision, PodName: actor.PodName, PodUID: actor.PodUID,
			RequestedImage: actor.RequestedImage, RuntimeImageID: actor.RuntimeImageID,
			ConfigDigest: actor.ConfigDigest,
		}
	}
	return result
}

func legacyInventory(value testingv1beta1.NetworkInventory) testingv1.NetworkInventory {
	result := testingv1.NetworkInventory{
		Digest: value.Digest, ObservedGeneration: value.ObservedGeneration,
		ObservedAt: value.ObservedAt, ResourceVersion: value.ResourceVersion,
		Actors: make([]testingv1.AdmittedActorIdentity, len(value.Actors)),
	}
	for index, actor := range value.Actors {
		result.Actors[index] = testingv1.AdmittedActorIdentity{
			Name: actor.Name, Role: actor.Role, ServiceName: actor.ServiceName,
			StatefulSetName: actor.StatefulSetName, StatefulSetUID: actor.StatefulSetUID,
			ControllerRevision: actor.ControllerRevision, PodName: actor.PodName, PodUID: actor.PodUID,
			RequestedImage: actor.RequestedImage, RuntimeImageID: actor.RuntimeImageID,
			ConfigDigest: actor.ConfigDigest,
		}
	}
	return result
}
