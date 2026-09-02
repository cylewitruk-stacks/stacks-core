package inventory

import (
	"testing"

	testingv1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	testingv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestBetaPublishedUsesSharedCompatibilityVector(t *testing.T) {
	legacy := readyNetwork()
	payload, err := Build(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Status.InventoryDigest, err = Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	beta := &testingv1beta1.StacksNetwork{ObjectMeta: legacy.ObjectMeta}
	beta.Generation = legacy.Generation
	for _, actor := range legacy.Spec.Actors {
		beta.Spec.RawActors = append(beta.Spec.RawActors, testingv1beta1.RawActorSpec{Name: actor.Name, Role: actor.Role})
	}
	beta.Status.ObservedGeneration = legacy.Status.ObservedGeneration
	beta.Status.InventoryReady = legacy.Status.InventoryReady
	beta.Status.InventoryDigest = legacy.Status.InventoryDigest
	beta.Status.InventoryObservedAt = legacy.Status.InventoryObservedAt
	for _, actor := range legacy.Status.Actors {
		beta.Status.Actors = append(beta.Status.Actors, testingv1beta1.ActorStatus{
			Name: actor.Name, Role: actor.Role, ResourceName: actor.ResourceName,
			Image: actor.Image, ServiceName: actor.ServiceName, StatefulSetUID: actor.StatefulSetUID,
			CurrentRevision: actor.CurrentRevision, PodName: actor.PodName, PodUID: actor.PodUID,
			RuntimeImageID: actor.RuntimeImageID, IdentityReady: actor.IdentityReady,
		})
	}
	published, err := BetaPublished(beta)
	if err != nil {
		t.Fatal(err)
	}
	if published.Digest != legacy.Status.InventoryDigest {
		t.Fatalf("beta adapter changed inventory digest: got %s want %s", published.Digest, legacy.Status.InventoryDigest)
	}
}

func TestBetaPublishedRejectsStatusThatOmitsDeclaredActor(t *testing.T) {
	legacy := readyNetwork()
	payload, _ := Build(legacy)
	legacy.Status.InventoryDigest, _ = Digest(payload)
	beta := &testingv1beta1.StacksNetwork{ObjectMeta: legacy.ObjectMeta}
	beta.Spec.RawActors = []testingv1beta1.RawActorSpec{{Name: "miner-1", Role: "miner"}, {Name: "signer-1", Role: "signer"}}
	beta.Status.ObservedGeneration = legacy.Status.ObservedGeneration
	beta.Status.InventoryReady = true
	beta.Status.InventoryDigest = legacy.Status.InventoryDigest
	actor := legacy.Status.Actors[0]
	beta.Status.Actors = []testingv1beta1.ActorStatus{{
		Name: actor.Name, Role: actor.Role, ResourceName: actor.ResourceName, Image: actor.Image,
		ServiceName: actor.ServiceName, StatefulSetUID: actor.StatefulSetUID,
		CurrentRevision: actor.CurrentRevision, PodName: actor.PodName, PodUID: actor.PodUID,
		RuntimeImageID: actor.RuntimeImageID, IdentityReady: actor.IdentityReady,
	}}
	if _, err := BetaPublished(beta); err == nil {
		t.Fatal("published beta inventory accepted a status that omitted a declared actor")
	}
}

func TestBetaPublishedIncludesEnrollmentActor(t *testing.T) {
	legacy := readyNetwork()
	legacy.Spec.Actors = append(legacy.Spec.Actors, testingv1.ActorSpec{
		Name: "stacker", Role: "infrastructure", Image: "stacker:test",
	})
	legacy.Status.Actors = append(legacy.Status.Actors,
		actorStatus("stacker", "infrastructure", "stacker:test", "c", "pod-stacker"))
	payload, err := Build(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Status.InventoryDigest, err = Digest(payload)
	if err != nil {
		t.Fatal(err)
	}

	beta := &testingv1beta1.StacksNetwork{ObjectMeta: legacy.ObjectMeta}
	beta.Spec.RawActors = []testingv1beta1.RawActorSpec{
		{Name: "signer-1", Role: "signer"},
		{Name: "miner-1", Role: "miner"},
	}
	beta.Spec.Enrollment = &testingv1beta1.SignerEnrollmentSpec{Name: "stacker"}
	beta.Status.ObservedGeneration = legacy.Status.ObservedGeneration
	beta.Status.InventoryReady = true
	beta.Status.InventoryDigest = legacy.Status.InventoryDigest
	for _, actor := range legacy.Status.Actors {
		beta.Status.Actors = append(beta.Status.Actors, testingv1beta1.ActorStatus{
			Name: actor.Name, Role: actor.Role, ResourceName: actor.ResourceName,
			Image: actor.Image, ServiceName: actor.ServiceName, StatefulSetUID: actor.StatefulSetUID,
			CurrentRevision: actor.CurrentRevision, PodName: actor.PodName, PodUID: actor.PodUID,
			RuntimeImageID: actor.RuntimeImageID, IdentityReady: actor.IdentityReady,
		})
	}

	published, err := BetaPublished(beta)
	if err != nil {
		t.Fatal(err)
	}
	if len(published.Actors) != 3 || published.Digest != legacy.Status.InventoryDigest {
		t.Fatalf("enrollment actor was not included in the beta inventory: %#v", published)
	}
}
