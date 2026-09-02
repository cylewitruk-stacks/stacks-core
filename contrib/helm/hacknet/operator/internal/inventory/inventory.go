// Package inventory owns the authoritative admitted-actor identity contract.
package inventory

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	testingv1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const (
	// SchemaVersion identifies the admitted-inventory digest contract.
	SchemaVersion = "stacks-network-admitted-inventory/v1"
)

var (
	runtimeDigestPattern = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	exactDigestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Payload is the canonical input to the admitted-inventory digest.
type Payload struct {
	Actors             []digestActor `json:"actors"`
	ObservedGeneration int64         `json:"observedGeneration"`
	SchemaVersion      string        `json:"schemaVersion"`
}

// digestActor is the stable actor projection included in the inventory digest.
type digestActor struct {
	AdversarialEgressProfile string `json:"adversarialEgressProfile,omitempty"`
	AdversarialPolicyDigest  string `json:"adversarialPolicyDigest,omitempty"`
	ConfigDigest             string `json:"configDigest,omitempty"`
	ControllerRevision       string `json:"controllerRevision"`
	EgressPolicyDigest       string `json:"egressPolicyDigest,omitempty"`
	Name                     string `json:"name"`
	PodName                  string `json:"podName"`
	PodUID                   string `json:"podUID"`
	RequestedImage           string `json:"requestedImage"`
	Role                     string `json:"role"`
	RuntimeImageID           string `json:"runtimeImageID"`
	ServiceName              string `json:"serviceName"`
	StatefulSetName          string `json:"statefulSetName"`
	StatefulSetUID           string `json:"statefulSetUID"`
}

// Digest returns the versioned SHA-256 digest for a complete payload.
func Digest(payload Payload) (string, error) {
	if payload.SchemaVersion != SchemaVersion {
		return "", fmt.Errorf("unsupported admitted inventory schema %q", payload.SchemaVersion)
	}
	if payload.ObservedGeneration < 1 {
		return "", errors.New("admitted inventory requires a positive observed generation")
	}
	if len(payload.Actors) == 0 {
		return "", errors.New("admitted inventory requires at least one actor")
	}
	return canonical.Digest(payload)
}

// Build reconstructs the canonical complete payload from topology status.
func Build(network *testingv1.StacksNetwork) (Payload, error) {
	if network.Status.ObservedGeneration != network.Generation {
		return Payload{}, errors.New("StacksNetwork inventory has not observed the current generation")
	}
	if !network.Status.InventoryReady {
		return Payload{}, errors.New("StacksNetwork admitted inventory is not complete")
	}
	if len(network.Status.Actors) != len(network.Spec.Actors) {
		return Payload{}, errors.New("StacksNetwork admitted inventory actor count is incomplete")
	}
	statuses := make(map[string]testingv1.ActorStatus, len(network.Status.Actors))
	for _, status := range network.Status.Actors {
		if _, duplicate := statuses[status.Name]; duplicate {
			return Payload{}, fmt.Errorf("StacksNetwork actor %s has duplicate status", status.Name)
		}
		statuses[status.Name] = status
	}
	actors := make([]digestActor, 0, len(network.Spec.Actors))
	for _, actor := range network.Spec.Actors {
		status, ok := statuses[actor.Name]
		if !ok || !status.IdentityReady || status.Role != actor.Role {
			return Payload{}, fmt.Errorf("StacksNetwork actor %s lacks a complete admitted identity", actor.Name)
		}
		if status.AdversarialPolicyDigest != actor.AdversarialPolicyDigest || status.AdversarialEgressProfile != actor.AdversarialEgressProfile {
			return Payload{}, fmt.Errorf("StacksNetwork actor %s adversarial identity does not match the compiled workload", actor.Name)
		}
		identity := testingv1.AdmittedActorIdentity{
			Name: actor.Name, Role: actor.Role,
			ServiceName: status.ServiceName, StatefulSetName: status.ResourceName,
			StatefulSetUID: status.StatefulSetUID, ControllerRevision: status.CurrentRevision,
			PodName: status.PodName, PodUID: status.PodUID,
			RequestedImage: status.Image, RuntimeImageID: status.RuntimeImageID,
			ConfigDigest: status.ConfigDigest, AdversarialPolicyDigest: status.AdversarialPolicyDigest,
			AdversarialEgressProfile: status.AdversarialEgressProfile, EgressPolicyDigest: status.EgressPolicyDigest,
		}
		if err := validateIdentity(identity); err != nil {
			return Payload{}, fmt.Errorf("StacksNetwork actor %s: %w", actor.Name, err)
		}
		actors = append(actors, toDigestActor(identity))
	}
	slices.SortFunc(actors, func(left, right digestActor) int {
		return strings.Compare(left.Name, right.Name)
	})
	return Payload{Actors: actors, ObservedGeneration: network.Generation, SchemaVersion: SchemaVersion}, nil
}

// Published verifies and returns the complete inventory published by topology status.
func Published(network *testingv1.StacksNetwork) (testingv1.NetworkInventory, error) {
	if network.Status.InventoryDigest == "" {
		return testingv1.NetworkInventory{}, errors.New("StacksNetwork admitted inventory has no published digest")
	}
	payload, err := Build(network)
	if err != nil {
		return testingv1.NetworkInventory{}, err
	}
	digest, err := Digest(payload)
	if err != nil {
		return testingv1.NetworkInventory{}, err
	}
	if digest != network.Status.InventoryDigest {
		return testingv1.NetworkInventory{}, fmt.Errorf(
			"StacksNetwork admitted inventory digest mismatch: published %s, calculated %s",
			network.Status.InventoryDigest, digest,
		)
	}
	actors := make([]testingv1.AdmittedActorIdentity, len(payload.Actors))
	for index, actor := range payload.Actors {
		actors[index] = fromDigestActor(actor)
	}
	return testingv1.NetworkInventory{
		Digest: digest, ObservedGeneration: payload.ObservedGeneration,
		ObservedAt:      network.Status.InventoryObservedAt,
		ResourceVersion: network.ResourceVersion, Actors: actors,
	}, nil
}

// CompareLive verifies that the expected inventory still names the only live actor Pods.
func CompareLive(expected testingv1.NetworkInventory, network *testingv1.StacksNetwork, pods []corev1.Pod, allowedPodChanges map[string]struct{}) []testingv1.IdentityDifference {
	differences := make([]testingv1.IdentityDifference, 0)
	current, err := Published(network)
	if err == nil {
		differences = append(differences, compareInventory(expected, current, allowedPodChanges)...)
	} else {
		differences = append(differences, compareIncompleteStatus(expected, network, allowedPodChanges)...)
	}
	differences = append(differences, comparePods(expected, network.Name, pods, allowedPodChanges)...)
	return differences
}

func compareInventory(expected, current testingv1.NetworkInventory, allowed map[string]struct{}) []testingv1.IdentityDifference {
	differences := make([]testingv1.IdentityDifference, 0)
	if expected.ObservedGeneration != current.ObservedGeneration {
		differences = append(differences, difference("", "observedGeneration", fmt.Sprint(expected.ObservedGeneration), fmt.Sprint(current.ObservedGeneration)))
	}
	currentActors := identitiesByName(current.Actors)
	for _, actor := range expected.Actors {
		observed, ok := currentActors[actor.Name]
		if !ok {
			differences = append(differences, difference(actor.Name, "actor", "present", "missing"))
			continue
		}
		differences = append(differences, compareActor(actor, observed, allowed)...)
		delete(currentActors, actor.Name)
	}
	for name := range currentActors {
		differences = append(differences, difference(name, "actor", "absent", "present"))
	}
	return differences
}

func compareIncompleteStatus(expected testingv1.NetworkInventory, network *testingv1.StacksNetwork, allowed map[string]struct{}) []testingv1.IdentityDifference {
	statuses := make(map[string]testingv1.ActorStatus, len(network.Status.Actors))
	for _, status := range network.Status.Actors {
		statuses[status.Name] = status
	}
	differences := make([]testingv1.IdentityDifference, 0)
	for _, actor := range expected.Actors {
		status, ok := statuses[actor.Name]
		if !ok {
			differences = append(differences, difference(actor.Name, "statusActor", "present", "missing"))
			continue
		}
		observed := testingv1.AdmittedActorIdentity{
			Name: status.Name, Role: status.Role, ServiceName: status.ServiceName,
			StatefulSetName: status.ResourceName, StatefulSetUID: status.StatefulSetUID,
			ControllerRevision: status.CurrentRevision, PodName: status.PodName,
			PodUID: status.PodUID, RequestedImage: status.Image, RuntimeImageID: status.RuntimeImageID,
			ConfigDigest: status.ConfigDigest, AdversarialPolicyDigest: status.AdversarialPolicyDigest,
			AdversarialEgressProfile: status.AdversarialEgressProfile, EgressPolicyDigest: status.EgressPolicyDigest,
		}
		differences = append(differences, compareActor(actor, observed, allowed)...)
	}
	return differences
}

func compareActor(expected, observed testingv1.AdmittedActorIdentity, allowed map[string]struct{}) []testingv1.IdentityDifference {
	_, podChangeAllowed := allowed[expected.Name]
	pairs := []struct {
		field, expected, observed string
		pod                       bool
	}{
		{"role", expected.Role, observed.Role, false},
		{"serviceName", expected.ServiceName, observed.ServiceName, false},
		{"statefulSetName", expected.StatefulSetName, observed.StatefulSetName, false},
		{"statefulSetUID", expected.StatefulSetUID, observed.StatefulSetUID, false},
		{"controllerRevision", expected.ControllerRevision, observed.ControllerRevision, false},
		{"podName", expected.PodName, observed.PodName, true},
		{"podUID", expected.PodUID, observed.PodUID, true},
		{"requestedImage", expected.RequestedImage, observed.RequestedImage, false},
		{"runtimeImageID", expected.RuntimeImageID, observed.RuntimeImageID, false},
		{"configDigest", expected.ConfigDigest, observed.ConfigDigest, false},
		{"adversarialPolicyDigest", expected.AdversarialPolicyDigest, observed.AdversarialPolicyDigest, false},
		{"adversarialEgressProfile", expected.AdversarialEgressProfile, observed.AdversarialEgressProfile, false},
		{"egressPolicyDigest", expected.EgressPolicyDigest, observed.EgressPolicyDigest, false},
	}
	differences := make([]testingv1.IdentityDifference, 0)
	for _, pair := range pairs {
		temporarilyUnavailableImage := pair.field == "runtimeImageID" && podChangeAllowed && pair.observed == ""
		if pair.expected != pair.observed && !(pair.pod && podChangeAllowed) && !temporarilyUnavailableImage {
			differences = append(differences, difference(expected.Name, pair.field, pair.expected, pair.observed))
		}
	}
	return differences
}

func comparePods(expected testingv1.NetworkInventory, network string, pods []corev1.Pod, allowed map[string]struct{}) []testingv1.IdentityDifference {
	differences := make([]testingv1.IdentityDifference, 0)
	for _, actor := range expected.Actors {
		matches := make([]corev1.Pod, 0, 1)
		for index := range pods {
			pod := pods[index]
			if pod.DeletionTimestamp == nil && pod.Labels["testing.stacks.org/network"] == network && pod.Labels["testing.stacks.org/actor"] == actor.Name {
				matches = append(matches, pod)
			}
		}
		_, podChangeAllowed := allowed[actor.Name]
		if len(matches) != 1 {
			if !podChangeAllowed {
				differences = append(differences, difference(actor.Name, "livePodCount", "1", fmt.Sprint(len(matches))))
			}
			continue
		}
		pod := matches[0]
		if string(pod.UID) != actor.PodUID && !podChangeAllowed {
			differences = append(differences, difference(actor.Name, "livePodUID", actor.PodUID, string(pod.UID)))
		}
		imageID := actorImageID(pod)
		if imageID != actor.RuntimeImageID && !(podChangeAllowed && imageID == "") {
			differences = append(differences, difference(actor.Name, "liveRuntimeImageID", actor.RuntimeImageID, imageID))
		}
	}
	return differences
}

func actorImageID(pod corev1.Pod) string {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "actor" {
			return status.ImageID
		}
	}
	return ""
}

// HasImmutableImageID reports whether a runtime image identity contains a
// complete SHA-256 content digest.
func HasImmutableImageID(value string) bool {
	return runtimeDigestPattern.MatchString(value)
}

// ImmutableImageID extracts one unambiguous SHA-256 identity from a runtime
// image reference.
func ImmutableImageID(value string) (string, bool) {
	matches := runtimeDigestPattern.FindAllString(value, -1)
	if len(matches) != 1 || !exactDigestPattern.MatchString(matches[0]) {
		return "", false
	}
	return matches[0], true
}

// RuntimeImageMatches reports whether a Kubernetes runtime image identity
// contains exactly the expected immutable SHA-256 identity.
func RuntimeImageMatches(value, expected string) bool {
	if !exactDigestPattern.MatchString(expected) {
		return false
	}
	actual, ok := ImmutableImageID(value)
	return ok && actual == expected
}

func identitiesByName(actors []testingv1.AdmittedActorIdentity) map[string]testingv1.AdmittedActorIdentity {
	result := make(map[string]testingv1.AdmittedActorIdentity, len(actors))
	for _, actor := range actors {
		result[actor.Name] = actor
	}
	return result
}

func validateIdentity(identity testingv1.AdmittedActorIdentity) error {
	values := map[string]string{
		"name": identity.Name, "role": identity.Role, "serviceName": identity.ServiceName,
		"statefulSetName": identity.StatefulSetName, "statefulSetUID": identity.StatefulSetUID,
		"controllerRevision": identity.ControllerRevision, "podName": identity.PodName,
		"podUID": identity.PodUID, "requestedImage": identity.RequestedImage,
		"runtimeImageID": identity.RuntimeImageID,
	}
	for field, value := range values {
		if value == "" {
			return fmt.Errorf("admitted identity lacks %s", field)
		}
	}
	if !HasImmutableImageID(identity.RuntimeImageID) {
		return errors.New("admitted identity lacks an immutable runtime image ID")
	}
	if identity.ConfigDigest != "" && !exactDigestPattern.MatchString(identity.ConfigDigest) {
		return errors.New("admitted identity has an invalid configuration digest")
	}
	if identity.AdversarialPolicyDigest != "" && !exactDigestPattern.MatchString(identity.AdversarialPolicyDigest) {
		return errors.New("admitted identity has an invalid adversarial policy digest")
	}
	switch identity.AdversarialEgressProfile {
	case "":
		if identity.EgressPolicyDigest != "" {
			return errors.New("admitted identity has an egress policy digest without an adversarial egress profile")
		}
	case "restricted":
		if !exactDigestPattern.MatchString(identity.EgressPolicyDigest) {
			return errors.New("restricted admitted identity lacks a valid egress policy digest")
		}
	case "unrestricted":
		if identity.EgressPolicyDigest != "" {
			return errors.New("unrestricted admitted identity must not name an egress NetworkPolicy digest")
		}
	default:
		return fmt.Errorf("admitted identity has unsupported adversarial egress profile %q", identity.AdversarialEgressProfile)
	}
	return nil
}

func toDigestActor(actor testingv1.AdmittedActorIdentity) digestActor {
	return digestActor{
		AdversarialEgressProfile: actor.AdversarialEgressProfile,
		AdversarialPolicyDigest:  actor.AdversarialPolicyDigest,
		EgressPolicyDigest:       actor.EgressPolicyDigest,
		ConfigDigest:             actor.ConfigDigest, ControllerRevision: actor.ControllerRevision, Name: actor.Name,
		PodName: actor.PodName, PodUID: actor.PodUID, RequestedImage: actor.RequestedImage,
		Role: actor.Role, RuntimeImageID: actor.RuntimeImageID, ServiceName: actor.ServiceName,
		StatefulSetName: actor.StatefulSetName, StatefulSetUID: actor.StatefulSetUID,
	}
}

func fromDigestActor(actor digestActor) testingv1.AdmittedActorIdentity {
	return testingv1.AdmittedActorIdentity{
		AdversarialEgressProfile: actor.AdversarialEgressProfile,
		AdversarialPolicyDigest:  actor.AdversarialPolicyDigest,
		EgressPolicyDigest:       actor.EgressPolicyDigest,
		ConfigDigest:             actor.ConfigDigest, ControllerRevision: actor.ControllerRevision, Name: actor.Name,
		PodName: actor.PodName, PodUID: actor.PodUID, RequestedImage: actor.RequestedImage,
		Role: actor.Role, RuntimeImageID: actor.RuntimeImageID, ServiceName: actor.ServiceName,
		StatefulSetName: actor.StatefulSetName, StatefulSetUID: actor.StatefulSetUID,
	}
}

func difference(actor, field, expected, observed string) testingv1.IdentityDifference {
	return testingv1.IdentityDifference{Scope: actor, Field: field, Expected: expected, Current: observed}
}

// DivergenceEvidence creates a bounded timestamped divergence record.
func DivergenceEvidence(expected testingv1.NetworkInventory, observedDigest string, differences []testingv1.IdentityDifference, at metav1.Time) *testingv1.IdentityDivergence {
	return &testingv1.IdentityDivergence{
		ExpectedDigest: expected.Digest, CurrentDigest: observedDigest,
		ObservedAt: at, Differences: differences,
	}
}
