package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AdmittedActorIdentity is the immutable runtime identity admitted for one actor.
type AdmittedActorIdentity struct {
	Name                     string `json:"name"`
	Role                     string `json:"role"`
	ServiceName              string `json:"serviceName"`
	StatefulSetName          string `json:"statefulSetName"`
	StatefulSetUID           string `json:"statefulSetUID"`
	ControllerRevision       string `json:"controllerRevision"`
	PodName                  string `json:"podName"`
	PodUID                   string `json:"podUID"`
	RequestedImage           string `json:"requestedImage"`
	RuntimeImageID           string `json:"runtimeImageID"`
	ConfigDigest             string `json:"configDigest,omitempty"`
	AdversarialPolicyDigest  string `json:"adversarialPolicyDigest,omitempty"`
	AdversarialEgressProfile string `json:"adversarialEgressProfile,omitempty"`
	EgressPolicyDigest       string `json:"egressPolicyDigest,omitempty"`
}

// NetworkInventory is the complete authoritative actor inventory bound to a run.
type NetworkInventory struct {
	Digest             string                  `json:"digest"`
	ObservedGeneration int64                   `json:"observedGeneration"`
	ObservedAt         *metav1.Time            `json:"observedAt,omitempty"`
	ResourceVersion    string                  `json:"resourceVersion,omitempty"`
	Actors             []AdmittedActorIdentity `json:"actors"`
}

// IdentityDivergence records an immutable identity mismatch without retargeting.
type IdentityDivergence struct {
	ExpectedDigest string               `json:"expectedDigest,omitempty"`
	CurrentDigest  string               `json:"currentDigest,omitempty"`
	ObservedAt     metav1.Time          `json:"observedAt"`
	Differences    []IdentityDifference `json:"differences,omitempty"`
}

// IdentityDifference describes one bounded inventory mismatch.
type IdentityDifference struct {
	Scope    string `json:"scope,omitempty"`
	Field    string `json:"field"`
	Expected string `json:"expected,omitempty"`
	Current  string `json:"current,omitempty"`
	Message  string `json:"message,omitempty"`
}

// IdentityTransition records an explicitly permitted Pod identity replacement.
type IdentityTransition struct {
	Campaign       string      `json:"campaign"`
	Actors         []string    `json:"actors"`
	PreviousDigest string      `json:"previousDigest"`
	CurrentDigest  string      `json:"currentDigest"`
	ObservedAt     metav1.Time `json:"observedAt"`
}
