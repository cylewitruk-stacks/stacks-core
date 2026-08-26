package v1beta1

import (
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ChainProgressAssertion requires every selected actor to advance by at least
// MinimumDelta during Window.
type ChainProgressAssertion struct {
	// +kubebuilder:validation:Enum=burnchain;stacks
	Chain string `json:"chain"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Actors []string        `json:"actors"`
	Window metav1.Duration `json:"window"`
	// +kubebuilder:validation:Minimum=1
	MinimumDelta int64 `json:"minimumDelta"`
}

// CohortAgreementAssertion bounds the selected actors' height spread.
type CohortAgreementAssertion struct {
	// +kubebuilder:validation:Enum=burnchain;stacks
	Chain string `json:"chain"`
	// +kubebuilder:validation:MinItems=2
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Actors []string `json:"actors"`
	// +kubebuilder:validation:Minimum=0
	MaximumSpread int64 `json:"maximumSpread"`
}

// SignerRegistrationAssertion requires a minimum count of selected signers to
// report current-cycle registration.
type SignerRegistrationAssertion struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Actors []string `json:"actors"`
	// +kubebuilder:validation:Minimum=1
	MinimumRegistered int32 `json:"minimumRegistered"`
}

// SignerStateFreshnessAssertion bounds the age of every selected signer's last
// state-machine transition.
type SignerStateFreshnessAssertion struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Actors     []string        `json:"actors"`
	MaximumAge metav1.Duration `json:"maximumAge"`
}

// ProposalOutcomeVisibilityAssertion requires proposal or policy activity to
// advance during Window for every selected signer.
type ProposalOutcomeVisibilityAssertion struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Actors []string        `json:"actors"`
	Window metav1.Duration `json:"window"`
	// +kubebuilder:validation:Minimum=1
	MinimumObserved int64 `json:"minimumObserved"`
}

// TelemetryCompletenessAssertion requires successful collection from every
// selected admitted actor in one stable identity window.
type TelemetryCompletenessAssertion struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Actors []string `json:"actors"`
}

// ProtocolAssertionSpec is one finite protocol assertion. Arbitrary queries
// and actor-supplied success predicates are intentionally unsupported.
// +kubebuilder:validation:XValidation:rule="(has(self.chainProgress) ? 1 : 0) + (has(self.cohortAgreement) ? 1 : 0) + (has(self.signerRegistration) ? 1 : 0) + (has(self.signerStateFreshness) ? 1 : 0) + (has(self.proposalOutcomeVisibility) ? 1 : 0) + (has(self.telemetryCompleteness) ? 1 : 0) == 1",message="exactly one protocol assertion must be configured"
type ProtocolAssertionSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	ID                        string                              `json:"id"`
	ChainProgress             *ChainProgressAssertion             `json:"chainProgress,omitempty"`
	CohortAgreement           *CohortAgreementAssertion           `json:"cohortAgreement,omitempty"`
	SignerRegistration        *SignerRegistrationAssertion        `json:"signerRegistration,omitempty"`
	SignerStateFreshness      *SignerStateFreshnessAssertion      `json:"signerStateFreshness,omitempty"`
	ProposalOutcomeVisibility *ProposalOutcomeVisibilityAssertion `json:"proposalOutcomeVisibility,omitempty"`
	TelemetryCompleteness     *TelemetryCompletenessAssertion     `json:"telemetryCompleteness,omitempty"`
}

// ProtocolAssertionSetSpec is a bounded assertion gate with one failure
// deadline for missing or unavailable evidence.
type ProtocolAssertionSetSpec struct {
	Timeout metav1.Duration `json:"timeout"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=id
	Assertions []ProtocolAssertionSpec `json:"assertions"`
}

// ProtocolAssertionResult records one bounded evaluator result.
type ProtocolAssertionResult struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// +kubebuilder:validation:Enum=Pending;Proven;Violated;Inconclusive
	Outcome    string       `json:"outcome"`
	Reason     string       `json:"reason"`
	StartedAt  *metav1.Time `json:"startedAt,omitempty"`
	ObservedAt *metav1.Time `json:"observedAt,omitempty"`
	Evidence   apixv1.JSON  `json:"evidence,omitempty"`
}

// ProtocolAssertionSetStatus records one run gate's bounded state.
type ProtocolAssertionSetStatus struct {
	// +kubebuilder:validation:Enum=Pending;Proven;Violated;Inconclusive
	Outcome     string                    `json:"outcome"`
	StartedAt   *metav1.Time              `json:"startedAt,omitempty"`
	CompletedAt *metav1.Time              `json:"completedAt,omitempty"`
	Results     []ProtocolAssertionResult `json:"results,omitempty"`
}

// ProtocolAssertionsStatus records baseline, active-fault, and recovery gates.
type ProtocolAssertionsStatus struct {
	Baseline *ProtocolAssertionSetStatus `json:"baseline,omitempty"`
	During   *ProtocolAssertionSetStatus `json:"during,omitempty"`
	Recovery *ProtocolAssertionSetStatus `json:"recovery,omitempty"`
}
