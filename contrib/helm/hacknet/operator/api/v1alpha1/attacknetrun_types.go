package v1alpha1

import (
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AttacknetRun declares a finite reproducible sequence of FaultCampaign templates.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type AttacknetRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AttacknetRunSpec   `json:"spec"`
	Status AttacknetRunStatus `json:"status,omitempty"`
}

// AttacknetRunList contains AttacknetRun objects.
// +kubebuilder:object:root=true
type AttacknetRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AttacknetRun `json:"items"`
}

// CampaignCatalogEntry binds a logical catalog name to an immutable template.
type CampaignCatalogEntry struct {
	Name               string `json:"name"`
	CampaignRef        string `json:"campaignRef"`
	ExpectedUID        string `json:"expectedUID,omitempty"`
	ExpectedGeneration *int64 `json:"expectedGeneration,omitempty"`
	ExpectedSpecDigest string `json:"expectedSpecDigest,omitempty"`
}

// RunInstruction identifies one ordered template execution.
type RunInstruction struct {
	ID                string `json:"id"`
	Campaign          string `json:"campaign"`
	DelayAfterSeconds int32  `json:"delayAfterSeconds,omitempty"`
	Enabled           *bool  `json:"enabled,omitempty"`
}

// RunBudgets bound aggregate mutation, duration, and ambiguity.
type RunBudgets struct {
	MaxCampaigns              int32 `json:"maxCampaigns"`
	MaxWallTimeSeconds        int32 `json:"maxWallTimeSeconds"`
	MaxCumulativeFaultSeconds int32 `json:"maxCumulativeFaultSeconds"`
	MaxActiveFaults           int32 `json:"maxActiveFaults"`
	MaxSignerImpactPercent    int32 `json:"maxSignerImpactPercent"`
	MaxBurnchainFaults        int32 `json:"maxBurnchainFaults"`
	MaxInconclusiveCampaigns  int32 `json:"maxInconclusiveCampaigns"`
}

// StopPolicy defines terminal handling for each campaign outcome.
type StopPolicy struct {
	OnCampaignFailure string `json:"onCampaignFailure"`
	OnInconclusive    string `json:"onInconclusive"`
	OnBudgetExhausted string `json:"onBudgetExhausted"`
	OnSuccess         string `json:"onSuccess"`
}

// AttributionPolicy requires attributable evidence for adverse outcomes.
type AttributionPolicy struct {
	RequiredOnFailure     bool     `json:"requiredOnFailure"`
	RequireIncidentBundle bool     `json:"requireIncidentBundle"`
	AllowedTerminalStates []string `json:"allowedTerminalStates"`
}

// ReplaySpec pins a run to an immutable prior descriptor and expectation.
type ReplaySpec struct {
	Enabled                   bool   `json:"enabled"`
	SourceRunRef              string `json:"sourceRunRef,omitempty"`
	DescriptorURI             string `json:"descriptorURI,omitempty"`
	DescriptorDigest          string `json:"descriptorDigest,omitempty"`
	AttemptID                 string `json:"attemptId,omitempty"`
	ExpectedAssertion         string `json:"expectedAssertion,omitempty"`
	ExpectedStatus            string `json:"expectedStatus,omitempty"`
	RequireSameResolvedImages bool   `json:"requireSameResolvedImages"`
	VerifyExpectedFailure     bool   `json:"verifyExpectedFailure"`
}

// ResumeSpec identifies a prior run instruction boundary to resume after.
type ResumeSpec struct {
	Enabled                   bool   `json:"enabled"`
	SourceRunRef              string `json:"sourceRunRef,omitempty"`
	AfterInstructionID        string `json:"afterInstructionId,omitempty"`
	RequireSameSeed           bool   `json:"requireSameSeed"`
	RequireSameResolvedImages bool   `json:"requireSameResolvedImages"`
}

// RetainedInstruction describes one removal-only minimization candidate.
type RetainedInstruction struct {
	InstructionID     string   `json:"instructionId"`
	RemovedTargets    []string `json:"removedTargets"`
	RemovedParameters []string `json:"removedParameters"`
}

// MinimizationSpec describes one bounded, fresh-network delta-debug attempt.
type MinimizationSpec struct {
	Enabled              bool                  `json:"enabled"`
	Strategy             string                `json:"strategy"`
	MaxAttempts          int32                 `json:"maxAttempts"`
	RequireFreshNetwork  bool                  `json:"requireFreshNetwork"`
	SourceRunRef         string                `json:"sourceRunRef,omitempty"`
	SourceScheduleDigest string                `json:"sourceScheduleDigest,omitempty"`
	AttemptID            string                `json:"attemptId,omitempty"`
	CandidateDigest      string                `json:"candidateDigest,omitempty"`
	ExpectedAssertion    string                `json:"expectedAssertion,omitempty"`
	ExpectedStatus       string                `json:"expectedStatus,omitempty"`
	Retained             []RetainedInstruction `json:"retained,omitempty"`
}

// AttacknetRunSpec defines a finite schedule and its safety/evidence policy.
type AttacknetRunSpec struct {
	NetworkRef        string                 `json:"networkRef"`
	Seed              string                 `json:"seed"`
	DecisionAlgorithm string                 `json:"decisionAlgorithm,omitempty"`
	CampaignCatalog   []CampaignCatalogEntry `json:"campaignCatalog"`
	Sequence          []RunInstruction       `json:"sequence"`
	Budgets           RunBudgets             `json:"budgets"`
	StopPolicy        StopPolicy             `json:"stopPolicy"`
	AttributionPolicy AttributionPolicy      `json:"attributionPolicy"`
	Replay            ReplaySpec             `json:"replay"`
	Resume            ResumeSpec             `json:"resume"`
	Minimization      MinimizationSpec       `json:"minimization"`
}

// ScheduleReference identifies the immutable controller-owned schedule ConfigMap.
type ScheduleReference struct {
	Name          string `json:"name"`
	UID           string `json:"uid"`
	Digest        string `json:"digest"`
	RunGeneration int64  `json:"runGeneration"`
	RunSpecDigest string `json:"runSpecDigest"`
}

// ScheduleSummary records immutable topology and schedule admission facts.
type ScheduleSummary struct {
	SchemaVersion         string           `json:"schemaVersion"`
	Actions               int32            `json:"actions"`
	Replay                bool             `json:"replay"`
	NetworkUID            string           `json:"networkUid"`
	NetworkGeneration     int64            `json:"networkGeneration"`
	ManifestDigest        string           `json:"manifestDigest"`
	SignerSetRewardCycle  *int64           `json:"signerSetRewardCycle,omitempty"`
	SignerSetTotalWeight  *float64         `json:"signerSetTotalWeight,omitempty"`
	SignerSetDigest       string           `json:"signerSetDigest,omitempty"`
	SignerSetObservedFrom string           `json:"signerSetObservedFrom,omitempty"`
	NetworkInventory      NetworkInventory `json:"networkInventory"`
}

// ActiveRunChild identifies the currently executing campaign child.
type ActiveRunChild struct {
	InstructionID string       `json:"instructionId"`
	Name          string       `json:"name"`
	UID           string       `json:"uid"`
	StartedAt     *metav1.Time `json:"startedAt,omitempty"`
}

// ResolvedCampaign records immutable source-template identity.
type ResolvedCampaign struct {
	Name             string `json:"name"`
	SourceName       string `json:"sourceName"`
	SourceUID        string `json:"sourceUID"`
	SourceGeneration int64  `json:"sourceGeneration"`
	SpecDigest       string `json:"specDigest"`
}

// BudgetUsage reports aggregate consumption of the sealed run budgets.
type BudgetUsage struct {
	Campaigns                  int32   `json:"campaigns,omitempty"`
	CampaignsStarted           int32   `json:"campaignsStarted,omitempty"`
	CampaignsCompleted         int32   `json:"campaignsCompleted,omitempty"`
	ActiveFaults               int32   `json:"activeFaults,omitempty"`
	WallTimeSeconds            float64 `json:"wallTimeSeconds,omitempty"`
	CumulativeFaultSeconds     float64 `json:"cumulativeFaultSeconds,omitempty"`
	MaximumSignerImpactPercent float64 `json:"maximumSignerImpactPercent,omitempty"`
	BurnchainFaults            int32   `json:"burnchainFaults,omitempty"`
	InconclusiveCampaigns      int32   `json:"inconclusiveCampaigns,omitempty"`
	MinimizationAttempts       int32   `json:"minimizationAttempts,omitempty"`
}

// TerminalClassification records expected-versus-observed replay/minimization evidence.
type TerminalClassification struct {
	AttemptID               string        `json:"attemptId,omitempty"`
	CandidateDigest         string        `json:"candidateDigest,omitempty"`
	ExpectedAssertion       string        `json:"expectedAssertion,omitempty"`
	ExpectedStatus          string        `json:"expectedStatus,omitempty"`
	Outcome                 string        `json:"outcome,omitempty"`
	Reason                  string        `json:"reason,omitempty"`
	ObservationCount        int32         `json:"observationCount,omitempty"`
	Observations            []apixv1.JSON `json:"observations,omitempty"`
	EvidenceDigest          string        `json:"evidenceDigest,omitempty"`
	EvidenceURI             string        `json:"evidenceURI,omitempty"`
	CausalMinimalityClaimed bool          `json:"causalMinimalityClaimed,omitempty"`
}

// RunCleanup reports cleanup completeness independently from the run outcome.
type RunCleanup struct {
	Required    bool         `json:"required"`
	Completed   bool         `json:"completed"`
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	Message     string       `json:"message,omitempty"`
}

// AttacknetRunStatus is the durable scheduler and evidence state machine.
type AttacknetRunStatus struct {
	ObservedGeneration     int64                   `json:"observedGeneration,omitempty"`
	Phase                  string                  `json:"phase,omitempty"`
	Reason                 string                  `json:"reason,omitempty"`
	Message                string                  `json:"message,omitempty"`
	LastTransitionTime     *metav1.Time            `json:"lastTransitionTime,omitempty"`
	StartedAt              *metav1.Time            `json:"startedAt,omitempty"`
	CompletedAt            *metav1.Time            `json:"completedAt,omitempty"`
	FinishedAt             *metav1.Time            `json:"finishedAt,omitempty"`
	ActiveCampaign         *string                 `json:"activeCampaign,omitempty"`
	ScheduleRef            *ScheduleReference      `json:"scheduleRef,omitempty"`
	ScheduleSummary        *ScheduleSummary        `json:"scheduleSummary,omitempty"`
	ActiveChild            *ActiveRunChild         `json:"activeChild,omitempty"`
	ResolvedCampaigns      []ResolvedCampaign      `json:"resolvedCampaigns,omitempty"`
	Decisions              []apixv1.JSON           `json:"decisions,omitempty"`
	BudgetUsage            *BudgetUsage            `json:"budgetUsage,omitempty"`
	IdentityDivergence     *IdentityDivergence     `json:"identityDivergence,omitempty"`
	IdentityTransitions    []IdentityTransition    `json:"identityTransitions,omitempty"`
	Attribution            string                  `json:"attribution,omitempty"`
	AttributionURI         string                  `json:"attributionURI,omitempty"`
	ReplayPlanURI          string                  `json:"replayPlanURI,omitempty"`
	EvidenceURI            string                  `json:"evidenceURI,omitempty"`
	EvidenceDigest         string                  `json:"evidenceDigest,omitempty"`
	TerminalClassification *TerminalClassification `json:"terminalClassification,omitempty"`
	Cleanup                *RunCleanup             `json:"cleanup,omitempty"`
	Conditions             []metav1.Condition      `json:"conditions,omitempty"`
}
