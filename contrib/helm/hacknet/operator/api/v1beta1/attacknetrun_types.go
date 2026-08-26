package v1beta1

import (
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AttacknetRun declares a finite reproducible schedule of FaultCampaigns.
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

// CampaignCatalogEntry binds a logical name to an immutable campaign template.
type CampaignCatalogEntry struct {
	Name               string `json:"name"`
	CampaignRef        string `json:"campaignRef"`
	ExpectedUID        string `json:"expectedUID,omitempty"`
	ExpectedGeneration *int64 `json:"expectedGeneration,omitempty"`
	ExpectedSpecDigest string `json:"expectedSpecDigest,omitempty"`
}

// RunExecutionSpec identifies one campaign execution in the schedule DAG.
type RunExecutionSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	ID        string                   `json:"id"`
	Campaign  string                   `json:"campaign"`
	Trigger   RunTriggerSpec           `json:"trigger,omitempty"`
	DependsOn []RunExecutionDependency `json:"dependsOn,omitempty"`
	Enabled   *bool                    `json:"enabled,omitempty"`
}

// RunTriggerSpec defines a trusted condition that makes an execution eligible.
// +kubebuilder:validation:XValidation:rule="(has(self.afterRunStart) ? 1 : 0) + (has(self.burnHeight) ? 1 : 0) + (has(self.stacksHeight) ? 1 : 0) + (has(self.observation) ? 1 : 0) <= 1",message="at most one run trigger may be set"
type RunTriggerSpec struct {
	AfterRunStart *metav1.Duration        `json:"afterRunStart,omitempty"`
	BurnHeight    *int64                  `json:"burnHeight,omitempty"`
	StacksHeight  *int64                  `json:"stacksHeight,omitempty"`
	Observation   *ObservationTriggerSpec `json:"observation,omitempty"`
}

// RunExecutionDependency waits for another execution to reach a named state.
type RunExecutionDependency struct {
	Execution string `json:"execution"`
	// +kubebuilder:validation:Enum=Injected;Effective;Recovered;Terminal
	State string          `json:"state"`
	Delay metav1.Duration `json:"delay,omitempty"`
}

// RunBudgets bound aggregate mutation, duration, concurrency, and ambiguity.
// +kubebuilder:validation:XValidation:rule="self.maxCumulativeFaultSeconds <= self.maxWallTimeSeconds",message="maxCumulativeFaultSeconds cannot exceed maxWallTimeSeconds"
type RunBudgets struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1024
	MaxCampaigns int32 `json:"maxCampaigns"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=604800
	MaxWallTimeSeconds int32 `json:"maxWallTimeSeconds"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=604800
	MaxCumulativeFaultSeconds int32 `json:"maxCumulativeFaultSeconds"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=512
	MaxActiveFaults int32 `json:"maxActiveFaults"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MaxSignerImpactPercent int32 `json:"maxSignerImpactPercent"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	MaxBurnchainFaults int32 `json:"maxBurnchainFaults"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=64
	MaxInconclusiveCampaigns int32 `json:"maxInconclusiveCampaigns"`
}

// StopPolicy defines terminal handling for each campaign outcome.
type StopPolicy struct {
	// +kubebuilder:validation:Enum=Continue;Stop;PauseForTriage
	OnCampaignFailure string `json:"onCampaignFailure"`
	// +kubebuilder:validation:Enum=Continue;Stop;PauseForTriage
	OnInconclusive string `json:"onInconclusive"`
	// +kubebuilder:validation:Enum=Stop;Pause
	OnBudgetExhausted string `json:"onBudgetExhausted"`
	// +kubebuilder:validation:Enum=Continue;Stop
	OnSuccess string `json:"onSuccess"`
}

// AttributionPolicy requires attributable evidence for adverse outcomes.
type AttributionPolicy struct {
	RequiredOnFailure     bool     `json:"requiredOnFailure"`
	RequireIncidentBundle bool     `json:"requireIncidentBundle"`
	AllowedTerminalStates []string `json:"allowedTerminalStates"`
}

// ReplaySpec pins a run to an immutable prior descriptor and expectation.
// +kubebuilder:validation:XValidation:rule="!self.enabled || (has(self.sourceRunRef) && has(self.descriptorURI) && has(self.descriptorDigest) && has(self.attemptId) && (!self.verifyExpectedFailure || (has(self.expectedAssertion) && has(self.expectedStatus))))",message="enabled replay requires immutable source, descriptor, attempt, and expected-failure fields"
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

// ResumeSpec identifies a prior run execution boundary to resume after.
// +kubebuilder:validation:XValidation:rule="!self.enabled || (has(self.sourceRunRef) && has(self.afterExecutionId))",message="enabled resume requires sourceRunRef and afterExecutionId"
type ResumeSpec struct {
	Enabled                   bool   `json:"enabled"`
	SourceRunRef              string `json:"sourceRunRef,omitempty"`
	AfterExecutionID          string `json:"afterExecutionId,omitempty"`
	RequireSameSeed           bool   `json:"requireSameSeed"`
	RequireSameResolvedImages bool   `json:"requireSameResolvedImages"`
}

// RetainedExecution describes one removal-only minimization candidate.
type RetainedExecution struct {
	ExecutionID       string   `json:"executionId"`
	RemovedStages     []string `json:"removedStages,omitempty"`
	RemovedActions    []string `json:"removedActions,omitempty"`
	RemovedTargets    []string `json:"removedTargets,omitempty"`
	RemovedParameters []string `json:"removedParameters,omitempty"`
}

// MinimizationSpec describes one bounded, fresh-network delta-debug attempt.
// +kubebuilder:validation:XValidation:rule="self.enabled || self.maxAttempts == 0",message="disabled minimization requires maxAttempts=0"
// +kubebuilder:validation:XValidation:rule="!self.enabled || (self.strategy == 'DeltaDebug' && self.maxAttempts == 1 && self.requireFreshNetwork && has(self.sourceRunRef) && has(self.sourceScheduleDigest) && has(self.attemptId) && has(self.expectedAssertion) && has(self.expectedStatus) && has(self.retained) && self.retained.size() > 0)",message="enabled minimization requires one bounded fresh-network DeltaDebug attempt and immutable source and expectation fields"
type MinimizationSpec struct {
	Enabled bool `json:"enabled"`
	// +kubebuilder:validation:Enum=DeltaDebug;FailurePrefix
	Strategy                string              `json:"strategy"`
	MaxAttempts             int32               `json:"maxAttempts"`
	RequireFreshNetwork     bool                `json:"requireFreshNetwork"`
	SourceRunRef            string              `json:"sourceRunRef,omitempty"`
	SourceScheduleDigest    string              `json:"sourceScheduleDigest,omitempty"`
	AttemptID               string              `json:"attemptId,omitempty"`
	CandidateScheduleDigest string              `json:"candidateScheduleDigest,omitempty"`
	ExpectedAssertion       string              `json:"expectedAssertion,omitempty"`
	ExpectedStatus          string              `json:"expectedStatus,omitempty"`
	Retained                []RetainedExecution `json:"retained,omitempty"`
}

// AttacknetRunSpec defines a finite schedule and its safety/evidence policy.
// +kubebuilder:validation:XValidation:rule="(self.replay.enabled ? 1 : 0) + (self.resume.enabled ? 1 : 0) + (self.minimization.enabled ? 1 : 0) <= 1",message="replay, resume, and minimization are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="self.executions.filter(execution, !has(execution.enabled) || execution.enabled).size() <= self.budgets.maxCampaigns",message="enabled executions exceed maxCampaigns budget"
type AttacknetRunSpec struct {
	NetworkRef string `json:"networkRef"`
	Seed       string `json:"seed"`
	// +kubebuilder:validation:Enum=dependency-trigger-scheduler/v1
	DecisionAlgorithm string `json:"decisionAlgorithm,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=name
	CampaignCatalog []CampaignCatalogEntry `json:"campaignCatalog"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1024
	// +listType=map
	// +listMapKey=id
	Executions        []RunExecutionSpec `json:"executions"`
	Budgets           RunBudgets         `json:"budgets"`
	StopPolicy        StopPolicy         `json:"stopPolicy"`
	AttributionPolicy AttributionPolicy  `json:"attributionPolicy"`
	Replay            ReplaySpec         `json:"replay"`
	Resume            ResumeSpec         `json:"resume"`
	Minimization      MinimizationSpec   `json:"minimization"`
}

// ScheduleReference identifies the immutable controller-owned schedule object.
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
	Executions            int32            `json:"executions"`
	Replay                bool             `json:"replay"`
	NetworkUID            string           `json:"networkUid"`
	NetworkGeneration     int64            `json:"networkGeneration"`
	ManifestDigest        string           `json:"manifestDigest"`
	SignerSetRewardCycle  *int64           `json:"signerSetRewardCycle,omitempty"`
	SignerSetTotalWeight  *int64           `json:"signerSetTotalWeight,omitempty"`
	SignerSetDigest       string           `json:"signerSetDigest,omitempty"`
	SignerSetObservedFrom string           `json:"signerSetObservedFrom,omitempty"`
	NetworkInventory      NetworkInventory `json:"networkInventory"`
}

// ActiveRunChild identifies one currently executing campaign child.
type ActiveRunChild struct {
	ExecutionID string       `json:"executionId"`
	Name        string       `json:"name"`
	UID         string       `json:"uid"`
	StartedAt   *metav1.Time `json:"startedAt,omitempty"`
}

// ResolvedCampaign records immutable source-template identity.
type ResolvedCampaign struct {
	Name             string `json:"name"`
	SourceName       string `json:"sourceName"`
	SourceUID        string `json:"sourceUID"`
	SourceGeneration int64  `json:"sourceGeneration"`
	SpecDigest       string `json:"specDigest"`
}

// BudgetUsage reports aggregate consumption of sealed run budgets.
type BudgetUsage struct {
	Campaigns                      int32 `json:"campaigns,omitempty"`
	CampaignsStarted               int32 `json:"campaignsStarted,omitempty"`
	CampaignsCompleted             int32 `json:"campaignsCompleted,omitempty"`
	ActiveCampaigns                int32 `json:"activeCampaigns,omitempty"`
	ActiveFaults                   int32 `json:"activeFaults,omitempty"`
	WallTimeMillis                 int64 `json:"wallTimeMillis,omitempty"`
	CumulativeFaultMillis          int64 `json:"cumulativeFaultMillis,omitempty"`
	MaximumSignerImpactBasisPoints int32 `json:"maximumSignerImpactBasisPoints,omitempty"`
	BurnchainFaults                int32 `json:"burnchainFaults,omitempty"`
	InconclusiveCampaigns          int32 `json:"inconclusiveCampaigns,omitempty"`
	MinimizationAttempts           int32 `json:"minimizationAttempts,omitempty"`
}

// TerminalClassification records expected-versus-observed replay evidence.
type TerminalClassification struct {
	AttemptID               string        `json:"attemptId,omitempty"`
	CandidateScheduleDigest string        `json:"candidateScheduleDigest,omitempty"`
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

// RunCleanup reports cleanup completeness independently from run outcome.
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
	ActiveChildren         []ActiveRunChild        `json:"activeChildren,omitempty"`
	ScheduleRef            *ScheduleReference      `json:"scheduleRef,omitempty"`
	ScheduleSummary        *ScheduleSummary        `json:"scheduleSummary,omitempty"`
	ResolvedCampaigns      []ResolvedCampaign      `json:"resolvedCampaigns,omitempty"`
	Decisions              []apixv1.JSON           `json:"decisions,omitempty"`
	TriggerReceipts        []apixv1.JSON           `json:"triggerReceipts,omitempty"`
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
