package v1beta1

import (
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// FaultCampaign declares one bounded, attributable graph of fault stages.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type FaultCampaign struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FaultCampaignSpec   `json:"spec"`
	Status FaultCampaignStatus `json:"status,omitempty"`
}

// FaultCampaignList contains FaultCampaign objects.
// +kubebuilder:object:root=true
type FaultCampaignList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FaultCampaign `json:"items"`
}

// FaultCampaignSpec defines staged injection, aggregate safety, and evidence.
// +kubebuilder:validation:XValidation:rule="(has(self.template) && self.template) || (has(self.networkRef) && self.networkRef.size() > 0)",message="executable campaigns require networkRef"
// +kubebuilder:validation:XValidation:rule="self.safety.allowBurnchain || !self.stages.exists(stage, stage.faults.exists(fault, fault.fault.type == 'burnchain-reorg' || (has(fault.target.roles) && fault.target.roles.exists(role, role == 'burnchain'))))",message="burnchain faults require safety.allowBurnchain=true"
type FaultCampaignSpec struct {
	Template bool `json:"template,omitempty"`
	// NetworkRef is optional only for an inert, reusable template. AttacknetRun
	// binds a neutral template to its admitted network in the sealed execution.
	NetworkRef string `json:"networkRef,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=id
	Stages             []FaultStageSpec    `json:"stages"`
	Safety             FaultSafety         `json:"safety"`
	EffectAssertions   []CampaignAssertion `json:"effectAssertions,omitempty"`
	RecoveryAssertions []CampaignAssertion `json:"recoveryAssertions,omitempty"`
}

// FaultStageSpec groups actions admitted and coordinated as one bounded stage.
type FaultStageSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	ID           string           `json:"id"`
	Trigger      StageTriggerSpec `json:"trigger,omitempty"`
	MaxStartSkew metav1.Duration  `json:"maxStartSkew,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=id
	Faults             []FaultActionSpec   `json:"faults"`
	EffectAssertions   []CampaignAssertion `json:"effectAssertions,omitempty"`
	RecoveryAssertions []CampaignAssertion `json:"recoveryAssertions,omitempty"`
	// +kubebuilder:validation:Enum=all
	CompletionPolicy string `json:"completionPolicy,omitempty"`
}

// StageTriggerSpec defines the trusted condition that makes a stage eligible.
// +kubebuilder:validation:XValidation:rule="(has(self.afterCampaignStart) ? 1 : 0) + (has(self.afterStage) ? 1 : 0) + (has(self.burnHeight) ? 1 : 0) + (has(self.stacksHeight) ? 1 : 0) + (has(self.observation) ? 1 : 0) <= 1",message="at most one stage trigger may be set"
type StageTriggerSpec struct {
	AfterCampaignStart *metav1.Duration        `json:"afterCampaignStart,omitempty"`
	AfterStage         *StageDependency        `json:"afterStage,omitempty"`
	BurnHeight         *int64                  `json:"burnHeight,omitempty"`
	StacksHeight       *int64                  `json:"stacksHeight,omitempty"`
	Observation        *ObservationTriggerSpec `json:"observation,omitempty"`
}

// StageDependency waits for a prior stage to reach a named durable state.
type StageDependency struct {
	Stage string `json:"stage"`
	// +kubebuilder:validation:Enum=Injected;Effective;Recovered;Terminal
	State string          `json:"state"`
	Delay metav1.Duration `json:"delay,omitempty"`
}

// ObservationTriggerSpec waits for one bounded trusted observation.
type ObservationTriggerSpec struct {
	Type           string `json:"type"`
	Actor          string `json:"actor,omitempty"`
	Expected       string `json:"expected,omitempty"`
	TimeoutSeconds int32  `json:"timeoutSeconds"`
}

// FaultActionSpec defines one fault action within a stage.
// +kubebuilder:validation:XValidation:rule="self.fault.type != 'burnchain-reorg' || (has(self.target.actors) && self.target.actors.size() == 1 && (!has(self.target.roles) || self.target.roles.size() == 0) && self.target.mode == 'one' && !has(self.target.value))",message="burnchain-reorg must target exactly one named Bitcoin actor with mode one and no value"
type FaultActionSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	ID                 string              `json:"id"`
	Target             FaultTarget         `json:"target"`
	Fault              FaultSpec           `json:"fault"`
	EffectAssertions   []CampaignAssertion `json:"effectAssertions,omitempty"`
	RecoveryAssertions []CampaignAssertion `json:"recoveryAssertions,omitempty"`
}

// FaultTarget selects enrolled actors by exact name or bounded role.
// +kubebuilder:validation:XValidation:rule="(has(self.actors) && self.actors.size() > 0) || (has(self.roles) && self.roles.size() > 0)",message="target requires actors or roles"
type FaultTarget struct {
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Actors []string `json:"actors,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Roles []string `json:"roles,omitempty"`
	// +kubebuilder:validation:Enum=one;all;fixed;fixed-percent;random-max-percent
	Mode  string              `json:"mode,omitempty"`
	Value *intstr.IntOrString `json:"value,omitempty"`
}

// FaultSpec defines one finite mechanism and its bounded parameters.
// +kubebuilder:validation:XValidation:rule="(self.type == 'pod' && self.action in ['pod-kill', 'pod-failure', 'container-kill']) || (self.type == 'network' && self.action in ['netem', 'delay', 'loss', 'duplicate', 'corrupt', 'partition', 'bandwidth']) || (self.type == 'dns' && self.action in ['error', 'random']) || (self.type == 'io' && self.action in ['latency', 'fault', 'mistake', 'attrOverride']) || (self.type == 'io-pressure' && self.action == 'disk-pressure') || (self.type in ['time', 'clock-skew', 'burnchain-reorg'] && !has(self.action))",message="fault action must be valid for its type"
// +kubebuilder:validation:XValidation:rule="(self.mode in ['one', 'all'] && !has(self.value)) || (self.mode in ['fixed', 'fixed-percent', 'random-max-percent'] && has(self.value))",message="fault value is required only for fixed and percent modes"
// +kubebuilder:validation:XValidation:rule="self.type == 'burnchain-reorg' ? has(self.burnchainReorg) : !has(self.burnchainReorg)",message="burnchainReorg is required only for burnchain-reorg faults"
type FaultSpec struct {
	// +kubebuilder:validation:Enum=pod;network;dns;io;time;io-pressure;clock-skew;burnchain-reorg
	Type string `json:"type"`
	// +kubebuilder:validation:Enum=pod-kill;pod-failure;container-kill;netem;delay;loss;duplicate;corrupt;partition;bandwidth;error;random;latency;fault;mistake;attrOverride;disk-pressure
	Action string `json:"action,omitempty"`
	// +kubebuilder:validation:Enum=one;all;fixed;fixed-percent;random-max-percent
	Mode       string              `json:"mode"`
	Value      *intstr.IntOrString `json:"value,omitempty"`
	Duration   metav1.Duration     `json:"duration"`
	Parameters apixv1.JSON         `json:"parameters,omitempty"`
	// BurnchainReorg declares the bounded semantic operation. Raw Bitcoin RPC
	// methods are intentionally not part of the campaign API.
	BurnchainReorg *BurnchainReorgFaultSpec `json:"burnchainReorg,omitempty"`
}

// BurnchainReorgFaultSpec replaces a bounded suffix of one regtest chain.
// +kubebuilder:validation:XValidation:rule="self.replacementBlocks > self.depth",message="replacementBlocks must exceed depth"
type BurnchainReorgFaultSpec struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=144
	Depth int32 `json:"depth"`
	// ReplacementBlocks must exceed Depth so the replacement branch has more
	// proof of work after the original invalidity marker is reconsidered.
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=288
	ReplacementBlocks int32 `json:"replacementBlocks"`
	// ReplacementInterval controls the cadence of the replacement branch.
	ReplacementInterval metav1.Duration `json:"replacementInterval,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=63
	DestinationIndex int32 `json:"destinationIndex,omitempty"`
}

// FaultSafety contains aggregate bounds and conspicuous dangerous-fault opt-ins.
type FaultSafety struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10000
	MaxUnavailableSignerBasisPoints int32 `json:"maxUnavailableSignerBasisPoints"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10000
	MaxUnavailableMinerBasisPoints int32 `json:"maxUnavailableMinerBasisPoints"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=512
	MaxConcurrentFaults      int32 `json:"maxConcurrentFaults"`
	AllowQuorumLoss          bool  `json:"allowQuorumLoss"`
	AllowBurnchain           bool  `json:"allowBurnchain"`
	AllowExtendedDuration    bool  `json:"allowExtendedDuration"`
	AllowExtremeSeverity     bool  `json:"allowExtremeSeverity"`
	AllowMinerMajorityOutage bool  `json:"allowMinerMajorityOutage"`
	AllowUnenrolledTargets   bool  `json:"allowUnenrolledNetworkTargets"`
	// MaxBurnchainReorgDepth and MaxBurnchainReplacementBlocks are required
	// per-campaign ceilings for semantic burnchain reorganization actions.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=144
	MaxBurnchainReorgDepth int32 `json:"maxBurnchainReorgDepth,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=288
	MaxBurnchainReplacementBlocks    int32 `json:"maxBurnchainReplacementBlocks,omitempty"`
	AllowEpochBoundaryCrossing       bool  `json:"allowEpochBoundaryCrossing,omitempty"`
	AllowRewardCycleBoundaryCrossing bool  `json:"allowRewardCycleBoundaryCrossing,omitempty"`
}

// CampaignAssertion describes one bounded effect or recovery assertion.
type CampaignAssertion struct {
	// +kubebuilder:validation:Enum=PodRestarted;PodUnavailable;ContainerRestarted;TargetReady;NetworkDegraded;NetworkRecovered;DNSDegraded;DNSRecovered;IODegraded;IORecovered;IOPressureObserved;IOPressureRecovered;ClockSkewObserved;ClockSkewCleared;BurnchainReorgProven;BurnchainPolicyRestored
	Type           string `json:"type"`
	Actor          string `json:"actor,omitempty"`
	Action         string `json:"action,omitempty"`
	TimeoutSeconds int32  `json:"timeoutSeconds,omitempty"`
}

// ResolvedTarget pins one selected actor to its immutable Pod identity.
type ResolvedTarget struct {
	Actor           string  `json:"actor"`
	Role            string  `json:"role"`
	Pod             string  `json:"pod"`
	PodUID          string  `json:"podUid"`
	PodIP           string  `json:"podIP"`
	Node            string  `json:"node"`
	RequestedImage  *string `json:"requestedImage"`
	ResolvedImageID *string `json:"resolvedImageId"`
	RestartCount    int32   `json:"restartCount"`
}

// CampaignAdmission records the immutable topology and complete compiled plan.
type CampaignAdmission struct {
	NetworkUID            string           `json:"networkUid"`
	NetworkGeneration     int64            `json:"networkGeneration"`
	NetworkInventory      NetworkInventory `json:"networkInventory"`
	CampaignGeneration    int64            `json:"campaignGeneration"`
	CampaignSpecDigest    string           `json:"campaignSpecDigest"`
	CompiledPlanDigest    string           `json:"compiledPlanDigest"`
	AdmittedAt            metav1.Time      `json:"admittedAt"`
	SignerSetRewardCycle  *int64           `json:"signerSetRewardCycle,omitempty"`
	SignerSetTotalWeight  *int64           `json:"signerSetTotalWeight,omitempty"`
	SignerSetDigest       string           `json:"signerSetDigest,omitempty"`
	SignerSetObservedFrom string           `json:"signerSetObservedFrom,omitempty"`
	AggregateImpact       *apixv1.JSON     `json:"aggregateImpact,omitempty"`
}

// ChaosReference identifies one exact controller-owned mutation object.
type ChaosReference struct {
	ActionID       string       `json:"actionId"`
	Kind           string       `json:"kind"`
	Name           string       `json:"name"`
	UID            string       `json:"uid,omitempty"`
	CreatedAt      *metav1.Time `json:"createdAt,omitempty"`
	InjectedAt     *metav1.Time `json:"injectedAt,omitempty"`
	Mechanism      string       `json:"mechanism,omitempty"`
	ResourceDigest string       `json:"resourceDigest,omitempty"`
	// RecoveryContract binds cleanup to the exact shared policy state that
	// existed before mutation.
	RecoveryContract *apixv1.JSON `json:"recoveryContract,omitempty"`
}

// FaultActionStatus records one action's independently observed lifecycle.
type FaultActionStatus struct {
	ID                 string           `json:"id"`
	Phase              string           `json:"phase,omitempty"`
	Reason             string           `json:"reason,omitempty"`
	ResolvedTargets    []ResolvedTarget `json:"resolvedTargets,omitempty"`
	CapabilityEvidence []apixv1.JSON    `json:"capabilityEvidence,omitempty"`
	Mutation           *ChaosReference  `json:"mutation,omitempty"`
	ActualInjection    *apixv1.JSON     `json:"actualInjection,omitempty"`
	EffectResults      []apixv1.JSON    `json:"effectResults,omitempty"`
	RecoveryResults    []apixv1.JSON    `json:"recoveryResults,omitempty"`
}

// FaultStageStatus records one stage's trigger, injection, and cleanup state.
type FaultStageStatus struct {
	ID                string              `json:"id"`
	Phase             string              `json:"phase,omitempty"`
	Reason            string              `json:"reason,omitempty"`
	TriggerReceipt    *apixv1.JSON        `json:"triggerReceipt,omitempty"`
	EligibleAt        *metav1.Time        `json:"eligibleAt,omitempty"`
	StartedAt         *metav1.Time        `json:"startedAt,omitempty"`
	CompletedAt       *metav1.Time        `json:"completedAt,omitempty"`
	ObservedStartSkew *metav1.Duration    `json:"observedStartSkew,omitempty"`
	Actions           []FaultActionStatus `json:"actions,omitempty"`
	EffectResults     []apixv1.JSON       `json:"effectResults,omitempty"`
	RecoveryResults   []apixv1.JSON       `json:"recoveryResults,omitempty"`
}

// CleanupEvidence records independently observed cleanup state.
type CleanupEvidence struct {
	Absent              bool        `json:"absent"`
	AllRecovered        bool        `json:"allRecovered"`
	Method              string      `json:"method,omitempty"`
	ZeroInjectionProven bool        `json:"zeroInjectionProven,omitempty"`
	ObservedAt          metav1.Time `json:"observedAt"`
}

// FaultCampaignStatus is the durable campaign state machine and evidence record.
type FaultCampaignStatus struct {
	ObservedGeneration int64               `json:"observedGeneration,omitempty"`
	Phase              string              `json:"phase,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	Message            string              `json:"message,omitempty"`
	LastTransitionTime *metav1.Time        `json:"lastTransitionTime,omitempty"`
	TemplateDigest     string              `json:"templateDigest,omitempty"`
	Admission          *CampaignAdmission  `json:"admission,omitempty"`
	Stages             []FaultStageStatus  `json:"stages,omitempty"`
	ActiveStageIDs     []string            `json:"activeStageIds,omitempty"`
	ProbeArtifacts     map[string]string   `json:"probeArtifacts,omitempty"`
	Cleanup            *CleanupEvidence    `json:"cleanup,omitempty"`
	IdentityDivergence *IdentityDivergence `json:"identityDivergence,omitempty"`
	CompletedAt        *metav1.Time        `json:"completedAt,omitempty"`
	EvidenceURI        string              `json:"evidenceURI,omitempty"`
	EvidenceDigest     string              `json:"evidenceDigest,omitempty"`
	Conditions         []metav1.Condition  `json:"conditions,omitempty"`
}
