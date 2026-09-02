package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// UpgradeCampaign declares one bounded, topology-owned actor image transition.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type UpgradeCampaign struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UpgradeCampaignSpec   `json:"spec"`
	Status UpgradeCampaignStatus `json:"status,omitempty"`
}

// UpgradeCampaignList contains UpgradeCampaign objects.
// +kubebuilder:object:root=true
type UpgradeCampaignList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UpgradeCampaign `json:"items"`
}

// UpgradeCampaignSpec defines immutable profiles and ordered rollout stages.
// Profile references are checked by the reconciler because a nested CEL join
// over the schema maxima exceeds the Kubernetes API-server cost budget.
type UpgradeCampaignSpec struct {
	NetworkRef string `json:"networkRef"`
	Template   bool   `json:"template,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=name
	Profiles []UpgradeProfileSpec `json:"profiles"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Stages []UpgradeStageSpec `json:"stages"`
	Safety UpgradeSafetySpec  `json:"safety"`
	// RollbackOnFailure restores the campaign's admitted baseline before the
	// terminal Failed phase is reported.
	RollbackOnFailure bool `json:"rollbackOnFailure"`
}

// UpgradeProfileSpec binds a logical version to immutable preparation evidence.
type UpgradeProfileSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name string `json:"name"`
	// Image is a pullable or locally imported immutable assignment reference.
	Image string `json:"image"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ImageID string `json:"imageID"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ProvenanceDigest string `json:"provenanceDigest"`
	// ConfigDigest binds the version-specific configuration smoke result.
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ConfigDigest string `json:"configDigest"`
	// +kubebuilder:validation:Enum=remoteGit;localGit;prebuilt
	SourceKind string `json:"sourceKind"`
	// +kubebuilder:validation:Pattern=`^$|^[0-9a-f]{40}$`
	Revision string `json:"revision,omitempty"`
	// +kubebuilder:validation:MaxItems=21
	// +listType=set
	// +kubebuilder:validation:XValidation:rule="self.all(c, c in ['M01','M02','M03','M04','M05','M06','M07','M08','M09','M10','M11','M12','M13','M15','M16','M17','M18','M19','M20','M21','M22'])",message="capabilities must name portable instrumentation families"
	Capabilities []string `json:"capabilities,omitempty"`
	// +kubebuilder:validation:Enum=compatible;incompatible;unknown;intentionally-incompatible
	Expectation string `json:"expectation,omitempty"`
}

// UpgradeStageSpec is one bounded parallel replacement batch.
// +kubebuilder:validation:XValidation:rule="duration(self.stableFor) >= duration('0s') && duration(self.deadline) > duration(self.stableFor)",message="stage requires 0 <= stableFor < deadline"
type UpgradeStageSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=map
	// +listMapKey=actor
	Assignments []UpgradeAssignment `json:"assignments"`
	// StableFor is the continuous Ready interval required before advancement.
	StableFor metav1.Duration `json:"stableFor"`
	// Deadline bounds the complete stage, including replacement and stability.
	Deadline metav1.Duration `json:"deadline"`
	// Assertions are trusted protocol gates evaluated after the assigned actors
	// are admitted and Ready, and before the stage stability timer can advance.
	Assertions *ProtocolAssertionSetSpec `json:"assertions,omitempty"`
}

// UpgradeAssignment selects the profile for one logical actor.
type UpgradeAssignment struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Actor string `json:"actor"`
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Profile string `json:"profile"`
	// Config optionally replaces the actor's configuration for this version.
	// Omission preserves the StacksNetwork configuration; a ConfigMap or Secret
	// source is the compatibility escape hatch for arbitrary historical builds.
	Config *ConfigSource `json:"config,omitempty"`
}

// UpgradeSafetySpec bounds concurrent protocol-role impact.
type UpgradeSafetySpec struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	MaxParallelActors int32 `json:"maxParallelActors"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MaxSignerWeightPercent int32 `json:"maxSignerWeightPercent"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MaxMinerPercent int32 `json:"maxMinerPercent"`
}

// UpgradeCampaignStatus is the durable rollout and rollback state machine.
type UpgradeCampaignStatus struct {
	ObservedGeneration int64                       `json:"observedGeneration,omitempty"`
	Phase              string                      `json:"phase,omitempty"`
	Reason             string                      `json:"reason,omitempty"`
	Message            string                      `json:"message,omitempty"`
	LastTransitionTime *metav1.Time                `json:"lastTransitionTime,omitempty"`
	CompletedAt        *metav1.Time                `json:"completedAt,omitempty"`
	NetworkUID         string                      `json:"networkUID,omitempty"`
	BaselineInventory  *NetworkInventory           `json:"baselineInventory,omitempty"`
	CurrentInventory   *NetworkInventory           `json:"currentInventory,omitempty"`
	CurrentStage       int32                       `json:"currentStage,omitempty"`
	StageStartedAt     *metav1.Time                `json:"stageStartedAt,omitempty"`
	StageReadySince    *metav1.Time                `json:"stageReadySince,omitempty"`
	StageAssertions    *ProtocolAssertionSetStatus `json:"stageAssertions,omitempty"`
	// +kubebuilder:validation:MaxItems=100
	AppliedAssignments []UpgradeAssignment `json:"appliedAssignments,omitempty"`
	// +kubebuilder:validation:MaxItems=256
	IdentityTransitions []IdentityTransition `json:"identityTransitions,omitempty"`
	RollbackComplete    bool                 `json:"rollbackComplete,omitempty"`
	// RollbackTerminalPhase preserves Failed versus Inconclusive while a
	// rollback is in progress.
	RollbackTerminalPhase string `json:"rollbackTerminalPhase,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
