// Package fuzzplan compiles finite human-authored fuzz plans into immutable,
// deterministic trial instructions. It performs no Kubernetes mutations.
package fuzzplan

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const (
	// PlanSchema identifies the strict human-authored fuzz-plan document.
	PlanSchema = "stacks-attacknet-fuzz-plan/v1"
	// DescriptorSchema identifies the immutable resolved session descriptor.
	DescriptorSchema = "stacks-attacknet-fuzz-session/v1"
	// DecisionAlgorithm identifies the deterministic selection algorithm.
	DecisionAlgorithm = "hmac-sha256-fuzz-plan/v1"
	// MaterializationAlgorithm identifies the deterministic conversion from a
	// trial descriptor into ordinary Attacknet resources.
	MaterializationAlgorithm = "attacknet-resource-materializer/v1"
	// MinimumReductionEvidenceBytes is the smallest complete bounded incident
	// bundle accepted for one reduction attempt.
	MinimumReductionEvidenceBytes int64 = 4 << 20
)

// Plan is one finite human-authored fuzz-session request.
type Plan struct {
	SchemaVersion string             `json:"schemaVersion" yaml:"schemaVersion"`
	SessionID     string             `json:"sessionId" yaml:"sessionId"`
	Seed          string             `json:"seed" yaml:"seed"`
	MaxTrials     int32              `json:"maxTrials" yaml:"maxTrials"`
	MaxDuration   metav1.Duration    `json:"maxDuration" yaml:"maxDuration"`
	Network       NetworkPlan        `json:"network" yaml:"network"`
	Templates     []TemplatePlan     `json:"templates" yaml:"templates"`
	Generation    GenerationPlan     `json:"generation" yaml:"generation"`
	Run           RunPlan            `json:"run" yaml:"run"`
	Confirmation  ConfirmationPlan   `json:"confirmation" yaml:"confirmation"`
	Reduction     ReductionPlan      `json:"reduction" yaml:"reduction"`
	Capacity      CapacityPlan       `json:"capacity" yaml:"capacity"`
	Corpus        CorpusPlan         `json:"corpus" yaml:"corpus"`
	Advisories    []AdvisoryFilePlan `json:"advisories,omitempty" yaml:"advisories,omitempty"`
}

// NetworkPlan selects the reusable StacksNetwork source document.
type NetworkPlan struct {
	TemplateFile   string `json:"templateFile" yaml:"templateFile"`
	ExpectedDigest string `json:"expectedDigest,omitempty" yaml:"expectedDigest,omitempty"`
}

// TemplatePlan selects one existing immutable campaign template.
type TemplatePlan struct {
	ID                 string   `json:"id" yaml:"id"`
	Kind               string   `json:"kind" yaml:"kind"`
	Name               string   `json:"name" yaml:"name"`
	Weight             int32    `json:"weight" yaml:"weight"`
	MaxUses            int32    `json:"maxUses" yaml:"maxUses"`
	ConflictGroups     []string `json:"conflictGroups,omitempty" yaml:"conflictGroups,omitempty"`
	Requires           []string `json:"requires,omitempty" yaml:"requires,omitempty"`
	ExpectedUID        string   `json:"expectedUid,omitempty" yaml:"expectedUid,omitempty"`
	ExpectedGeneration *int64   `json:"expectedGeneration,omitempty" yaml:"expectedGeneration,omitempty"`
	ExpectedSpecDigest string   `json:"expectedSpecDigest,omitempty" yaml:"expectedSpecDigest,omitempty"`
}

// GenerationPlan bounds deterministic execution selection.
type GenerationPlan struct {
	MinExecutions int32                             `json:"minExecutions" yaml:"minExecutions"`
	MaxExecutions int32                             `json:"maxExecutions" yaml:"maxExecutions"`
	Triggers      []attacknetv1beta1.RunTriggerSpec `json:"triggers" yaml:"triggers"`
}

// RunPlan contains the policies copied into every generated AttacknetRun.
type RunPlan struct {
	Budgets            attacknetv1beta1.RunBudgets                `json:"budgets" yaml:"budgets"`
	StopPolicy         attacknetv1beta1.StopPolicy                `json:"stopPolicy" yaml:"stopPolicy"`
	AttributionPolicy  attacknetv1beta1.AttributionPolicy         `json:"attributionPolicy" yaml:"attributionPolicy"`
	BaselineAssertions *attacknetv1beta1.ProtocolAssertionSetSpec `json:"baselineAssertions,omitempty" yaml:"baselineAssertions,omitempty"`
	DuringAssertions   *attacknetv1beta1.ProtocolAssertionSetSpec `json:"duringAssertions,omitempty" yaml:"duringAssertions,omitempty"`
	RecoveryAssertions *attacknetv1beta1.ProtocolAssertionSetSpec `json:"recoveryAssertions,omitempty" yaml:"recoveryAssertions,omitempty"`
}

// ConfirmationPlan controls fresh-network reproduction requirements.
type ConfirmationPlan struct {
	RequiredMatches int32 `json:"requiredMatches" yaml:"requiredMatches"`
	MaxAttempts     int32 `json:"maxAttempts" yaml:"maxAttempts"`
}

// ReductionPlan bounds deterministic removal-only reduction.
type ReductionPlan struct {
	Enabled          bool            `json:"enabled" yaml:"enabled"`
	MaxAttempts      int32           `json:"maxAttempts" yaml:"maxAttempts"`
	MaxDuration      metav1.Duration `json:"maxDuration" yaml:"maxDuration"`
	MaxEvidenceBytes int64           `json:"maxEvidenceBytes" yaml:"maxEvidenceBytes"`
}

// CapacityPlan declares unattended-session headroom and escrow requirements.
type CapacityPlan struct {
	MinimumNodeBytes      int64 `json:"minimumNodeBytes" yaml:"minimumNodeBytes"`
	MinimumImageBytes     int64 `json:"minimumImageBytes" yaml:"minimumImageBytes"`
	MinimumCorpusBytes    int64 `json:"minimumCorpusBytes" yaml:"minimumCorpusBytes"`
	StorageEscrowBytes    int64 `json:"storageEscrowBytes" yaml:"storageEscrowBytes"`
	EvidenceEscrowBytes   int64 `json:"evidenceEscrowBytes" yaml:"evidenceEscrowBytes"`
	RequirePhysicalEscrow bool  `json:"requirePhysicalEscrow" yaml:"requirePhysicalEscrow"`
}

// CorpusPlan defines the local immutable artifact boundary.
type CorpusPlan struct {
	Root                string `json:"root" yaml:"root"`
	MaximumBytes        int64  `json:"maximumBytes" yaml:"maximumBytes"`
	RetainCleanEvidence bool   `json:"retainCleanEvidence" yaml:"retainCleanEvidence"`
}

// AdvisoryFilePlan binds an optional bounded agent proposal to one trial.
type AdvisoryFilePlan struct {
	TrialOrdinal int32  `json:"trialOrdinal" yaml:"trialOrdinal"`
	File         string `json:"file" yaml:"file"`
}

// ResolvedInput contains immutable source identities supplied by the CLI
// after strict plan parsing and direct API reads.
type ResolvedInput struct {
	Plan       Plan
	PlanDigest string
	Network    ResolvedNetwork
	Templates  []ResolvedTemplate
	Advisories []AdvisoryArtifact
}

// ResolvedNetwork binds the exact reusable topology source.
type ResolvedNetwork struct {
	TemplateDigest string                         `json:"templateDigest"`
	Template       attacknetv1beta1.StacksNetwork `json:"template"`
	Policies       []ResolvedPolicy               `json:"policies"`
}

// ResolvedPolicy binds one policy referenced by the source topology to its
// exact Kubernetes identity and immutable desired state.
type ResolvedPolicy struct {
	Name       string                               `json:"name"`
	Namespace  string                               `json:"namespace"`
	UID        string                               `json:"uid"`
	Generation int64                                `json:"generation"`
	SpecDigest string                               `json:"specDigest"`
	Spec       attacknetv1beta1.BurnchainPolicySpec `json:"spec"`
}

// ResolvedTemplate binds a selectable logical ID to Kubernetes identity.
type ResolvedTemplate struct {
	ID             string                                `json:"id"`
	Kind           string                                `json:"kind"`
	Name           string                                `json:"name"`
	Namespace      string                                `json:"namespace"`
	UID            string                                `json:"uid"`
	Generation     int64                                 `json:"generation"`
	SpecDigest     string                                `json:"specDigest"`
	Weight         int32                                 `json:"weight"`
	MaxUses        int32                                 `json:"maxUses"`
	ConflictGroups []string                              `json:"conflictGroups,omitempty"`
	Requires       []string                              `json:"requires,omitempty"`
	FaultSpec      *attacknetv1beta1.FaultCampaignSpec   `json:"faultSpec,omitempty"`
	UpgradeSpec    *attacknetv1beta1.UpgradeCampaignSpec `json:"upgradeSpec,omitempty"`
}

// AdvisoryArtifact is the accepted ranking object retained by the corpus.
type AdvisoryArtifact struct {
	SchemaVersion string              `json:"schemaVersion"`
	TrialOrdinal  int32               `json:"trialOrdinal"`
	Candidates    []AdvisoryCandidate `json:"candidates"`
	Digest        string              `json:"digest"`
}

// AdvisoryCandidate contains bounded ranking data only.
type AdvisoryCandidate struct {
	ID        string `json:"id"`
	Score     int32  `json:"score"`
	Rationale string `json:"rationale,omitempty"`
}

// Descriptor is the immutable complete session plan.
type Descriptor struct {
	SchemaVersion            string             `json:"schemaVersion"`
	SessionID                string             `json:"sessionId"`
	Seed                     string             `json:"seed"`
	DecisionAlgorithm        string             `json:"decisionAlgorithm"`
	MaterializationAlgorithm string             `json:"materializationAlgorithm"`
	MaxDuration              metav1.Duration    `json:"maxDuration"`
	PlanDigest               string             `json:"planDigest"`
	Network                  ResolvedNetwork    `json:"network"`
	Templates                []ResolvedTemplate `json:"templates"`
	Generation               GenerationPlan     `json:"generation"`
	Run                      RunPlan            `json:"run"`
	Confirmation             ConfirmationPlan   `json:"confirmation"`
	Reduction                ReductionPlan      `json:"reduction"`
	Capacity                 CapacityPlan       `json:"capacity"`
	Corpus                   CorpusPlan         `json:"corpus"`
	Advisories               []AdvisoryArtifact `json:"advisories,omitempty"`
	Trials                   []Trial            `json:"trials"`
	Digest                   string             `json:"digest"`
}

// Trial is one explicit deterministic run instruction.
type Trial struct {
	Ordinal        int32             `json:"ordinal"`
	Seed           string            `json:"seed"`
	Executions     []TrialExecution  `json:"executions"`
	DecisionDigest string            `json:"decisionDigest"`
	Receipts       []DecisionReceipt `json:"receipts"`
	AdvisoryDigest string            `json:"advisoryDigest,omitempty"`
}

// TrialExecution selects one admitted template and trigger.
type TrialExecution struct {
	ID       string                          `json:"id"`
	Template string                          `json:"template"`
	Kind     string                          `json:"kind"`
	Trigger  attacknetv1beta1.RunTriggerSpec `json:"trigger,omitempty"`
}

// DecisionReceipt makes one pseudo-random choice independently reproducible.
type DecisionReceipt struct {
	Algorithm          string `json:"algorithm"`
	TrialOrdinal       int32  `json:"trialOrdinal"`
	Domain             string `json:"domain"`
	ContextDigest      string `json:"contextDigest"`
	Counter            uint64 `json:"counter"`
	CandidateSetDigest string `json:"candidateSetDigest"`
	Selected           string `json:"selected"`
	AdvisoryDigest     string `json:"advisoryDigest,omitempty"`
	Digest             string `json:"digest"`
}
