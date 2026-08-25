package v1alpha1

import (
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// FaultCampaign declares one bounded fault experiment against a StacksNetwork.
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

// FaultCampaignSpec defines selection, injection, safety, and evidence policy.
type FaultCampaignSpec struct {
	Template           bool                `json:"template,omitempty"`
	NetworkRef         string              `json:"networkRef"`
	Target             FaultTarget         `json:"target"`
	Fault              FaultSpec           `json:"fault"`
	Safety             FaultSafety         `json:"safety"`
	EffectAssertions   []CampaignAssertion `json:"effectAssertions,omitempty"`
	RecoveryAssertions []CampaignAssertion `json:"recoveryAssertions,omitempty"`
}

// FaultTarget selects enrolled actors by exact name or bounded role.
type FaultTarget struct {
	Actors []string `json:"actors,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

// FaultSpec defines one finite fault mechanism and its bounded parameters.
type FaultSpec struct {
	Type       string              `json:"type"`
	Action     string              `json:"action,omitempty"`
	Mode       string              `json:"mode"`
	Value      *intstr.IntOrString `json:"value,omitempty"`
	Duration   string              `json:"duration"`
	Parameters apixv1.JSON         `json:"parameters"`
}

// FaultSafety contains explicit bounds and conspicuous dangerous-fault opt-ins.
type FaultSafety struct {
	MaxUnavailableSignerPercent float64 `json:"maxUnavailableSignerPercent"`
	MaxUnavailableMinerPercent  float64 `json:"maxUnavailableMinerPercent"`
	AllowQuorumLoss             bool    `json:"allowQuorumLoss"`
	AllowBurnchain              bool    `json:"allowBurnchain"`
	AllowExtendedDuration       bool    `json:"allowExtendedDuration"`
	AllowExtremeSeverity        bool    `json:"allowExtremeSeverity"`
	AllowMinerMajorityOutage    bool    `json:"allowMinerMajorityOutage"`
	AllowUnenrolledTargets      bool    `json:"allowUnenrolledNetworkTargets"`
}

// CampaignAssertion describes one bounded effect or recovery assertion.
type CampaignAssertion struct {
	Type           string `json:"type"`
	Actor          string `json:"actor,omitempty"`
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

// CampaignAdmission records the immutable topology and compiled fault admitted before mutation.
type CampaignAdmission struct {
	NetworkUID            string           `json:"networkUid"`
	NetworkGeneration     int64            `json:"networkGeneration"`
	NetworkInventory      NetworkInventory `json:"networkInventory"`
	CampaignGeneration    int64            `json:"campaignGeneration,omitempty"`
	CampaignSpecDigest    string           `json:"campaignSpecDigest,omitempty"`
	CompiledDigest        string           `json:"compiledDigest"`
	AdmittedAt            metav1.Time      `json:"admittedAt"`
	SignerSetRewardCycle  *int64           `json:"signerSetRewardCycle,omitempty"`
	SignerSetTotalWeight  *float64         `json:"signerSetTotalWeight,omitempty"`
	SignerSetDigest       string           `json:"signerSetDigest,omitempty"`
	SignerSetObservedFrom string           `json:"signerSetObservedFrom,omitempty"`
	SignerImpact          *apixv1.JSON     `json:"signerImpact,omitempty"`
	MinerImpact           *apixv1.JSON     `json:"minerImpact,omitempty"`
}

// ChaosReference identifies the exact controller-owned mutation object.
type ChaosReference struct {
	Kind           string       `json:"kind"`
	Name           string       `json:"name"`
	UID            string       `json:"uid,omitempty"`
	CreatedAt      *metav1.Time `json:"createdAt,omitempty"`
	Mechanism      string       `json:"mechanism,omitempty"`
	ResourceDigest string       `json:"resourceDigest,omitempty"`
}

// CleanupEvidence records the independently observed cleanup state.
type CleanupEvidence struct {
	Absent              bool        `json:"absent"`
	AllRecovered        bool        `json:"allRecovered"`
	Method              string      `json:"method,omitempty"`
	ZeroInjectionProven bool        `json:"zeroInjectionProven,omitempty"`
	ObservedAt          metav1.Time `json:"observedAt"`
}

// FaultCampaignStatus is the durable campaign state machine and evidence record.
type FaultCampaignStatus struct {
	ObservedGeneration  int64               `json:"observedGeneration,omitempty"`
	Phase               string              `json:"phase,omitempty"`
	Reason              string              `json:"reason,omitempty"`
	Message             string              `json:"message,omitempty"`
	LastTransitionTime  *metav1.Time        `json:"lastTransitionTime,omitempty"`
	TemplateDigest      string              `json:"templateDigest,omitempty"`
	Admission           *CampaignAdmission  `json:"admission,omitempty"`
	ResolvedTargetCount int32               `json:"resolvedTargetCount,omitempty"`
	ResolvedTargets     []ResolvedTarget    `json:"resolvedTargets,omitempty"`
	CapabilityEvidence  []apixv1.JSON       `json:"capabilityEvidence,omitempty"`
	Chaos               *ChaosReference     `json:"chaos,omitempty"`
	InjectedAt          *metav1.Time        `json:"injectedAt,omitempty"`
	ActualInjection     *apixv1.JSON        `json:"actualInjection,omitempty"`
	ProbeArtifacts      map[string]string   `json:"probeArtifacts,omitempty"`
	EffectResults       []apixv1.JSON       `json:"effectResults,omitempty"`
	RecoveryResults     []apixv1.JSON       `json:"recoveryResults,omitempty"`
	Cleanup             *CleanupEvidence    `json:"cleanup,omitempty"`
	IdentityDivergence  *IdentityDivergence `json:"identityDivergence,omitempty"`
	CompletedAt         *metav1.Time        `json:"completedAt,omitempty"`
	EvidenceURI         string              `json:"evidenceURI,omitempty"`
	EvidenceDigest      string              `json:"evidenceDigest,omitempty"`
	Conditions          []metav1.Condition  `json:"conditions,omitempty"`
}
