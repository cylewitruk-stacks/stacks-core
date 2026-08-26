package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BurnchainPolicy declares externally controlled Bitcoin regtest mining policy.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type BurnchainPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BurnchainPolicySpec   `json:"spec"`
	Status BurnchainPolicyStatus `json:"status,omitempty"`
}

// BurnchainPolicyList contains BurnchainPolicy objects.
// +kubebuilder:object:root=true
type BurnchainPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BurnchainPolicy `json:"items"`
}

// BurnchainPolicySpec defines bootstrap and steady-state block production.
// +kubebuilder:validation:XValidation:rule="self.destinationSelection == 'fixed' ? (!has(self.fixedDestinationIndex) || self.fixedDestinationIndex < size(self.destinations)) : (!has(self.fixedDestinationIndex) || self.fixedDestinationIndex == 0)",message="fixedDestinationIndex must select a destination only in fixed mode"
type BurnchainPolicySpec struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	NetworkRef string `json:"networkRef"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	BitcoinNodeRef string `json:"bitcoinNodeRef"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10000000
	BootstrapHeight int64           `json:"bootstrapHeight,omitempty"`
	Cadence         metav1.Duration `json:"cadence"`
	Paused          bool            `json:"paused,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Destinations []BurnchainDestinationSpec `json:"destinations"`
	// +kubebuilder:default=round-robin
	DestinationSelection BurnchainDestinationMode `json:"destinationSelection,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=63
	FixedDestinationIndex int32                  `json:"fixedDestinationIndex,omitempty"`
	Flash                 *BurnchainFlashRequest `json:"flash,omitempty"`
	RPC                   BurnchainRPCSpec       `json:"rpc,omitempty"`
}

// BurnchainDestinationMode controls how the clock chooses a destination.
// +kubebuilder:validation:Enum=round-robin;fixed
type BurnchainDestinationMode string

const (
	// BurnchainDestinationRoundRobin rotates through every configured destination.
	BurnchainDestinationRoundRobin BurnchainDestinationMode = "round-robin"
	// BurnchainDestinationFixed always uses one configured destination.
	BurnchainDestinationFixed BurnchainDestinationMode = "fixed"
)

// BurnchainDestinationSpec binds one watch-only wallet to a mining address.
type BurnchainDestinationSpec struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[^,\r\n]+$`
	WalletName string `json:"walletName"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[^,\r\n]+$`
	Address string `json:"address"`
}

// BurnchainFlashRequest is one idempotent bounded multi-block request.
type BurnchainFlashRequest struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ID string `json:"id"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	Blocks   int32           `json:"blocks"`
	Interval metav1.Duration `json:"interval,omitempty"`
}

// BurnchainRPCSpec configures bounded RPC retry behavior.
// +kubebuilder:validation:XValidation:rule="has(self.usernameSecretRef) == has(self.passwordSecretRef)",message="usernameSecretRef and passwordSecretRef must be configured together"
type BurnchainRPCSpec struct {
	Timeout           metav1.Duration     `json:"timeout,omitempty"`
	MinimumBackoff    metav1.Duration     `json:"minimumBackoff,omitempty"`
	MaximumBackoff    metav1.Duration     `json:"maximumBackoff,omitempty"`
	UsernameSecretRef *SecretKeyReference `json:"usernameSecretRef,omitempty"`
	PasswordSecretRef *SecretKeyReference `json:"passwordSecretRef,omitempty"`
}

// BurnchainPolicyStatus reports applied policy and observed Bitcoin progress.
type BurnchainPolicyStatus struct {
	ObservedGeneration     int64              `json:"observedGeneration,omitempty"`
	AdmittedNetworkUID     string             `json:"admittedNetworkUID,omitempty"`
	AdmittedBitcoinUID     string             `json:"admittedBitcoinStatefulSetUID,omitempty"`
	AdmittedBitcoinImageID string             `json:"admittedBitcoinRuntimeImageID,omitempty"`
	Phase                  string             `json:"phase,omitempty"`
	Reason                 string             `json:"reason,omitempty"`
	Message                string             `json:"message,omitempty"`
	AppliedPolicyDigest    string             `json:"appliedPolicyDigest,omitempty"`
	AppliedFlashID         string             `json:"appliedFlashId,omitempty"`
	ObservedHeight         int64              `json:"observedHeight,omitempty"`
	LastBlockHash          string             `json:"lastBlockHash,omitempty"`
	LastSuccessAt          *metav1.Time       `json:"lastSuccessAt,omitempty"`
	LastAttemptAt          *metav1.Time       `json:"lastAttemptAt,omitempty"`
	ConsecutiveFailures    int32              `json:"consecutiveFailures,omitempty"`
	Conditions             []metav1.Condition `json:"conditions,omitempty"`
}
