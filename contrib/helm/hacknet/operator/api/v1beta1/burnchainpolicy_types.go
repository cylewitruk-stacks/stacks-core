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
	BootstrapHeight int64 `json:"bootstrapHeight,omitempty"`
	// ReserveOutputs controls the initial coinbase outputs mined by this
	// policy. Set it to zero on secondary Bitcoin nodes so only one policy
	// establishes the shared regtest chain.
	// +kubebuilder:default=4
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10000
	ReserveOutputs *int32          `json:"reserveOutputs,omitempty"`
	Cadence        metav1.Duration `json:"cadence"`
	Paused         bool            `json:"paused,omitempty"`
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
	// ProtocolSchedule lets semantic faults prove whether a requested branch
	// replacement crosses an epoch or reward-cycle boundary.
	ProtocolSchedule *BurnchainProtocolSchedule `json:"protocolSchedule,omitempty"`
}

// BurnchainProtocolSchedule describes the finite regtest protocol boundaries
// relevant to reorganization safety. It is declared by the environment rather
// than inferred from node configuration text.
// +kubebuilder:validation:XValidation:rule="self.epochs.size() > 0 && has(self.rewardCycle)",message="protocolSchedule must declare both epoch and reward-cycle geometry"
type BurnchainProtocolSchedule struct {
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=name
	Epochs      []BurnchainEpochBoundary      `json:"epochs,omitempty"`
	RewardCycle *BurnchainRewardCycleSchedule `json:"rewardCycle,omitempty"`
}

// BurnchainEpochBoundary names one inclusive epoch start height.
type BurnchainEpochBoundary struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10000000
	StartHeight int64 `json:"startHeight"`
}

// BurnchainRewardCycleSchedule defines deterministic reward-cycle geometry.
// +kubebuilder:validation:XValidation:rule="self.prepareLength < self.cycleLength",message="prepareLength must be less than cycleLength"
type BurnchainRewardCycleSchedule struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10000000
	FirstHeight int64 `json:"firstHeight"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	CycleLength int64 `json:"cycleLength"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	PrepareLength int64 `json:"prepareLength"`
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

// BurnchainChainTipStatus is one bounded branch observed by Bitcoin Core.
type BurnchainChainTipStatus struct {
	// +kubebuilder:validation:Minimum=0
	Height int64 `json:"height"`
	// +kubebuilder:validation:MinLength=64
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{64}$`
	Hash string `json:"hash"`
	// +kubebuilder:validation:Minimum=0
	BranchLen int64 `json:"branchLength"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	Status string `json:"status"`
}

// BurnchainPeerStatus identifies one currently connected Bitcoin peer.
type BurnchainPeerStatus struct {
	// +kubebuilder:validation:Minimum=0
	ID int64 `json:"id"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Address string `json:"address"`
	Inbound bool   `json:"inbound"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	ConnectionType string `json:"connectionType"`
	// LastBlock is Bitcoin Core's Unix timestamp for the latest block message
	// received from this peer, or zero when none has been observed.
	// +kubebuilder:validation:Minimum=0
	LastBlock int64 `json:"lastBlock"`
	// LastTransaction is Bitcoin Core's Unix timestamp for the latest
	// transaction message received from this peer, or zero when absent.
	// +kubebuilder:validation:Minimum=0
	LastTransaction int64 `json:"lastTransaction"`
}

// BurnchainPolicyStatus reports applied policy and observed Bitcoin progress.
type BurnchainPolicyStatus struct {
	ObservedGeneration     int64  `json:"observedGeneration,omitempty"`
	AdmittedNetworkUID     string `json:"admittedNetworkUID,omitempty"`
	AdmittedBitcoinUID     string `json:"admittedBitcoinStatefulSetUID,omitempty"`
	AdmittedBitcoinImageID string `json:"admittedBitcoinRuntimeImageID,omitempty"`
	Phase                  string `json:"phase,omitempty"`
	Reason                 string `json:"reason,omitempty"`
	Message                string `json:"message,omitempty"`
	AppliedPolicyDigest    string `json:"appliedPolicyDigest,omitempty"`
	AppliedFlashID         string `json:"appliedFlashId,omitempty"`
	ObservedHeight         int64  `json:"observedHeight,omitempty"`
	// +kubebuilder:validation:Pattern=`^$|^[0-9a-fA-F]{64}$`
	LastBlockHash   string `json:"lastBlockHash,omitempty"`
	ObservedHeaders int64  `json:"observedHeaders,omitempty"`
	// +kubebuilder:validation:Pattern=`^$|^[0-9a-fA-F]{64}$`
	ObservedChainwork string `json:"observedChainwork,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	ObservedChainTips []BurnchainChainTipStatus `json:"observedChainTips,omitempty"`
	// +kubebuilder:validation:MaxItems=128
	ObservedPeers           []BurnchainPeerStatus `json:"observedPeers,omitempty"`
	BitcoinObservationAt    *metav1.Time          `json:"bitcoinObservationAt,omitempty"`
	BitcoinObservationError string                `json:"bitcoinObservationError,omitempty"`
	LastSuccessAt           *metav1.Time          `json:"lastSuccessAt,omitempty"`
	LastAttemptAt           *metav1.Time          `json:"lastAttemptAt,omitempty"`
	ConsecutiveFailures     int32                 `json:"consecutiveFailures,omitempty"`
	Conditions              []metav1.Condition    `json:"conditions,omitempty"`
}
