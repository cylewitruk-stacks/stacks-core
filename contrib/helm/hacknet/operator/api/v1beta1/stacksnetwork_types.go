package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StacksNetwork declares one disposable Stacks network as a domain topology.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type StacksNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StacksNetworkSpec   `json:"spec"`
	Status StacksNetworkStatus `json:"status,omitempty"`
}

// StacksNetworkList contains StacksNetwork objects.
// +kubebuilder:object:root=true
type StacksNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StacksNetwork `json:"items"`
}

// StacksNetworkSpec defines the burnchain, Stacks nodes, and signer sets.
type StacksNetworkSpec struct {
	Suspended bool                  `json:"suspended,omitempty"`
	Defaults  NetworkDefaults       `json:"defaults,omitempty"`
	Genesis   *StacksGenesisSpec    `json:"genesis,omitempty"`
	Burnchain BurnchainTopologySpec `json:"burnchain"`
	// +kubebuilder:validation:MaxItems=100
	Nodes []StacksNodeSpec `json:"nodes,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	SignerSets []SignerSetSpec       `json:"signerSets,omitempty"`
	Enrollment *SignerEnrollmentSpec `json:"enrollment,omitempty"`
	// +kubebuilder:validation:MaxItems=100
	RawActors       []RawActorSpec   `json:"rawActors,omitempty"`
	Telemetry       *TelemetrySpec   `json:"telemetry,omitempty"`
	Probe           *ProbeSpec       `json:"probe,omitempty"`
	SuspensionGrace *metav1.Duration `json:"suspensionGrace,omitempty"`
}

// StacksGenesisSpec defines network-wide genesis values which every generated
// Stacks node profile must render identically.
type StacksGenesisSpec struct {
	PoX5 *PoX5GenesisSpec `json:"pox5,omitempty"`
	// +kubebuilder:validation:MaxItems=1000
	// +listType=map
	// +listMapKey=address
	Balances []GenesisBalanceSpec `json:"balances,omitempty"`
}

// PoX5GenesisSpec identifies the sBTC contracts activated by PoX-5.
type PoX5GenesisSpec struct {
	SbtcContract         string `json:"sbtcContract"`
	SbtcRegistryContract string `json:"sbtcRegistryContract"`
}

// GenesisBalanceSpec assigns one account's initial micro-STX balance.
type GenesisBalanceSpec struct {
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`
	// +kubebuilder:validation:Minimum=1
	Amount int64 `json:"amount"`
}

// SignerEnrollmentSpec declares the one-shot client that enrolls signer keys
// and renews their stacking commitments for the disposable network.
type SignerEnrollmentSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name    string `json:"name"`
	Image   string `json:"image"`
	NodeRef string `json:"nodeRef"`
	// CredentialsSecretRef supplies STACKING_KEYS and STACKING_ADDRESSES from
	// separate keys without granting the topology operator Secret read access.
	CredentialsSecretRef SignerEnrollmentSecretRef `json:"credentialsSecretRef"`
	// +kubebuilder:validation:Minimum=1
	StackingCycles int32 `json:"stackingCycles,omitempty"`
	// +kubebuilder:validation:Minimum=1
	PoX5StackingCycles int32 `json:"pox5StackingCycles,omitempty"`
	// +kubebuilder:validation:Minimum=1
	PoX5RenewalWindowCycles int32 `json:"pox5RenewalWindowCycles,omitempty"`
	// +kubebuilder:validation:Minimum=1
	IntervalSeconds int32                     `json:"intervalSeconds,omitempty"`
	Workload        *WorkloadPolicy           `json:"workload,omitempty"`
	Advanced        *AdvancedWorkloadOverride `json:"advanced,omitempty"`
}

// SignerEnrollmentSecretRef identifies the two credential lists used by the
// enrollment client.
type SignerEnrollmentSecretRef struct {
	Name         string `json:"name"`
	KeysKey      string `json:"keysKey"`
	AddressesKey string `json:"addressesKey"`
}

// NetworkDefaults contains shared images and workload defaults.
type NetworkDefaults struct {
	NodeImage        string                        `json:"nodeImage"`
	SignerImage      string                        `json:"signerImage"`
	BitcoinImage     string                        `json:"bitcoinImage"`
	DependencyImage  string                        `json:"dependencyImage,omitempty"`
	ImagePullPolicy  corev1.PullPolicy             `json:"imagePullPolicy,omitempty"`
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// BootstrapPeers supplies the default legacy P2P bootstrap inventory for
	// generated Stacks node profiles. A profile-local list overrides it.
	// +kubebuilder:validation:MaxItems=64
	BootstrapPeers []string       `json:"bootstrapPeers,omitempty"`
	Workload       WorkloadPolicy `json:"workload,omitempty"`
}

// BurnchainTopologySpec declares Bitcoin nodes and the cadence policy they use.
type BurnchainTopologySpec struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Nodes     []BitcoinNodeSpec           `json:"nodes"`
	PolicyRef corev1.LocalObjectReference `json:"policyRef"`
}

// BitcoinNodeSpec declares one independently persisted Bitcoin regtest node.
type BitcoinNodeSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name      string                    `json:"name"`
	Image     string                    `json:"image,omitempty"`
	Config    ConfigSource              `json:"config"`
	RPCPort   int32                     `json:"rpcPort,omitempty"`
	P2PPort   int32                     `json:"p2pPort,omitempty"`
	Workload  *WorkloadPolicy           `json:"workload,omitempty"`
	Advanced  *AdvancedWorkloadOverride `json:"advanced,omitempty"`
	Suspended bool                      `json:"suspended,omitempty"`
}

// StacksNodeRole is the protocol role of a Stacks node process.
// +kubebuilder:validation:Enum=miner;follower;adversary
type StacksNodeRole string

const (
	// StacksNodeMiner produces Stacks blocks.
	StacksNodeMiner StacksNodeRole = "miner"
	// StacksNodeFollower follows and relays the canonical chain.
	StacksNodeFollower StacksNodeRole = "follower"
	// StacksNodeAdversary runs an explicitly modified Stacks node.
	StacksNodeAdversary StacksNodeRole = "adversary"
)

// StacksNodeSpec declares one standalone miner, follower, or adversarial node.
type StacksNodeSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name             string                    `json:"name"`
	Role             StacksNodeRole            `json:"role"`
	Image            string                    `json:"image,omitempty"`
	BurnchainNodeRef string                    `json:"burnchainNodeRef"`
	Config           ConfigSource              `json:"config"`
	Workload         *WorkloadPolicy           `json:"workload,omitempty"`
	Advanced         *AdvancedWorkloadOverride `json:"advanced,omitempty"`
	Suspended        bool                      `json:"suspended,omitempty"`
}

// SignerSetSpec declares one signer cohort and its configured Stacks nodes.
type SignerSetSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Members []SignerMemberSpec `json:"members"`
}

// SignerMemberSpec binds one signer process to one configured Stacks node.
type SignerMemberSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	NodeName string `json:"nodeName"`
	// +kubebuilder:validation:Minimum=1
	Index int32 `json:"index"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=9007199254740991
	Weight           int64                     `json:"weight"`
	PublicKey        string                    `json:"publicKey,omitempty"`
	BurnchainNodeRef string                    `json:"burnchainNodeRef"`
	SignerImage      string                    `json:"signerImage,omitempty"`
	NodeImage        string                    `json:"nodeImage,omitempty"`
	SignerConfig     ConfigSource              `json:"signerConfig"`
	NodeConfig       ConfigSource              `json:"nodeConfig"`
	SignerWorkload   *WorkloadPolicy           `json:"signerWorkload,omitempty"`
	NodeWorkload     *WorkloadPolicy           `json:"nodeWorkload,omitempty"`
	SignerAdvanced   *AdvancedWorkloadOverride `json:"signerAdvanced,omitempty"`
	NodeAdvanced     *AdvancedWorkloadOverride `json:"nodeAdvanced,omitempty"`
	Suspended        bool                      `json:"suspended,omitempty"`
}

// ConfigSource selects one generated profile or complete mounted config object.
// +kubebuilder:validation:XValidation:rule="(has(self.generated) ? 1 : 0) + (has(self.configMapRef) ? 1 : 0) + (has(self.secretRef) ? 1 : 0) == 1",message="exactly one config source is required"
type ConfigSource struct {
	Generated    *GeneratedConfigSpec `json:"generated,omitempty"`
	ConfigMapRef *ConfigObjectRef     `json:"configMapRef,omitempty"`
	SecretRef    *ConfigObjectRef     `json:"secretRef,omitempty"`
}

// GeneratedConfigSpec selects a versioned deterministic config profile.
type GeneratedConfigSpec struct {
	// +kubebuilder:validation:Enum=bitcoin-regtest/v1;nakamoto-regtest-node/v1
	Profile string `json:"profile"`
	// Seed optionally pins the deterministic node identity used by the node
	// profile. Mining and signer secrets require a complete Secret-backed config.
	Seed string `json:"seed,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`
	// +kubebuilder:validation:Enum=queued;blocking
	EventDispatcher string `json:"eventDispatcher,omitempty"`
}

// ConfigObjectRef identifies a complete config file in a ConfigMap or Secret.
type ConfigObjectRef struct {
	Name      string `json:"name"`
	Key       string `json:"key,omitempty"`
	MountPath string `json:"mountPath,omitempty"`
}

// WorkloadPolicy contains safe resource, storage, and placement controls.
type WorkloadPolicy struct {
	Storage                       *StorageSpec                      `json:"storage,omitempty"`
	Resources                     *corev1.ResourceRequirements      `json:"resources,omitempty"`
	NodeSelector                  map[string]string                 `json:"nodeSelector,omitempty"`
	Affinity                      *corev1.Affinity                  `json:"affinity,omitempty"`
	Tolerations                   []corev1.Toleration               `json:"tolerations,omitempty"`
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	TerminationGracePeriodSeconds *int64                            `json:"terminationGracePeriodSeconds,omitempty"`
	RuntimeExposure               string                            `json:"runtimeExposure,omitempty"`
	Telemetry                     *TelemetrySpec                    `json:"telemetry,omitempty"`
	Probe                         *ProbeSpec                        `json:"probe,omitempty"`
}

// AdvancedWorkloadOverride exposes bounded Pod controls for unusual actors.
type AdvancedWorkloadOverride struct {
	Command                  []string                   `json:"command,omitempty"`
	Args                     []string                   `json:"args,omitempty"`
	Env                      []corev1.EnvVar            `json:"env,omitempty"`
	WorkingDir               string                     `json:"workingDir,omitempty"`
	ReadinessProbe           *corev1.Probe              `json:"readinessProbe,omitempty"`
	LivenessProbe            *corev1.Probe              `json:"livenessProbe,omitempty"`
	StartupProbe             *corev1.Probe              `json:"startupProbe,omitempty"`
	PodSecurityContext       *corev1.PodSecurityContext `json:"podSecurityContext,omitempty"`
	ContainerSecurityContext *corev1.SecurityContext    `json:"containerSecurityContext,omitempty"`
	Labels                   map[string]string          `json:"labels,omitempty"`
	Annotations              map[string]string          `json:"annotations,omitempty"`
}

// RawActorSpec is the explicit escape hatch for non-standard adversarial actors.
type RawActorSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name         string                    `json:"name"`
	Role         string                    `json:"role"`
	Image        string                    `json:"image"`
	Config       *ConfigSource             `json:"config,omitempty"`
	Ports        []ActorPort               `json:"ports,omitempty"`
	Dependencies []ActorDependency         `json:"dependencies,omitempty"`
	Workload     *WorkloadPolicy           `json:"workload,omitempty"`
	Advanced     *AdvancedWorkloadOverride `json:"advanced"`
	Suspended    bool                      `json:"suspended,omitempty"`
}

// StorageSpec configures one actor's persistent data volume.
type StorageSpec struct {
	Enabled          *bool                               `json:"enabled,omitempty"`
	Size             string                              `json:"size,omitempty"`
	MountPath        string                              `json:"mountPath,omitempty"`
	StorageClassName *string                             `json:"storageClassName,omitempty"`
	AccessModes      []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`
}

// TelemetrySpec configures the optional per-actor OpenTelemetry collector.
// +kubebuilder:validation:XValidation:rule="!has(self.enabled) || !self.enabled || (has(self.exporterEndpoint) && self.exporterEndpoint.size() > 0 && has(self.exporterServiceRef))",message="enabled telemetry requires exporterEndpoint and exporterServiceRef"
type TelemetrySpec struct {
	Enabled          *bool                        `json:"enabled,omitempty"`
	Image            string                       `json:"image,omitempty"`
	ImagePullPolicy  corev1.PullPolicy            `json:"imagePullPolicy,omitempty"`
	Resources        *corev1.ResourceRequirements `json:"resources,omitempty"`
	MetricsPort      int32                        `json:"metricsPort,omitempty"`
	ExporterEndpoint string                       `json:"exporterEndpoint,omitempty"`
	// ExporterServiceRef binds the exporter endpoint to one same-namespace
	// Kubernetes Service whose ready endpoints gate network readiness.
	ExporterServiceRef *TelemetryExporterServiceReference `json:"exporterServiceRef,omitempty"`
	TokenSecretRef     *SecretKeyReference                `json:"tokenSecretRef,omitempty"`
}

// TelemetryExporterServiceReference identifies the in-cluster service and
// service port which must be available before telemetry is considered ready.
type TelemetryExporterServiceReference struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,13}[a-z0-9])?$`
	PortName string `json:"portName"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// SecretKeyReference identifies one key in a Secret.
type SecretKeyReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// ProbeSpec configures the optional credential-free active-probe sidecar.
type ProbeSpec struct {
	Enabled            *bool                        `json:"enabled,omitempty"`
	Image              string                       `json:"image,omitempty"`
	ImagePullPolicy    corev1.PullPolicy            `json:"imagePullPolicy,omitempty"`
	Resources          *corev1.ResourceRequirements `json:"resources,omitempty"`
	AdditionalServices []ProbeService               `json:"additionalServices,omitempty"`
}

// ProbeService describes one explicitly trusted service visible to probes.
type ProbeService struct {
	Name        string      `json:"name"`
	ServiceName string      `json:"serviceName"`
	Ports       []ProbePort `json:"ports"`
}

// ProbePort describes one trusted service port.
type ProbePort struct {
	Name string `json:"name"`
	Port int32  `json:"port"`
}

// ActorPort exposes one raw actor container and optional service port.
type ActorPort struct {
	Name          string          `json:"name"`
	ContainerPort int32           `json:"containerPort"`
	ServicePort   int32           `json:"servicePort,omitempty"`
	Protocol      corev1.Protocol `json:"protocol,omitempty"`
}

// ActorDependency is a raw actor startup requirement on another actor.
type ActorDependency struct {
	Actor string `json:"actor"`
	Port  int32  `json:"port"`
}

// ActorStatus reports rollout and immutable runtime identity for one actor.
type ActorStatus struct {
	Name                       string `json:"name"`
	Role                       string `json:"role"`
	ResourceName               string `json:"resourceName"`
	Image                      string `json:"image,omitempty"`
	Ready                      bool   `json:"ready"`
	ReadyReplicas              int32  `json:"readyReplicas,omitempty"`
	UpdatedReplicas            int32  `json:"updatedReplicas,omitempty"`
	Generation                 int64  `json:"generation,omitempty"`
	ObservedGeneration         int64  `json:"observedGeneration,omitempty"`
	CurrentRevision            string `json:"currentRevision,omitempty"`
	UpdateRevision             string `json:"updateRevision,omitempty"`
	ServiceName                string `json:"serviceName,omitempty"`
	StatefulSetUID             string `json:"statefulSetUID,omitempty"`
	StatefulSetResourceVersion string `json:"statefulSetResourceVersion,omitempty"`
	PodName                    string `json:"podName,omitempty"`
	PodUID                     string `json:"podUID,omitempty"`
	PodResourceVersion         string `json:"podResourceVersion,omitempty"`
	RuntimeImageID             string `json:"runtimeImageID,omitempty"`
	IdentityReady              bool   `json:"identityReady,omitempty"`
}

// StacksNetworkStatus reports reconciled workload and admitted identity state.
type StacksNetworkStatus struct {
	ObservedGeneration  int64              `json:"observedGeneration,omitempty"`
	Phase               string             `json:"phase,omitempty"`
	DesiredActors       int32              `json:"desiredActors,omitempty"`
	ReadyActors         int32              `json:"readyActors,omitempty"`
	ReadySummary        string             `json:"readySummary,omitempty"`
	InventoryReady      bool               `json:"inventoryReady,omitempty"`
	InventoryDigest     string             `json:"inventoryDigest,omitempty"`
	InventoryObservedAt *metav1.Time       `json:"inventoryObservedAt,omitempty"`
	Actors              []ActorStatus      `json:"actors,omitempty"`
	Conditions          []metav1.Condition `json:"conditions,omitempty"`
}
