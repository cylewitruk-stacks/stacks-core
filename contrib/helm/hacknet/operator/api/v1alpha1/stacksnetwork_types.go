package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StacksNetwork declares a disposable Stacks test network.
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

// StacksNetworkSpec defines actor workloads and common defaults.
type StacksNetworkSpec struct {
	Suspended bool                  `json:"suspended,omitempty"`
	Defaults  StacksNetworkDefaults `json:"defaults,omitempty"`
	Telemetry *TelemetrySpec        `json:"telemetry,omitempty"`
	Probe     *ProbeSpec            `json:"probe,omitempty"`
	Actors    []ActorSpec           `json:"actors"`
}

// StacksNetworkDefaults contains default actor workload settings.
type StacksNetworkDefaults struct {
	NodeImage                     string                            `json:"nodeImage,omitempty"`
	SignerImage                   string                            `json:"signerImage,omitempty"`
	BurnchainImage                string                            `json:"burnchainImage,omitempty"`
	ImagePullPolicy               corev1.PullPolicy                 `json:"imagePullPolicy,omitempty"`
	DependencyImage               string                            `json:"dependencyImage,omitempty"`
	ImagePullSecrets              []corev1.LocalObjectReference     `json:"imagePullSecrets,omitempty"`
	Storage                       *StorageSpec                      `json:"storage,omitempty"`
	Resources                     *corev1.ResourceRequirements      `json:"resources,omitempty"`
	PodSecurityContext            *corev1.PodSecurityContext        `json:"podSecurityContext,omitempty"`
	ContainerSecurityContext      *corev1.SecurityContext           `json:"containerSecurityContext,omitempty"`
	TerminationGracePeriodSeconds *int64                            `json:"terminationGracePeriodSeconds,omitempty"`
	NodeSelector                  map[string]string                 `json:"nodeSelector,omitempty"`
	Affinity                      *corev1.Affinity                  `json:"affinity,omitempty"`
	Tolerations                   []corev1.Toleration               `json:"tolerations,omitempty"`
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// StorageSpec configures one actor's persistent data volume.
type StorageSpec struct {
	Enabled          *bool                               `json:"enabled,omitempty"`
	Size             string                              `json:"size,omitempty"`
	MountPath        string                              `json:"mountPath,omitempty"`
	StorageClassName *string                             `json:"storageClassName,omitempty"`
	AccessModes      []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`
}

// SecretKeyReference identifies one key in a Secret.
type SecretKeyReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// TelemetrySpec configures the optional per-actor OpenTelemetry collector.
type TelemetrySpec struct {
	Enabled          *bool                        `json:"enabled,omitempty"`
	Image            string                       `json:"image,omitempty"`
	ImagePullPolicy  corev1.PullPolicy            `json:"imagePullPolicy,omitempty"`
	Resources        *corev1.ResourceRequirements `json:"resources,omitempty"`
	MetricsPort      int32                        `json:"metricsPort,omitempty"`
	ExporterEndpoint string                       `json:"exporterEndpoint,omitempty"`
	TokenSecretRef   *SecretKeyReference          `json:"tokenSecretRef,omitempty"`
}

// ProbeService describes one explicitly trusted service visible to active probes.
type ProbeService struct {
	Name        string      `json:"name"`
	ServiceName string      `json:"serviceName"`
	Ports       []ProbePort `json:"ports"`
}

// ProbePort describes one named trusted service port.
type ProbePort struct {
	Name string `json:"name"`
	Port int32  `json:"port"`
}

// ProbeSpec configures the optional credential-free active-probe sidecar.
type ProbeSpec struct {
	Enabled            *bool                        `json:"enabled,omitempty"`
	Image              string                       `json:"image,omitempty"`
	ImagePullPolicy    corev1.PullPolicy            `json:"imagePullPolicy,omitempty"`
	Resources          *corev1.ResourceRequirements `json:"resources,omitempty"`
	AdditionalServices []ProbeService               `json:"additionalServices,omitempty"`
}

// ActorConfig configures actor files mounted from inline data or an existing object.
type ActorConfig struct {
	Inline       string                       `json:"inline,omitempty"`
	Files        map[string]string            `json:"files,omitempty"`
	Key          string                       `json:"key,omitempty"`
	MountPath    string                       `json:"mountPath,omitempty"`
	ConfigMapRef *corev1.LocalObjectReference `json:"configMapRef,omitempty"`
	SecretRef    *corev1.LocalObjectReference `json:"secretRef,omitempty"`
}

// ActorPort exposes one container and optional service port.
type ActorPort struct {
	Name          string          `json:"name"`
	ContainerPort int32           `json:"containerPort"`
	ServicePort   int32           `json:"servicePort,omitempty"`
	Protocol      corev1.Protocol `json:"protocol,omitempty"`
}

// ActorDependency is a startup reachability requirement on another actor.
type ActorDependency struct {
	Actor string `json:"actor"`
	Port  int32  `json:"port"`
}

// RuntimePolicySpec mounts one hot-reloadable runtime policy ConfigMap.
type RuntimePolicySpec struct {
	ConfigMapRef corev1.LocalObjectReference `json:"configMapRef"`
	MountPath    string                      `json:"mountPath,omitempty"`
	Optional     bool                        `json:"optional,omitempty"`
}

// ActorSpec defines one logical network actor and its Kubernetes workload.
type ActorSpec struct {
	Name                          string                            `json:"name"`
	Role                          string                            `json:"role"`
	Suspended                     bool                              `json:"suspended,omitempty"`
	SignerIndex                   *int32                            `json:"signerIndex,omitempty"`
	SignerWeight                  *float64                          `json:"signerWeight,omitempty"`
	SignerPublicKey               string                            `json:"signerPublicKey,omitempty"`
	Image                         string                            `json:"image,omitempty"`
	ImagePullPolicy               corev1.PullPolicy                 `json:"imagePullPolicy,omitempty"`
	Command                       []string                          `json:"command,omitempty"`
	Args                          []string                          `json:"args,omitempty"`
	Config                        *ActorConfig                      `json:"config,omitempty"`
	Env                           []corev1.EnvVar                   `json:"env,omitempty"`
	Ports                         []ActorPort                       `json:"ports,omitempty"`
	Dependencies                  []ActorDependency                 `json:"dependencies,omitempty"`
	RuntimeExposure               string                            `json:"runtimeExposure,omitempty"`
	Storage                       *StorageSpec                      `json:"storage,omitempty"`
	Resources                     *corev1.ResourceRequirements      `json:"resources,omitempty"`
	PodSecurityContext            *corev1.PodSecurityContext        `json:"podSecurityContext,omitempty"`
	ContainerSecurityContext      *corev1.SecurityContext           `json:"containerSecurityContext,omitempty"`
	ReadinessProbe                *corev1.Probe                     `json:"readinessProbe,omitempty"`
	LivenessProbe                 *corev1.Probe                     `json:"livenessProbe,omitempty"`
	StartupProbe                  *corev1.Probe                     `json:"startupProbe,omitempty"`
	WorkingDir                    string                            `json:"workingDir,omitempty"`
	RuntimePolicy                 *RuntimePolicySpec                `json:"runtimePolicy,omitempty"`
	TerminationGracePeriodSeconds *int64                            `json:"terminationGracePeriodSeconds,omitempty"`
	NodeSelector                  map[string]string                 `json:"nodeSelector,omitempty"`
	Affinity                      *corev1.Affinity                  `json:"affinity,omitempty"`
	Tolerations                   []corev1.Toleration               `json:"tolerations,omitempty"`
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	Telemetry                     *TelemetrySpec                    `json:"telemetry,omitempty"`
	Probe                         *ProbeSpec                        `json:"probe,omitempty"`
	Labels                        map[string]string                 `json:"labels,omitempty"`
	Annotations                   map[string]string                 `json:"annotations,omitempty"`
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
