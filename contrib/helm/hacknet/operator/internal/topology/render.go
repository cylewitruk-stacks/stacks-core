// Package topology reconciles StacksNetwork resources into Kubernetes workloads.
package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

const (
	managedByLabel       = "testing.stacks.org/managed-by"
	managedByValue       = "stacks-hacknet-operator"
	legacyManagedByLabel = "app.kubernetes.io/managed-by"
	legacyManagedByValue = "hacknet-operator"
	networkLabel         = "testing.stacks.org/network"
	actorLabel           = "testing.stacks.org/actor"
	roleLabel            = "testing.stacks.org/role"
	configHashKey        = "testing.stacks.org/config-hash"
)

var placeholderPattern = regexp.MustCompile(`\$\{(NETWORK|NAMESPACE|ACTOR|SERVICE:([a-z0-9]([-a-z0-9]*[a-z0-9])?))\}`)

// ResourceSet contains the desired objects for one StacksNetwork.
type ResourceSet struct {
	ConfigMaps   []*corev1.ConfigMap   `json:"configmaps"`
	Services     []*corev1.Service     `json:"services"`
	StatefulSets []*appsv1.StatefulSet `json:"statefulsets"`
}

// Objects returns every desired object in deterministic apply order.
func (r ResourceSet) Objects() []client.Object {
	objects := make([]client.Object, 0, len(r.ConfigMaps)+len(r.Services)+len(r.StatefulSets))
	for _, object := range r.ConfigMaps {
		objects = append(objects, object)
	}
	for _, object := range r.Services {
		objects = append(objects, object)
	}
	for _, object := range r.StatefulSets {
		objects = append(objects, object)
	}
	return objects
}

type actorContext struct {
	network  *attacknetv1alpha1.StacksNetwork
	actor    *attacknetv1alpha1.ActorSpec
	name     string
	services map[string]string
	scheme   *runtime.Scheme
}

// Render converts a StacksNetwork declaration into owned Kubernetes resources.
func Render(network *attacknetv1alpha1.StacksNetwork, scheme *runtime.Scheme) (ResourceSet, error) {
	if err := validateNetwork(network); err != nil {
		return ResourceSet{}, err
	}
	services := make(map[string]string, len(network.Spec.Actors))
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		services[actor.Name] = stableName(network.Name, actor.Name)
	}
	result := ResourceSet{}
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		ctx := actorContext{network: network, actor: actor, name: services[actor.Name], services: services, scheme: scheme}
		configMap, err := ctx.configMap()
		if err != nil {
			return ResourceSet{}, err
		}
		if configMap != nil {
			result.ConfigMaps = append(result.ConfigMaps, configMap)
		}
		service, err := ctx.service()
		if err != nil {
			return ResourceSet{}, err
		}
		statefulSet, err := ctx.statefulSet()
		if err != nil {
			return ResourceSet{}, err
		}
		result.Services = append(result.Services, service)
		result.StatefulSets = append(result.StatefulSets, statefulSet)
	}
	return result, nil
}

func stableName(network, actor string) string {
	candidate := network + "-" + actor
	if len(candidate) <= 63 {
		return candidate
	}
	digest := sha256.Sum256([]byte(candidate))
	return strings.TrimRight(candidate[:54], "-") + "-" + hex.EncodeToString(digest[:4])
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func pullPolicy(value, fallback corev1.PullPolicy) corev1.PullPolicy {
	if value != "" {
		return value
	}
	if fallback != "" {
		return fallback
	}
	return corev1.PullIfNotPresent
}

func defaultResources(cpuRequest, memoryRequest, cpuLimit, memoryLimit string) corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpuRequest), corev1.ResourceMemory: resource.MustParse(memoryRequest)},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpuLimit), corev1.ResourceMemory: resource.MustParse(memoryLimit)},
	}
}

func copyResources(value *corev1.ResourceRequirements, fallback corev1.ResourceRequirements) corev1.ResourceRequirements {
	if value == nil {
		return *fallback.DeepCopy()
	}
	return *value.DeepCopy()
}

func mergeResources(base, override *corev1.ResourceRequirements) *corev1.ResourceRequirements {
	if base == nil && override == nil {
		return nil
	}
	result := &corev1.ResourceRequirements{}
	if base != nil {
		result = base.DeepCopy()
	}
	if override == nil {
		return result
	}
	if override.Limits != nil {
		if result.Limits == nil {
			result.Limits = corev1.ResourceList{}
		}
		for name, quantity := range override.Limits {
			result.Limits[name] = quantity.DeepCopy()
		}
	}
	if override.Requests != nil {
		if result.Requests == nil {
			result.Requests = corev1.ResourceList{}
		}
		for name, quantity := range override.Requests {
			result.Requests[name] = quantity.DeepCopy()
		}
	}
	if override.Claims != nil {
		result.Claims = append([]corev1.ResourceClaim(nil), override.Claims...)
	}
	return result
}

func storageSettings(network *attacknetv1alpha1.StacksNetwork, actor *attacknetv1alpha1.ActorSpec) attacknetv1alpha1.StorageSpec {
	result := attacknetv1alpha1.StorageSpec{Size: "1Gi", MountPath: "/data", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}
	if network.Spec.Defaults.Storage != nil {
		mergeStorage(&result, network.Spec.Defaults.Storage)
	}
	if actor.Storage != nil {
		mergeStorage(&result, actor.Storage)
	}
	return result
}

func mergeStorage(target *attacknetv1alpha1.StorageSpec, source *attacknetv1alpha1.StorageSpec) {
	if source.Enabled != nil {
		target.Enabled = source.Enabled
	}
	if source.Size != "" {
		target.Size = source.Size
	}
	if source.MountPath != "" {
		target.MountPath = source.MountPath
	}
	if source.StorageClassName != nil {
		target.StorageClassName = source.StorageClassName
	}
	if len(source.AccessModes) > 0 {
		target.AccessModes = append([]corev1.PersistentVolumeAccessMode(nil), source.AccessModes...)
	}
}

func telemetrySettings(network *attacknetv1alpha1.StacksNetwork, actor *attacknetv1alpha1.ActorSpec) attacknetv1alpha1.TelemetrySpec {
	result := attacknetv1alpha1.TelemetrySpec{
		Image:           "ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.158.0",
		ImagePullPolicy: corev1.PullIfNotPresent,
		Resources:       ptr(defaultResources("10m", "32Mi", "200m", "160Mi")),
	}
	mergeTelemetry(&result, network.Spec.Telemetry)
	mergeTelemetry(&result, actor.Telemetry)
	return result
}

func mergeTelemetry(target *attacknetv1alpha1.TelemetrySpec, source *attacknetv1alpha1.TelemetrySpec) {
	if source == nil {
		return
	}
	if source.Enabled != nil {
		target.Enabled = source.Enabled
	}
	if source.Image != "" {
		target.Image = source.Image
	}
	if source.ImagePullPolicy != "" {
		target.ImagePullPolicy = source.ImagePullPolicy
	}
	if source.Resources != nil {
		target.Resources = mergeResources(target.Resources, source.Resources)
	}
	if source.MetricsPort != 0 {
		target.MetricsPort = source.MetricsPort
	}
	if source.ExporterEndpoint != "" {
		target.ExporterEndpoint = source.ExporterEndpoint
	}
	if source.TokenSecretRef != nil {
		copied := *source.TokenSecretRef
		target.TokenSecretRef = &copied
	}
}

func probeSettings(network *attacknetv1alpha1.StacksNetwork, actor *attacknetv1alpha1.ActorSpec) attacknetv1alpha1.ProbeSpec {
	result := attacknetv1alpha1.ProbeSpec{
		Image: "stacks-hacknet-probe:dev", ImagePullPolicy: corev1.PullIfNotPresent,
		Resources: ptr(defaultResources("5m", "24Mi", "100m", "64Mi")),
	}
	mergeProbe(&result, network.Spec.Probe)
	mergeProbe(&result, actor.Probe)
	return result
}

func mergeProbe(target *attacknetv1alpha1.ProbeSpec, source *attacknetv1alpha1.ProbeSpec) {
	if source == nil {
		return
	}
	if source.Enabled != nil {
		target.Enabled = source.Enabled
	}
	if source.Image != "" {
		target.Image = source.Image
	}
	if source.ImagePullPolicy != "" {
		target.ImagePullPolicy = source.ImagePullPolicy
	}
	if source.Resources != nil {
		target.Resources = mergeResources(target.Resources, source.Resources)
	}
	if source.AdditionalServices != nil {
		target.AdditionalServices = append([]attacknetv1alpha1.ProbeService(nil), source.AdditionalServices...)
	}
}

func ptr[T any](value T) *T { return &value }

func actorImage(network *attacknetv1alpha1.StacksNetwork, actor *attacknetv1alpha1.ActorSpec) string {
	if actor.Image != "" {
		return actor.Image
	}
	switch actor.Role {
	case "signer":
		return network.Spec.Defaults.SignerImage
	case "burnchain":
		if network.Spec.Defaults.BurnchainImage != "" {
			return network.Spec.Defaults.BurnchainImage
		}
		return "bitcoin/bitcoin:25.2"
	default:
		return network.Spec.Defaults.NodeImage
	}
}

func configKey(actor *attacknetv1alpha1.ActorSpec) string {
	if actor.Config != nil && actor.Config.Key != "" {
		return actor.Config.Key
	}
	if actor.Role == "signer" {
		return "signer.toml"
	}
	return "Config.toml"
}

func configMountPath(actor *attacknetv1alpha1.ActorSpec) string {
	if actor.Config != nil && actor.Config.MountPath != "" {
		return actor.Config.MountPath
	}
	return "/etc/stacks"
}

func actorCommand(actor *attacknetv1alpha1.ActorSpec) ([]string, []string) {
	if actor.Command != nil || actor.Args != nil {
		return actor.Command, actor.Args
	}
	path := strings.TrimRight(configMountPath(actor), "/") + "/" + configKey(actor)
	switch actor.Role {
	case "signer":
		return []string{"stacks-signer"}, []string{"run", "--config", path}
	case "miner", "companion", "follower", "adversary":
		return []string{"stacks-node"}, []string{"start", "--config", path}
	default:
		return nil, nil
	}
}

func rolePorts(role string) []attacknetv1alpha1.ActorPort {
	port := func(name string, number int32) attacknetv1alpha1.ActorPort {
		return attacknetv1alpha1.ActorPort{Name: name, ContainerPort: number, ServicePort: number, Protocol: corev1.ProtocolTCP}
	}
	switch role {
	case "signer":
		return []attacknetv1alpha1.ActorPort{port("events", 30000), port("metrics", 31000)}
	case "burnchain":
		return []attacknetv1alpha1.ActorPort{port("rpc", 18443), port("p2p", 18444)}
	case "miner", "companion", "follower", "adversary":
		return []attacknetv1alpha1.ActorPort{port("rpc", 20443), port("p2p", 20444), port("metrics", 20446)}
	default:
		return nil
	}
}

func effectivePorts(actor *attacknetv1alpha1.ActorSpec) []attacknetv1alpha1.ActorPort {
	ports := actor.Ports
	if len(ports) == 0 {
		ports = rolePorts(actor.Role)
	}
	result := append([]attacknetv1alpha1.ActorPort(nil), ports...)
	for index := range result {
		if result[index].ServicePort == 0 {
			result[index].ServicePort = result[index].ContainerPort
		}
		if result[index].Protocol == "" {
			result[index].Protocol = corev1.ProtocolTCP
		}
	}
	return result
}

func (c actorContext) labels() map[string]string {
	result := make(map[string]string, len(c.actor.Labels)+7)
	for key, value := range c.actor.Labels {
		result[key] = value
	}
	result["app.kubernetes.io/name"] = "stacks-hacknet-actor"
	result["app.kubernetes.io/instance"] = c.network.Name
	result[legacyManagedByLabel] = legacyManagedByValue
	result[managedByLabel] = managedByValue
	result[networkLabel] = c.network.Name
	result[actorLabel] = c.actor.Name
	result[roleLabel] = c.actor.Role
	return result
}

func (c actorContext) metadata() metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: c.name, Namespace: c.network.Namespace, Labels: c.labels()}
}

func (c actorContext) own(object client.Object) error {
	return ownership.SetControllerReference(c.network, object, c.scheme)
}

func (c actorContext) expand(value string) (string, error) {
	var expansionError error
	result := placeholderPattern.ReplaceAllStringFunc(value, func(token string) string {
		parts := placeholderPattern.FindStringSubmatch(token)
		switch parts[1] {
		case "NETWORK":
			return c.network.Name
		case "NAMESPACE":
			return c.network.Namespace
		case "ACTOR":
			return c.actor.Name
		default:
			service, exists := c.services[parts[2]]
			if !exists {
				expansionError = fmt.Errorf("placeholder references unknown actor %q", parts[2])
				return token
			}
			return service
		}
	})
	return result, expansionError
}

func (c actorContext) expandObject(value any, result any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	expanded, err := c.expandValue(decoded)
	if err != nil {
		return err
	}
	encoded, err = json.Marshal(expanded)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, result)
}

func (c actorContext) expandValue(value any) (any, error) {
	switch typed := value.(type) {
	case string:
		return c.expand(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			expanded, err := c.expandValue(item)
			if err != nil {
				return nil, err
			}
			result[index] = expanded
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			expanded, err := c.expandValue(item)
			if err != nil {
				return nil, err
			}
			result[key] = expanded
		}
		return result, nil
	default:
		return value, nil
	}
}

func mergeAPIObjects[T any](base, override *T) (*T, error) {
	if base == nil && override == nil {
		return nil, nil
	}
	merged := map[string]any{}
	for _, source := range []*T{base, override} {
		if source == nil {
			continue
		}
		encoded, err := json.Marshal(source)
		if err != nil {
			return nil, err
		}
		value := map[string]any{}
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, err
		}
		mergeJSONMap(merged, value)
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	result := new(T)
	if err := json.Unmarshal(encoded, result); err != nil {
		return nil, err
	}
	return result, nil
}

func mergeJSONMap(target, source map[string]any) {
	for key, value := range source {
		if nested, ok := value.(map[string]any); ok {
			current, _ := target[key].(map[string]any)
			if current == nil {
				current = map[string]any{}
			}
			mergeJSONMap(current, nested)
			target[key] = current
			continue
		}
		target[key] = value
	}
}
