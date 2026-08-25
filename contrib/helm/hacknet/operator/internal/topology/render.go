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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
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

func (c actorContext) configMap() (*corev1.ConfigMap, error) {
	telemetry := telemetrySettings(c.network, c.actor)
	data := map[string]string{}
	if c.actor.Config != nil {
		if c.actor.Config.Inline != "" {
			value, err := c.expand(c.actor.Config.Inline)
			if err != nil {
				return nil, err
			}
			data[configKey(c.actor)] = value
		}
		for key, source := range c.actor.Config.Files {
			value, err := c.expand(source)
			if err != nil {
				return nil, err
			}
			data[key] = value
		}
	}
	if boolValue(telemetry.Enabled, false) {
		data["otelcol.yaml"] = c.otelConfig(telemetry)
	}
	if len(data) == 0 {
		return nil, nil
	}
	result := &corev1.ConfigMap{ObjectMeta: c.metadata(), Data: data}
	if err := c.own(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c actorContext) service() (*corev1.Service, error) {
	ports := effectivePorts(c.actor)
	servicePorts := make([]corev1.ServicePort, 0, len(ports)+1)
	for _, port := range ports {
		servicePorts = append(servicePorts, corev1.ServicePort{Name: port.Name, Port: port.ServicePort, TargetPort: intstr.FromString(port.Name), Protocol: port.Protocol})
	}
	if boolValue(probeSettings(c.network, c.actor).Enabled, false) {
		servicePorts = append(servicePorts, corev1.ServicePort{Name: "probe", Port: 18080, TargetPort: intstr.FromString("probe"), Protocol: corev1.ProtocolTCP})
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	result := &corev1.Service{ObjectMeta: c.metadata(), Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone,
		PublishNotReadyAddresses: c.actor.RuntimeExposure == "reachable",
		Selector:                 map[string]string{networkLabel: c.network.Name, actorLabel: c.actor.Name}, Ports: servicePorts,
		SessionAffinity:       corev1.ServiceAffinityNone,
		InternalTrafficPolicy: &internalTrafficPolicy,
	}}
	if err := c.own(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c actorContext) otelConfig(telemetry attacknetv1alpha1.TelemetrySpec) string {
	metricsPort := telemetry.MetricsPort
	if metricsPort == 0 {
		if c.actor.Role == "signer" {
			metricsPort = 31000
		} else {
			metricsPort = 20446
		}
	}
	headers := ""
	if telemetry.TokenSecretRef != nil {
		headers = "    headers:\n      Authorization: \"Bearer ${env:STACKS_FEDERATION_TOKEN}\"\n"
	}
	serviceName := "stacks-node"
	if c.actor.Role == "signer" {
		serviceName = "stacks-signer"
	}
	return fmt.Sprintf(`extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: stacks-actor
          scrape_interval: 5s
          scrape_timeout: 2s
          static_configs:
            - targets: ["127.0.0.1:%d"]
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 128
    spike_limit_mib: 32
  resource/actor:
    attributes:
      - key: service.name
        action: upsert
        value: %s
      - key: stacks.actor.name
        action: upsert
        value: %s
      - key: stacks.actor.role
        action: upsert
        value: %s
  batch:
    timeout: 2s
exporters:
  otlp_http/federation:
    endpoint: "${env:STACKS_FEDERATION_ENDPOINT}"
%s    compression: gzip
    sending_queue:
      enabled: true
      queue_size: 500
    retry_on_failure:
      enabled: true
      max_elapsed_time: 60s
service:
  extensions: [health_check]
  pipelines:
    metrics:
      receivers: [prometheus]
      processors: [memory_limiter, resource/actor, batch]
      exporters: [otlp_http/federation]
`, metricsPort, serviceName, c.actor.Name, c.actor.Role, headers)
}

func (c actorContext) statefulSet() (*appsv1.StatefulSet, error) {
	actor, defaults := c.actor, c.network.Spec.Defaults
	storage, telemetry, trustedProbe := storageSettings(c.network, actor), telemetrySettings(c.network, actor), probeSettings(c.network, actor)
	command, args := actorCommand(actor)
	for index := range command {
		value, err := c.expand(command[index])
		if err != nil {
			return nil, err
		}
		command[index] = value
	}
	for index := range args {
		value, err := c.expand(args[index])
		if err != nil {
			return nil, err
		}
		args[index] = value
	}
	hashPayload := struct {
		Config        *attacknetv1alpha1.ActorConfig   `json:"config"`
		Telemetry     *attacknetv1alpha1.TelemetrySpec `json:"telemetry"`
		Probe         *attacknetv1alpha1.ProbeSpec     `json:"probe"`
		Command, Args []string
	}{Config: actor.Config, Command: command, Args: args}
	if boolValue(telemetry.Enabled, false) {
		hashPayload.Telemetry = &telemetry
	}
	if boolValue(trustedProbe.Enabled, false) {
		hashPayload.Probe = &trustedProbe
	}
	hashBytes, err := json.Marshal(hashPayload)
	if err != nil {
		return nil, err
	}
	configHash := sha256.Sum256(hashBytes)
	annotations := map[string]string{configHashKey: hex.EncodeToString(configHash[:])}
	for key, value := range actor.Annotations {
		annotations[key] = value
	}
	ports := effectivePorts(actor)
	containerPorts := make([]corev1.ContainerPort, 0, len(ports))
	for _, port := range ports {
		containerPorts = append(containerPorts, corev1.ContainerPort{Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol})
	}
	containerSecurity, err := mergeAPIObjects(defaults.ContainerSecurityContext, actor.ContainerSecurityContext)
	if err != nil {
		return nil, fmt.Errorf("actor %q container security context: %w", actor.Name, err)
	}
	main := corev1.Container{
		Name: "actor", Image: actorImage(c.network, actor), ImagePullPolicy: pullPolicy(actor.ImagePullPolicy, defaults.ImagePullPolicy),
		Command: command, Args: args, Ports: containerPorts,
		Env:       []corev1.EnvVar{{Name: "HACKNET_NETWORK", Value: c.network.Name}, {Name: "HACKNET_ACTOR", Value: actor.Name}, {Name: "HACKNET_ROLE", Value: actor.Role}},
		Resources: resourceValue(mergeResources(defaults.Resources, actor.Resources)), SecurityContext: containerSecurity,
		VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: storage.MountPath}}, WorkingDir: actor.WorkingDir,
	}
	for _, variable := range actor.Env {
		copied := variable.DeepCopy()
		if err := c.expandObject(copied, copied); err != nil {
			return nil, err
		}
		main.Env = append(main.Env, *copied)
	}
	main.ReadinessProbe = actor.ReadinessProbe
	if main.ReadinessProbe == nil {
		main.ReadinessProbe = defaultReadinessProbe(actor.Role)
	}
	main.LivenessProbe, main.StartupProbe = actor.LivenessProbe, actor.StartupProbe
	volumes := []corev1.Volume{}
	if source, mount := c.configVolume(); source != nil {
		volumes = append(volumes, *source)
		main.VolumeMounts = append(main.VolumeMounts, *mount)
	}
	if actor.RuntimePolicy != nil {
		volumes = append(volumes, corev1.Volume{Name: "runtime-policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: actor.RuntimePolicy.ConfigMapRef, Optional: ptr(actor.RuntimePolicy.Optional), DefaultMode: ptr[int32](0o644)}}})
		path := actor.RuntimePolicy.MountPath
		if path == "" {
			path = "/run/hacknet-policy"
		}
		main.VolumeMounts = append(main.VolumeMounts, corev1.VolumeMount{Name: "runtime-policy", MountPath: path, ReadOnly: true})
	}
	containers := []corev1.Container{main}
	if boolValue(telemetry.Enabled, false) {
		volumes = replaceOrAppendConfigVolume(volumes, &main, c.name)
		containers[0] = main
		volumes = append(volumes, corev1.Volume{Name: "telemetry-tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		container, err := c.telemetryContainer(telemetry)
		if err != nil {
			return nil, err
		}
		containers = append(containers, container)
	}
	if boolValue(trustedProbe.Enabled, false) {
		container, err := c.probeContainer(trustedProbe, storage)
		if err != nil {
			return nil, err
		}
		containers = append(containers, container)
	}
	claims := []corev1.PersistentVolumeClaim{}
	if boolValue(storage.Enabled, true) {
		size, err := resource.ParseQuantity(storage.Size)
		if err != nil {
			return nil, fmt.Errorf("actor %q storage size: %w", actor.Name, err)
		}
		claims = append(claims, corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Labels: c.labels()}, Spec: corev1.PersistentVolumeClaimSpec{AccessModes: storage.AccessModes, StorageClassName: storage.StorageClassName, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: size}}}})
	} else {
		volumes = append(volumes, corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	}
	initContainers := []corev1.Container{}
	if len(actor.Dependencies) > 0 {
		checks := make([]string, 0, len(actor.Dependencies))
		for _, dependency := range actor.Dependencies {
			checks = append(checks, fmt.Sprintf("until nc -z %s %d; do sleep 1; done", c.services[dependency.Actor], dependency.Port))
		}
		initContainers = append(initContainers, corev1.Container{Name: "wait-for-dependencies", Image: defaultString(defaults.DependencyImage, "busybox:1.36.1"), Command: []string{"sh", "-ec", strings.Join(checks, "; ")}, SecurityContext: restrictedSecurityContext(true)})
	}
	for index := range containers {
		applyContainerDefaults(&containers[index])
	}
	for index := range initContainers {
		applyContainerDefaults(&initContainers[index])
	}
	podSecurity, err := mergeAPIObjects(defaults.PodSecurityContext, actor.PodSecurityContext)
	if err != nil {
		return nil, fmt.Errorf("actor %q pod security context: %w", actor.Name, err)
	}
	if boolValue(trustedProbe.Enabled, false) {
		if podSecurity == nil {
			podSecurity = &corev1.PodSecurityContext{}
		} else {
			podSecurity = podSecurity.DeepCopy()
		}
		if podSecurity.FSGroup == nil {
			podSecurity.FSGroup = ptr[int64](65532)
			policy := corev1.FSGroupChangeOnRootMismatch
			podSecurity.FSGroupChangePolicy = &policy
		}
	}
	grace := int64(30)
	if defaults.TerminationGracePeriodSeconds != nil {
		grace = *defaults.TerminationGracePeriodSeconds
	}
	if actor.TerminationGracePeriodSeconds != nil {
		grace = *actor.TerminationGracePeriodSeconds
	}
	podSpec := corev1.PodSpec{
		AutomountServiceAccountToken:  ptr(false),
		TerminationGracePeriodSeconds: &grace,
		SecurityContext:               podSecurity,
		Containers:                    containers,
		InitContainers:                initContainers,
		Volumes:                       volumes,
		ImagePullSecrets:              append([]corev1.LocalObjectReference(nil), defaults.ImagePullSecrets...),
		RestartPolicy:                 corev1.RestartPolicyAlways,
		DNSPolicy:                     corev1.DNSClusterFirst,
		SchedulerName:                 corev1.DefaultSchedulerName,
	}
	if err := c.expandObject(chooseMap(defaults.NodeSelector, actor.NodeSelector), &podSpec.NodeSelector); err != nil {
		return nil, err
	}
	if err := c.expandObject(chooseAffinity(defaults.Affinity, actor.Affinity), &podSpec.Affinity); err != nil {
		return nil, err
	}
	if err := c.expandObject(chooseTolerations(defaults.Tolerations, actor.Tolerations), &podSpec.Tolerations); err != nil {
		return nil, err
	}
	if err := c.expandObject(chooseSpread(defaults.TopologySpreadConstraints, actor.TopologySpreadConstraints), &podSpec.TopologySpreadConstraints); err != nil {
		return nil, err
	}
	replicas := int32(1)
	if c.network.Spec.Suspended || actor.Suspended {
		replicas = 0
	}
	revisionHistoryLimit := int32(10)
	result := &appsv1.StatefulSet{ObjectMeta: c.metadata(), Spec: appsv1.StatefulSetSpec{
		ServiceName: c.name, Replicas: &replicas, PodManagementPolicy: appsv1.ParallelPodManagement,
		PersistentVolumeClaimRetentionPolicy: &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType, WhenScaled: appsv1.RetainPersistentVolumeClaimRetentionPolicyType},
		UpdateStrategy:                       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType},
		Selector:                             &metav1.LabelSelector{MatchLabels: map[string]string{networkLabel: c.network.Name, actorLabel: actor.Name}},
		Template:                             corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: c.labels(), Annotations: annotations}, Spec: podSpec}, VolumeClaimTemplates: claims,
		RevisionHistoryLimit: &revisionHistoryLimit,
	}}
	if err := c.own(result); err != nil {
		return nil, err
	}
	return result, nil
}

func resourceValue(value *corev1.ResourceRequirements) corev1.ResourceRequirements {
	if value == nil {
		return corev1.ResourceRequirements{}
	}
	return *value.DeepCopy()
}
func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
func chooseMap(base, override map[string]string) map[string]string {
	if override != nil {
		return override
	}
	return base
}
func chooseAffinity(base, override *corev1.Affinity) *corev1.Affinity {
	if override != nil {
		return override
	}
	return base
}
func chooseTolerations(base, override []corev1.Toleration) []corev1.Toleration {
	if override != nil {
		return override
	}
	return base
}
func chooseSpread(base, override []corev1.TopologySpreadConstraint) []corev1.TopologySpreadConstraint {
	if override != nil {
		return override
	}
	return base
}

func restrictedSecurityContext(readOnly bool) *corev1.SecurityContext {
	return &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(readOnly), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}
}

func defaultReadinessProbe(role string) *corev1.Probe {
	probe := &corev1.Probe{PeriodSeconds: 5, FailureThreshold: 30}
	switch role {
	case "signer":
		probe.ProbeHandler.TCPSocket = &corev1.TCPSocketAction{Port: intstr.FromString("events")}
	case "burnchain":
		probe.ProbeHandler.TCPSocket = &corev1.TCPSocketAction{Port: intstr.FromString("rpc")}
	case "miner", "companion", "follower", "adversary":
		probe.ProbeHandler.HTTPGet = &corev1.HTTPGetAction{Path: "/v2/info", Port: intstr.FromString("rpc")}
		probe.FailureThreshold = 90
	default:
		return nil
	}
	return probe
}

func applyContainerDefaults(container *corev1.Container) {
	if container.ImagePullPolicy == "" {
		container.ImagePullPolicy = defaultImagePullPolicy(container.Image)
	}
	if container.TerminationMessagePath == "" {
		container.TerminationMessagePath = corev1.TerminationMessagePathDefault
	}
	if container.TerminationMessagePolicy == "" {
		container.TerminationMessagePolicy = corev1.TerminationMessageReadFile
	}
	applyProbeDefaults(container.LivenessProbe)
	applyProbeDefaults(container.ReadinessProbe)
	applyProbeDefaults(container.StartupProbe)
}

func applyProbeDefaults(probe *corev1.Probe) {
	if probe == nil {
		return
	}
	if probe.TimeoutSeconds == 0 {
		probe.TimeoutSeconds = 1
	}
	if probe.PeriodSeconds == 0 {
		probe.PeriodSeconds = 10
	}
	if probe.SuccessThreshold == 0 {
		probe.SuccessThreshold = 1
	}
	if probe.FailureThreshold == 0 {
		probe.FailureThreshold = 3
	}
	if probe.HTTPGet != nil && probe.HTTPGet.Scheme == "" {
		probe.HTTPGet.Scheme = corev1.URISchemeHTTP
	}
}

func defaultImagePullPolicy(image string) corev1.PullPolicy {
	if strings.Contains(image, "@") {
		return corev1.PullIfNotPresent
	}
	lastSlash := strings.LastIndexByte(image, '/')
	lastColon := strings.LastIndexByte(image, ':')
	if lastColon <= lastSlash || image[lastColon+1:] == "latest" {
		return corev1.PullAlways
	}
	return corev1.PullIfNotPresent
}

func (c actorContext) configVolume() (*corev1.Volume, *corev1.VolumeMount) {
	if c.actor.Config == nil {
		return nil, nil
	}
	volume := &corev1.Volume{Name: "actor-config"}
	config := c.actor.Config
	switch {
	case config.Inline != "" || config.Files != nil:
		volume.ConfigMap = &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: c.name}, DefaultMode: ptr[int32](0o644)}
	case config.ConfigMapRef != nil:
		volume.ConfigMap = &corev1.ConfigMapVolumeSource{LocalObjectReference: *config.ConfigMapRef, DefaultMode: ptr[int32](0o644)}
	case config.SecretRef != nil:
		volume.Secret = &corev1.SecretVolumeSource{SecretName: config.SecretRef.Name, DefaultMode: ptr[int32](0o644)}
	default:
		return nil, nil
	}
	return volume, &corev1.VolumeMount{Name: "actor-config", MountPath: configMountPath(c.actor), ReadOnly: true}
}

func replaceOrAppendConfigVolume(volumes []corev1.Volume, actor *corev1.Container, name string) []corev1.Volume {
	for index := range volumes {
		if volumes[index].Name == "actor-config" && volumes[index].ConfigMap != nil && volumes[index].ConfigMap.Name == name {
			volumes[index].Name = "generated-config"
			for mount := range actor.VolumeMounts {
				if actor.VolumeMounts[mount].Name == "actor-config" {
					actor.VolumeMounts[mount].Name = "generated-config"
				}
			}
			return volumes
		}
	}
	return append(volumes, corev1.Volume{Name: "generated-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}, DefaultMode: ptr[int32](0o644)}}})
}

func (c actorContext) telemetryContainer(settings attacknetv1alpha1.TelemetrySpec) (corev1.Container, error) {
	endpoint, err := c.expand(settings.ExporterEndpoint)
	if err != nil {
		return corev1.Container{}, err
	}
	env := []corev1.EnvVar{{Name: "STACKS_FEDERATION_ENDPOINT", Value: endpoint}}
	if settings.TokenSecretRef != nil {
		env = append(env, corev1.EnvVar{Name: "STACKS_FEDERATION_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: settings.TokenSecretRef.Name}, Key: settings.TokenSecretRef.Key}}})
	}
	return corev1.Container{Name: "telemetry", Image: settings.Image, ImagePullPolicy: pullPolicy(settings.ImagePullPolicy, corev1.PullIfNotPresent), Args: []string{"--config=/etc/otelcol-contrib/config.yaml"}, Env: env, Ports: []corev1.ContainerPort{{Name: "otel-health", ContainerPort: 13133, Protocol: corev1.ProtocolTCP}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/", Port: intstr.FromString("otel-health")}}, PeriodSeconds: 5}, SecurityContext: restrictedSecurityContext(true), Resources: copyResources(settings.Resources, corev1.ResourceRequirements{}), VolumeMounts: []corev1.VolumeMount{{Name: "generated-config", MountPath: "/etc/otelcol-contrib/config.yaml", SubPath: "otelcol.yaml", ReadOnly: true}, {Name: "telemetry-tmp", MountPath: "/tmp"}}}, nil
}

func (c actorContext) probeContainer(settings attacknetv1alpha1.ProbeSpec, storage attacknetv1alpha1.StorageSpec) (corev1.Container, error) {
	type peer struct {
		Host  string           `json:"host"`
		Ports map[string]int32 `json:"ports"`
	}
	peers := map[string]peer{}
	for index := range c.network.Spec.Actors {
		actor := &c.network.Spec.Actors[index]
		ports := map[string]int32{}
		for _, port := range effectivePorts(actor) {
			ports[port.Name] = port.ServicePort
		}
		if boolValue(probeSettings(c.network, actor).Enabled, false) {
			ports["probe"] = 18080
		}
		peers[actor.Name] = peer{Host: fmt.Sprintf("%s.%s.svc.cluster.local", c.services[actor.Name], c.network.Namespace), Ports: ports}
	}
	for _, service := range settings.AdditionalServices {
		ports := map[string]int32{}
		for _, port := range service.Ports {
			ports[port.Name] = port.Port
		}
		peers[service.Name] = peer{Host: fmt.Sprintf("%s.%s.svc.cluster.local", service.ServiceName, c.network.Namespace), Ports: ports}
	}
	encoded, err := json.Marshal(peers)
	if err != nil {
		return corev1.Container{}, err
	}
	runAs := int64(65532)
	seccomp := corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	return corev1.Container{Name: "attacknet-probe", Image: settings.Image, ImagePullPolicy: pullPolicy(settings.ImagePullPolicy, corev1.PullIfNotPresent), Env: []corev1.EnvVar{{Name: "PROBE_ACTOR", Value: c.actor.Name}, {Name: "PROBE_PORT", Value: "18080"}, {Name: "PROBE_DATA_ROOT", Value: storage.MountPath}, {Name: "PROBE_DNS_CONTROL", Value: "kubernetes.default.svc.cluster.local"}, {Name: "PROBE_PEERS_JSON", Value: string(encoded)}}, Ports: []corev1.ContainerPort{{Name: "probe", ContainerPort: 18080, Protocol: corev1.ProtocolTCP}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("probe")}}, PeriodSeconds: 5, FailureThreshold: 6}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(false), RunAsNonRoot: ptr(true), RunAsUser: &runAs, RunAsGroup: &runAs, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &seccomp}, Resources: copyResources(settings.Resources, corev1.ResourceRequirements{}), VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: storage.MountPath}}}, nil
}

func validateNetwork(network *attacknetv1alpha1.StacksNetwork) error {
	if network.Name == "" || network.Namespace == "" || network.UID == "" {
		return fmt.Errorf("metadata.name, metadata.namespace, and metadata.uid are required")
	}
	if len(network.Spec.Actors) < 1 || len(network.Spec.Actors) > 100 {
		return fmt.Errorf("spec.actors must contain between 1 and 100 actors")
	}
	actors := map[string]*attacknetv1alpha1.ActorSpec{}
	validRoles := map[string]bool{"burnchain": true, "miner": true, "signer": true, "companion": true, "follower": true, "adversary": true, "infrastructure": true}
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		if actor.Name == "" || len(actor.Name) > 40 || len(validation.IsDNS1123Label(actor.Name)) > 0 {
			return fmt.Errorf("invalid actor name %q", actor.Name)
		}
		if _, exists := actors[actor.Name]; exists {
			return fmt.Errorf("duplicate actor name %q", actor.Name)
		}
		actors[actor.Name] = actor
		if !validRoles[actor.Role] {
			return fmt.Errorf("actor %q has invalid role %q", actor.Name, actor.Role)
		}
		if actorImage(network, actor) == "" {
			return fmt.Errorf("actor %q has no image and no applicable default image", actor.Name)
		}
		if actor.RuntimeExposure != "" && actor.RuntimeExposure != "ready" && actor.RuntimeExposure != "reachable" {
			return fmt.Errorf("actor %q has invalid runtimeExposure", actor.Name)
		}
		sources := 0
		if actor.Config != nil {
			if actor.Config.Inline != "" {
				sources++
			}
			if actor.Config.Files != nil {
				if len(actor.Config.Files) == 0 {
					return fmt.Errorf("actor %q config files must not be empty", actor.Name)
				}
				sources++
			}
			if actor.Config.ConfigMapRef != nil {
				sources++
			}
			if actor.Config.SecretRef != nil {
				sources++
			}
			for key := range actor.Config.Files {
				if problems := validation.IsConfigMapKey(key); len(problems) > 0 {
					return fmt.Errorf("actor %q config key %q is invalid: %s", actor.Name, key, strings.Join(problems, "; "))
				}
			}
		}
		if sources > 1 {
			return fmt.Errorf("actor %q config must use exactly one inline, files, ConfigMap, or Secret source", actor.Name)
		}
		if (actor.Role == "miner" || actor.Role == "signer" || actor.Role == "companion" || actor.Role == "follower") && sources != 1 {
			return fmt.Errorf("Stacks actor %q requires exactly one config source", actor.Name)
		}
		if problems := validation.IsConfigMapKey(configKey(actor)); len(problems) > 0 {
			return fmt.Errorf("actor %q config key %q is invalid: %s", actor.Name, configKey(actor), strings.Join(problems, "; "))
		}
		if actor.RuntimePolicy != nil {
			name := actor.RuntimePolicy.ConfigMapRef.Name
			if len(name) > 63 || len(validation.IsDNS1123Label(name)) > 0 {
				return fmt.Errorf("actor %q has invalid runtime policy ConfigMap name", actor.Name)
			}
		}
		ports := map[string]bool{}
		portNumbers := map[string]bool{}
		for _, port := range effectivePorts(actor) {
			if port.Name == "" || len(port.Name) > 15 || len(validation.IsDNS1123Label(port.Name)) > 0 || port.ContainerPort < 1 || port.ServicePort < 1 {
				return fmt.Errorf("actor %q has an invalid port", actor.Name)
			}
			if ports[port.Name] {
				return fmt.Errorf("actor %q declares duplicate port %q", actor.Name, port.Name)
			}
			numberKey := fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol)
			if portNumbers[numberKey] {
				return fmt.Errorf("actor %q declares duplicate container port %s", actor.Name, numberKey)
			}
			ports[port.Name] = true
			portNumbers[numberKey] = true
		}
		if boolValue(probeSettings(network, actor).Enabled, false) && ports["probe"] {
			return fmt.Errorf("actor %q reserves port name probe for the trusted probe sidecar", actor.Name)
		}
		if boolValue(telemetrySettings(network, actor).Enabled, false) && telemetrySettings(network, actor).ExporterEndpoint == "" {
			return fmt.Errorf("actor %q enables telemetry without exporterEndpoint", actor.Name)
		}
		if boolValue(probeSettings(network, actor).Enabled, false) && probeSettings(network, actor).Image == "" {
			return fmt.Errorf("actor %q enables the trusted probe without an image", actor.Name)
		}
	}
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		for _, dependency := range actor.Dependencies {
			target, exists := actors[dependency.Actor]
			if !exists {
				return fmt.Errorf("actor %q depends on unknown actor %q", actor.Name, dependency.Actor)
			}
			if target == actor {
				return fmt.Errorf("actor %q cannot depend on itself", actor.Name)
			}
			found := false
			for _, port := range effectivePorts(target) {
				if port.ServicePort == dependency.Port {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("actor %q dependency %q uses port %d, which the target does not expose", actor.Name, dependency.Actor, dependency.Port)
			}
		}
	}
	return nil
}
