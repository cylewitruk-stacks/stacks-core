package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
)

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
		Config                  *attacknetv1alpha1.ActorConfig   `json:"config"`
		Telemetry               *attacknetv1alpha1.TelemetrySpec `json:"telemetry"`
		Probe                   *attacknetv1alpha1.ProbeSpec     `json:"probe"`
		Command, Args           []string
		AdversarialPolicyDigest string `json:"adversarialPolicyDigest,omitempty"`
	}{Config: actor.Config, Command: command, Args: args, AdversarialPolicyDigest: actor.AdversarialPolicyDigest}
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
	if actor.Role == "signer" && actor.AdversarialPolicyDigest != "" {
		main.Env = append(main.Env, corev1.EnvVar{
			Name: "STACKS_SIGNER_ATTACKNET_SESSION", Value: adversarial.SessionFilePath,
		})
		main.VolumeMounts = append(main.VolumeMounts, corev1.VolumeMount{
			Name: "adversarial-session", MountPath: adversarial.SessionMountPath, ReadOnly: true,
		})
		volumes = append(volumes, corev1.Volume{
			Name: "adversarial-session",
			VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{{
				Path: "session.json", FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1", FieldPath: "metadata.annotations['" + adversarial.SessionAnnotation + "']",
				},
			}}}},
		})
	}
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
	if actor.Config != nil && actor.Config.ExpectedDigest != "" {
		mount, ok := mountedActorConfig(containers[0])
		if !ok {
			return nil, fmt.Errorf("actor %q declares an expected config digest without a mounted config", actor.Name)
		}
		initContainers = append(initContainers, corev1.Container{
			Name:    "verify-config-digest",
			Image:   defaultString(defaults.DependencyImage, "busybox:1.36.1"),
			Command: []string{"sh", "-ec", `set -- $(sha256sum "$CONFIG_PATH"); actual="sha256:$1"; if [ "$actual" != "$EXPECTED_CONFIG_DIGEST" ]; then echo "mounted actor configuration digest mismatch" >&2; exit 1; fi`},
			Env: []corev1.EnvVar{
				{Name: "CONFIG_PATH", Value: actorConfigPath(actor.Config)},
				{Name: "EXPECTED_CONFIG_DIGEST", Value: actor.Config.ExpectedDigest},
			},
			SecurityContext: restrictedSecurityContext(true),
			VolumeMounts:    []corev1.VolumeMount{mount},
		})
	}
	if len(actor.Dependencies) > 0 {
		checks := make([]string, 0, len(actor.Dependencies))
		for _, dependency := range actor.Dependencies {
			host := dependency.Service
			if dependency.Actor != "" {
				host = c.services[dependency.Actor]
			}
			checks = append(checks, fmt.Sprintf("until nc -z %s %d; do sleep 1; done", host, dependency.Port))
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

func mountedActorConfig(container corev1.Container) (corev1.VolumeMount, bool) {
	for _, mount := range container.VolumeMounts {
		if mount.Name == "actor-config" || mount.Name == "generated-config" {
			return *mount.DeepCopy(), true
		}
	}
	return corev1.VolumeMount{}, false
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
