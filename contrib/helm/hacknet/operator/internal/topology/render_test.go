package topology

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, attacknetv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func testNetwork() *attacknetv1alpha1.StacksNetwork {
	enabled := true
	return &attacknetv1alpha1.StacksNetwork{TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1alpha1.GroupVersion.String(), Kind: "StacksNetwork"}, ObjectMeta: metav1.ObjectMeta{Name: "attacknet", Namespace: "test", UID: types.UID("network-uid"), Generation: 4}, Spec: attacknetv1alpha1.StacksNetworkSpec{Defaults: attacknetv1alpha1.StacksNetworkDefaults{NodeImage: "stacks-node:test", SignerImage: "stacks-signer:test"}, Telemetry: &attacknetv1alpha1.TelemetrySpec{Enabled: &enabled, ExporterEndpoint: "http://${SERVICE:collector}:4318", Image: "otel:test"}, Actors: []attacknetv1alpha1.ActorSpec{{Name: "collector", Role: "infrastructure", Image: "collector:test", Storage: &attacknetv1alpha1.StorageSpec{Enabled: ptr(false)}}, {Name: "miner-1", Role: "miner", Config: &attacknetv1alpha1.ActorConfig{Inline: "peer=${SERVICE:signer-1}"}, Dependencies: []attacknetv1alpha1.ActorDependency{{Actor: "signer-1", Port: 30000}}}, {Name: "signer-1", Role: "signer", Config: &attacknetv1alpha1.ActorConfig{Files: map[string]string{"signer.toml": "node=${SERVICE:miner-1}"}}}}}}
}

func TestRenderPreservesSecurityStorageAndDependencies(t *testing.T) {
	resources, err := Render(testNetwork(), testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Services) != 3 || len(resources.StatefulSets) != 3 || len(resources.ConfigMaps) != 3 {
		t.Fatalf("unexpected resources: %#v", resources)
	}
	miner := resources.StatefulSets[1]
	if miner.Spec.PersistentVolumeClaimRetentionPolicy == nil || miner.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted != appsv1.DeletePersistentVolumeClaimRetentionPolicyType || miner.Spec.PersistentVolumeClaimRetentionPolicy.WhenScaled != appsv1.RetainPersistentVolumeClaimRetentionPolicyType {
		t.Fatal("PVC retention policy changed")
	}
	if miner.Spec.Template.Spec.AutomountServiceAccountToken == nil || *miner.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("actor Pod has a ServiceAccount token")
	}
	if len(miner.Spec.Template.Spec.InitContainers) != 1 || !strings.Contains(strings.Join(miner.Spec.Template.Spec.InitContainers[0].Command, " "), "attacknet-signer-1 30000") {
		t.Fatal("dependency gate was not rendered")
	}
	if len(miner.Spec.Template.Spec.Containers) != 2 || miner.Spec.Template.Spec.Containers[1].Name != "telemetry" {
		t.Fatal("telemetry sidecar missing")
	}
	if got := miner.Spec.Template.Spec.Containers[1].Env[0].Value; got != "http://attacknet-collector:4318" {
		t.Fatalf("telemetry endpoint was not expanded: %s", got)
	}
	if owner := metav1.GetControllerOf(miner); owner == nil || owner.UID != "network-uid" {
		t.Fatal("controller owner reference missing")
	} else if owner.BlockOwnerDeletion != nil {
		t.Fatal("controller owner reference unexpectedly requires owner deletion authority")
	}
	if miner.Labels[legacyManagedByLabel] != legacyManagedByValue || miner.Labels[managedByLabel] != managedByValue {
		t.Fatalf("managed-by compatibility labels are incomplete: %#v", miner.Labels)
	}
}

func TestRenderVerifiesSealedExternalConfigurationBeforeActorStartup(t *testing.T) {
	network := testNetwork()
	network.Spec.Actors[1].Config = &attacknetv1alpha1.ActorConfig{
		ConfigMapRef:   &corev1.LocalObjectReference{Name: "sealed-miner-config"},
		Key:            "config.toml",
		MountPath:      "/etc/stacks",
		ExpectedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	var miner *appsv1.StatefulSet
	for _, statefulSet := range resources.StatefulSets {
		if statefulSet.Labels[actorLabel] == "miner-1" {
			miner = statefulSet
		}
	}
	if miner == nil || len(miner.Spec.Template.Spec.InitContainers) != 2 {
		t.Fatalf("config verifier was not rendered before dependency gating: %#v", miner)
	}
	verifier := miner.Spec.Template.Spec.InitContainers[0]
	if verifier.Name != "verify-config-digest" || len(verifier.VolumeMounts) != 1 || verifier.VolumeMounts[0].Name != "actor-config" || verifier.SecurityContext == nil || verifier.SecurityContext.ReadOnlyRootFilesystem == nil || !*verifier.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("config verifier does not preserve its restricted, credential-free mount contract: %#v", verifier)
	}
	if len(verifier.Env) != 2 || verifier.Env[0].Value != "/etc/stacks/config.toml" || !strings.Contains(strings.Join(verifier.Command, " "), "sha256sum") {
		t.Fatalf("config verifier does not bind the mounted file: %#v", verifier)
	}
}

func TestRenderMakesStableKubernetesDefaultsExplicit(t *testing.T) {
	resources, err := Render(testNetwork(), testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range resources.Services {
		if service.Spec.SessionAffinity != corev1.ServiceAffinityNone ||
			service.Spec.InternalTrafficPolicy == nil ||
			*service.Spec.InternalTrafficPolicy != corev1.ServiceInternalTrafficPolicyCluster {
			t.Fatalf("Service API defaults are implicit for %s: %#v", service.Name, service.Spec)
		}
	}
	for _, statefulSet := range resources.StatefulSets {
		if statefulSet.Spec.RevisionHistoryLimit == nil || *statefulSet.Spec.RevisionHistoryLimit != 10 {
			t.Fatalf("StatefulSet revision-history default is implicit for %s", statefulSet.Name)
		}
		pod := statefulSet.Spec.Template.Spec
		if pod.RestartPolicy != corev1.RestartPolicyAlways || pod.DNSPolicy != corev1.DNSClusterFirst || pod.SchedulerName != corev1.DefaultSchedulerName {
			t.Fatalf("Pod API defaults are implicit for %s: %#v", statefulSet.Name, pod)
		}
		for _, container := range append(append([]corev1.Container(nil), pod.InitContainers...), pod.Containers...) {
			if container.ImagePullPolicy == "" || container.TerminationMessagePath != corev1.TerminationMessagePathDefault || container.TerminationMessagePolicy != corev1.TerminationMessageReadFile {
				t.Fatalf("container API defaults are implicit for %s/%s: %#v", statefulSet.Name, container.Name, container)
			}
			for _, probe := range []*corev1.Probe{container.LivenessProbe, container.ReadinessProbe, container.StartupProbe} {
				if probe == nil {
					continue
				}
				if probe.TimeoutSeconds == 0 || probe.PeriodSeconds == 0 || probe.SuccessThreshold == 0 || probe.FailureThreshold == 0 {
					t.Fatalf("probe API defaults are implicit for %s/%s: %#v", statefulSet.Name, container.Name, probe)
				}
				if probe.HTTPGet != nil && probe.HTTPGet.Scheme == "" {
					t.Fatalf("HTTP probe scheme is implicit for %s/%s", statefulSet.Name, container.Name)
				}
			}
		}
		for _, volume := range pod.Volumes {
			switch {
			case volume.ConfigMap != nil && volume.ConfigMap.DefaultMode == nil:
				t.Fatalf("ConfigMap mode is implicit for %s/%s", statefulSet.Name, volume.Name)
			case volume.Secret != nil && volume.Secret.DefaultMode == nil:
				t.Fatalf("Secret mode is implicit for %s/%s", statefulSet.Name, volume.Name)
			}
		}
	}
}

func TestDefaultImagePullPolicyMatchesKubernetes(t *testing.T) {
	tests := map[string]corev1.PullPolicy{
		"registry.example/image":                   corev1.PullAlways,
		"registry.example/image:latest":            corev1.PullAlways,
		"registry.example:5000/image:v1":           corev1.PullIfNotPresent,
		"registry.example/image@sha256:0123456789": corev1.PullIfNotPresent,
	}
	for image, expected := range tests {
		if actual := defaultImagePullPolicy(image); actual != expected {
			t.Errorf("defaultImagePullPolicy(%q) = %q, want %q", image, actual, expected)
		}
	}
}

func TestRenderProbeIsOptInAndCredentialFree(t *testing.T) {
	network := testNetwork()
	network.Spec.Telemetry = nil
	enabled := true
	network.Spec.Probe = &attacknetv1alpha1.ProbeSpec{Enabled: &enabled, Image: "probe:test"}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, statefulSet := range resources.StatefulSets {
		if len(statefulSet.Spec.Template.Spec.Containers) != 2 {
			t.Fatalf("probe missing from %s", statefulSet.Name)
		}
		probe := statefulSet.Spec.Template.Spec.Containers[1]
		if probe.Name != "attacknet-probe" || probe.SecurityContext == nil || probe.SecurityContext.RunAsNonRoot == nil || !*probe.SecurityContext.RunAsNonRoot {
			t.Fatal("probe security contract changed")
		}
		if *statefulSet.Spec.Template.Spec.AutomountServiceAccountToken {
			t.Fatal("probe Pod has Kubernetes credentials")
		}
	}
	for _, service := range resources.Services {
		found := false
		for _, port := range service.Spec.Ports {
			found = found || (port.Name == "probe" && port.Port == 18080)
		}
		if !found {
			t.Fatalf("trusted probe endpoint is not exposed by %s", service.Name)
		}
	}
	probeEnv := resources.StatefulSets[0].Spec.Template.Spec.Containers[1].Env
	if len(probeEnv) < 5 || !strings.Contains(probeEnv[4].Value, `"probe":18080`) {
		t.Fatalf("peer probe endpoints are absent from the trusted peer map: %#v", probeEnv)
	}
}

func TestStableNameIsDeterministicAndBounded(t *testing.T) {
	name := stableName(strings.Repeat("n", 40), strings.Repeat("a", 40))
	if len(name) > 63 || name != stableName(strings.Repeat("n", 40), strings.Repeat("a", 40)) {
		t.Fatalf("invalid stable name %q", name)
	}
}

func TestRenderSupportsReachableSuspendedAndSecretBackedActors(t *testing.T) {
	network := testNetwork()
	network.Spec.Telemetry = nil
	network.Spec.Actors = []attacknetv1alpha1.ActorSpec{{
		Name: "miner-1", Role: "miner", RuntimeExposure: "reachable", Suspended: true,
		Config: &attacknetv1alpha1.ActorConfig{SecretRef: &corev1.LocalObjectReference{Name: "miner-config"}},
	}}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if !resources.Services[0].Spec.PublishNotReadyAddresses {
		t.Fatal("reachable actor endpoints are still gated by readiness")
	}
	statefulSet := resources.StatefulSets[0]
	if statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 0 {
		t.Fatal("suspended actor was not scaled to zero")
	}
	found := false
	for _, volume := range statefulSet.Spec.Template.Spec.Volumes {
		found = found || (volume.Secret != nil && volume.Secret.SecretName == "miner-config")
	}
	if !found {
		t.Fatalf("secret-backed config was not mounted: %#v", statefulSet.Spec.Template.Spec.Volumes)
	}
}

func TestRenderRejectsAmbiguousSourcesUnknownDependenciesAndBadPorts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*attacknetv1alpha1.StacksNetwork)
	}{
		{name: "ambiguous config", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Config = &attacknetv1alpha1.ActorConfig{Inline: "a", ConfigMapRef: &corev1.LocalObjectReference{Name: "b"}}
		}},
		{name: "missing stacks config", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Config = nil
		}},
		{name: "invalid actor name", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Name = "Miner_1"
		}},
		{name: "invalid primary config key", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Config = &attacknetv1alpha1.ActorConfig{Inline: "x", Key: "bad/key"}
		}},
		{name: "invalid runtime policy reference", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].RuntimePolicy = &attacknetv1alpha1.RuntimePolicySpec{ConfigMapRef: corev1.LocalObjectReference{Name: "Bad_Name"}}
		}},
		{name: "invalid config key", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Config = &attacknetv1alpha1.ActorConfig{Files: map[string]string{"bad/key": "x"}}
		}},
		{name: "unknown dependency", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Dependencies = []attacknetv1alpha1.ActorDependency{{Actor: "missing", Port: 1}}
		}},
		{name: "unexposed dependency port", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Dependencies = []attacknetv1alpha1.ActorDependency{{Actor: "signer-1", Port: 1}}
		}},
		{name: "ambiguous dependency target", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Dependencies = []attacknetv1alpha1.ActorDependency{{Actor: "signer-1", Service: "clock-clock", Port: 30000}}
		}},
		{name: "invalid dependency service", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Dependencies = []attacknetv1alpha1.ActorDependency{{Service: "Bad_Service", Port: 18500}}
		}},
		{name: "duplicate port", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Ports = []attacknetv1alpha1.ActorPort{{Name: "rpc", ContainerPort: 1}, {Name: "rpc", ContainerPort: 2}}
		}},
		{name: "duplicate port number", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Ports = []attacknetv1alpha1.ActorPort{{Name: "rpc", ContainerPort: 1}, {Name: "p2p", ContainerPort: 1}}
		}},
		{name: "duplicate service port number", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			network.Spec.Actors[1].Ports = []attacknetv1alpha1.ActorPort{{Name: "rpc", ContainerPort: 1, ServicePort: 3}, {Name: "p2p", ContainerPort: 2, ServicePort: 3}}
		}},
		{name: "reserved probe port", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			enabled := true
			network.Spec.Probe = &attacknetv1alpha1.ProbeSpec{Enabled: &enabled, Image: "probe:test"}
			network.Spec.Actors[1].Ports = []attacknetv1alpha1.ActorPort{{Name: "probe", ContainerPort: 18080}}
		}},
		{name: "reserved probe service port", mutate: func(network *attacknetv1alpha1.StacksNetwork) {
			enabled := true
			network.Spec.Probe = &attacknetv1alpha1.ProbeSpec{Enabled: &enabled, Image: "probe:test"}
			network.Spec.Actors[1].Ports = []attacknetv1alpha1.ActorPort{{Name: "health", ContainerPort: 8080, ServicePort: 18080}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network := testNetwork()
			test.mutate(network)
			if _, err := Render(network, testScheme(t)); err == nil {
				t.Fatal("invalid network rendered")
			}
		})
	}
}

func TestRenderSameNamespaceServiceDependency(t *testing.T) {
	network := testNetwork()
	network.Spec.Actors[1].Dependencies = []attacknetv1alpha1.ActorDependency{{Service: "clock-clock", Port: 18500}}
	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	statefulSet := resources.StatefulSets[1]
	command := strings.Join(statefulSet.Spec.Template.Spec.InitContainers[0].Command, " ")
	if !strings.Contains(command, "nc -z clock-clock 18500") {
		t.Fatalf("Service dependency command = %q", command)
	}
}

func TestRenderDeepMergesOverridesAndExpandsSchedulingFields(t *testing.T) {
	network := testNetwork()
	network.Spec.Telemetry = nil
	network.Spec.Defaults.Resources = &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("1Gi")},
	}
	network.Spec.Defaults.ContainerSecurityContext = &corev1.SecurityContext{RunAsNonRoot: ptr(true), ReadOnlyRootFilesystem: ptr(true)}
	network.Spec.Actors[1].Resources = &corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m")}}
	network.Spec.Actors[1].ContainerSecurityContext = &corev1.SecurityContext{Privileged: ptr(false)}
	network.Spec.Actors[1].NodeSelector = map[string]string{"service": "${SERVICE:signer-1}"}
	network.Spec.Actors[1].Env = []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "${NETWORK}-token"}, Key: "token"}}}}

	resources, err := Render(network, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	actor := resources.StatefulSets[1].Spec.Template.Spec.Containers[0]
	if actor.Resources.Requests.Cpu().String() != "250m" || actor.Resources.Requests.Memory().String() != "128Mi" || actor.Resources.Limits.Memory().String() != "1Gi" {
		t.Fatalf("partial resource override discarded defaults: %#v", actor.Resources)
	}
	if actor.SecurityContext.RunAsNonRoot == nil || !*actor.SecurityContext.RunAsNonRoot || actor.SecurityContext.ReadOnlyRootFilesystem == nil || !*actor.SecurityContext.ReadOnlyRootFilesystem || actor.SecurityContext.Privileged == nil || *actor.SecurityContext.Privileged {
		t.Fatalf("partial security override discarded defaults: %#v", actor.SecurityContext)
	}
	pod := resources.StatefulSets[1].Spec.Template.Spec
	if pod.NodeSelector["service"] != "attacknet-signer-1" {
		t.Fatalf("scheduling placeholder was not expanded: %#v", pod.NodeSelector)
	}
	if actor.Env[len(actor.Env)-1].ValueFrom.SecretKeyRef.Name != "attacknet-token" {
		t.Fatalf("nested environment placeholder was not expanded: %#v", actor.Env)
	}
}
