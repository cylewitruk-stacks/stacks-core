package burnchainpolicy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

type resourceConfig struct {
	Image           string
	ImagePullPolicy corev1.PullPolicy
	BitcoinService  string
	BitcoinRPCPort  int32
	Runtime         desiredRuntime
	Policy          *attacknetv1beta1.BurnchainPolicy
	Network         *attacknetv1beta1.StacksNetwork
	Scheme          *runtime.Scheme
}

func (configuration resourceConfig) configMap() (*corev1.ConfigMap, error) {
	labels := configuration.labels()
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: configuration.resourceName(), Namespace: configuration.Policy.Namespace,
			Labels: labels, Annotations: map[string]string{
				annotationRuntimeGen:   strconv.FormatUint(configuration.Runtime.policy.Generation, 10),
				annotationPolicyDigest: configuration.Runtime.digest, annotationFlashID: configuration.Runtime.flashID,
			},
		},
		Data: map[string]string{policyKey: configuration.Runtime.encoded},
	}
	if err := ownership.SetControllerReference(configuration.Policy, configMap, configuration.Scheme); err != nil {
		return nil, fmt.Errorf("set policy ConfigMap owner: %w", err)
	}
	return configMap, nil
}

func (configuration resourceConfig) deployment() (*appsv1.Deployment, error) {
	labels := configuration.labels()
	wallets, addresses := make([]string, 0, len(configuration.Policy.Spec.Destinations)), make([]string, 0, len(configuration.Policy.Spec.Destinations))
	for _, destination := range configuration.Policy.Spec.Destinations {
		wallets = append(wallets, destination.WalletName)
		addresses = append(addresses, destination.Address)
	}
	rpcTimeout, minimumBackoff, maximumBackoff := durationSeconds(configuration.Policy.Spec.RPC.Timeout.Duration, 30), durationSeconds(configuration.Policy.Spec.RPC.MinimumBackoff.Duration, 1), durationSeconds(configuration.Policy.Spec.RPC.MaximumBackoff.Duration, 10)
	if maximumBackoff < minimumBackoff {
		maximumBackoff = minimumBackoff
	}
	container := corev1.Container{
		Name: "clock", Image: configuration.Image, ImagePullPolicy: configuration.ImagePullPolicy,
		Env: []corev1.EnvVar{
			{Name: "BITCOIN_RPC_HOST", Value: configuration.BitcoinService},
			{Name: "BITCOIN_RPC_PORT", Value: strconv.Itoa(int(configuration.BitcoinRPCPort))},
			{Name: "BITCOIN_RPC_USER", Value: "devnet"}, {Name: "BITCOIN_RPC_PASSWORD", Value: "devnet"},
			{Name: "MINER_WALLETS", Value: strings.Join(wallets, ",")}, {Name: "MINER_BTC_ADDRS", Value: strings.Join(addresses, ",")},
			{Name: "BURNCHAIN_BOOTSTRAP_HEIGHT", Value: strconv.FormatInt(configuration.Policy.Spec.BootstrapHeight, 10)},
			{Name: "BURNCHAIN_MINER_RESERVE_OUTPUTS", Value: strconv.FormatInt(reserveOutputs(configuration.Policy), 10)},
			{Name: "BURNCHAIN_RANDOM_SEED", Value: strconv.FormatUint(deterministicSeed(string(configuration.Policy.UID)), 10)},
			{Name: "BURNCHAIN_RPC_TIMEOUT_SECONDS", Value: strconv.FormatUint(rpcTimeout, 10)},
			{Name: "BURNCHAIN_RETRY_INITIAL_SECONDS", Value: strconv.FormatUint(minimumBackoff, 10)},
			{Name: "BURNCHAIN_RETRY_MAXIMUM_SECONDS", Value: strconv.FormatUint(maximumBackoff, 10)},
		},
		Ports:          []corev1.ContainerPort{{Name: "health", ContainerPort: clockHealthPort, Protocol: corev1.ProtocolTCP}},
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstrFromInt32(clockHealthPort)}}, PeriodSeconds: 2, TimeoutSeconds: 1, FailureThreshold: 15},
		LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/", Port: intstrFromInt32(clockHealthPort)}}, PeriodSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("24Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("96Mi")},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), RunAsNonRoot: ptr.To(true),
			RunAsUser: ptr.To[int64](65532), RunAsGroup: ptr.To[int64](65532),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts:           []corev1.VolumeMount{{Name: "policy", MountPath: "/run/hacknet-policy", ReadOnly: true}, {Name: "tmp", MountPath: "/tmp"}},
		TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: corev1.TerminationMessageReadFile,
	}
	if username, password := configuration.Policy.Spec.RPC.UsernameSecretRef, configuration.Policy.Spec.RPC.PasswordSecretRef; username != nil && password != nil {
		container.Env[2] = secretEnv("BITCOIN_RPC_USER", username)
		container.Env[3] = secretEnv("BITCOIN_RPC_PASSWORD", password)
	}
	replicas, history, progress, grace := int32(1), int32(2), int32(120), int64(15)
	enableServiceLinks := false
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: configuration.resourceName(), Namespace: configuration.Policy.Namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas, RevisionHistoryLimit: &history, ProgressDeadlineSeconds: &progress,
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: map[string]string{annotationPolicyDigest: configuration.Runtime.digest}},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: &enableServiceLinks,
					RestartPolicy: corev1.RestartPolicyAlways, DNSPolicy: corev1.DNSClusterFirst,
					TerminationGracePeriodSeconds: &grace, SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{container}, ImagePullSecrets: append([]corev1.LocalObjectReference(nil), configuration.Network.Spec.Defaults.ImagePullSecrets...),
					Volumes: []corev1.Volume{
						{Name: "policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configuration.resourceName()}}}},
						{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					},
				},
			},
		},
	}
	if err := ownership.SetControllerReference(configuration.Policy, deployment, configuration.Scheme); err != nil {
		return nil, fmt.Errorf("set policy Deployment owner: %w", err)
	}
	return deployment, nil
}

// reserveOutputs preserves the default for objects constructed outside API defaulting.
func reserveOutputs(policy *attacknetv1beta1.BurnchainPolicy) int64 {
	if policy.Spec.ReserveOutputs == nil {
		return 4
	}
	return int64(*policy.Spec.ReserveOutputs)
}

func (configuration resourceConfig) service() (*corev1.Service, error) {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: configuration.resourceName(), Namespace: configuration.Policy.Namespace, Labels: configuration.labels()},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: configuration.labels(),
			Ports: []corev1.ServicePort{{Name: "metrics", Port: clockHealthPort, TargetPort: intstrFromInt32(clockHealthPort), Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := ownership.SetControllerReference(configuration.Policy, service, configuration.Scheme); err != nil {
		return nil, fmt.Errorf("set policy Service owner: %w", err)
	}
	return service, nil
}

func (configuration resourceConfig) resourceName() string {
	return burnchaintopology.PolicyServiceName(configuration.Policy.Name)
}

func (configuration resourceConfig) labels() map[string]string {
	return map[string]string{
		labelManagedBy: labelManagedByValue, labelNetwork: configuration.Network.Name,
		labelPolicy: configuration.Policy.Name, labelComponent: componentClock,
	}
}

func durationSeconds(value time.Duration, fallback uint64) uint64 {
	if value == 0 {
		return fallback
	}
	return uint64(value / time.Second)
}

func intstrFromInt32(value int32) intstr.IntOrString {
	return intstr.FromInt32(value)
}

func secretEnv(name string, reference *attacknetv1beta1.SecretKeyReference) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: reference.Name}, Key: reference.Key,
	}}}
}
