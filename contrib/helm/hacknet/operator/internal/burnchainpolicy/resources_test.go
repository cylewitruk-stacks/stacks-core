package burnchainpolicy

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestDeploymentIsRestrictedAndUsesSecretProjections(t *testing.T) {
	policy := validPolicy()
	policy.Spec.RPC.UsernameSecretRef = &attacknetv1beta1.SecretKeyReference{Name: "bitcoin-auth", Key: "username"}
	policy.Spec.RPC.PasswordSecretRef = &attacknetv1beta1.SecretKeyReference{Name: "bitcoin-auth", Key: "password"}
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	configuration := resourceConfig{
		Image: "clock@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ImagePullPolicy: corev1.PullIfNotPresent,
		BitcoinService: "bitcoin-1", BitcoinRPCPort: 18443, Runtime: desiredRuntime{encoded: "POLICY_GENERATION=1\n", digest: "sha256:digest"},
		Policy: policy, Network: &attacknetv1beta1.StacksNetwork{Spec: attacknetv1beta1.StacksNetworkSpec{}}, Scheme: scheme,
	}
	deployment, err := configuration.deployment()
	if err != nil {
		t.Fatal(err)
	}
	if deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
		t.Fatalf("unexpected Deployment strategy: %#v", deployment.Spec)
	}
	pod := deployment.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || len(pod.Containers) != 1 {
		t.Fatalf("clock Pod exposes ambient Kubernetes credentials: %#v", pod)
	}
	container := pod.Containers[0]
	security := container.SecurityContext
	if security == nil || !ptr.Deref(security.ReadOnlyRootFilesystem, false) || !ptr.Deref(security.RunAsNonRoot, false) || ptr.Deref(security.AllowPrivilegeEscalation, true) || len(security.Capabilities.Drop) != 1 || security.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("clock container is not restricted: %#v", security)
	}
	for _, index := range []int{2, 3} {
		if container.Env[index].Value != "" || container.Env[index].ValueFrom == nil || container.Env[index].ValueFrom.SecretKeyRef == nil {
			t.Fatalf("RPC credential %s was not projected from a Secret", container.Env[index].Name)
		}
	}
	if deployment.OwnerReferences[0].UID != policy.UID || deployment.OwnerReferences[0].BlockOwnerDeletion != nil {
		t.Fatalf("unexpected permission-expanding owner reference: %#v", deployment.OwnerReferences)
	}
}

func TestDeploymentDefaultsToGeneratedRegtestCredentials(t *testing.T) {
	policy := validPolicy()
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	configuration := resourceConfig{Image: "clock", BitcoinService: "bitcoin-1", BitcoinRPCPort: 18443,
		Policy: policy, Network: &attacknetv1beta1.StacksNetwork{}, Scheme: scheme}
	deployment, err := configuration.deployment()
	if err != nil {
		t.Fatal(err)
	}
	if deployment.Spec.Template.Spec.Containers[0].Env[2].Value != "devnet" || deployment.Spec.Template.Spec.Containers[0].Env[3].Value != "devnet" {
		t.Fatal("generated regtest defaults must retain devnet credentials")
	}
}

func TestServiceExposesCredentialFreeMetricsAndStatusEndpoint(t *testing.T) {
	policy := validPolicy()
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	configuration := resourceConfig{Policy: policy, Network: &attacknetv1beta1.StacksNetwork{}, Scheme: scheme}
	service, err := configuration.service()
	if err != nil {
		t.Fatal(err)
	}
	if service.Spec.Type != corev1.ServiceTypeClusterIP || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Name != "metrics" || service.Spec.Ports[0].Port != clockHealthPort {
		t.Fatalf("unexpected clock Service: %#v", service.Spec)
	}
	if service.OwnerReferences[0].UID != policy.UID {
		t.Fatalf("clock Service is not policy-owned: %#v", service.OwnerReferences)
	}
}
