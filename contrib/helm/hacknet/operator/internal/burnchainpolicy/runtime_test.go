package burnchainpolicy

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

func TestCompileRuntimeUsesDeterministicBoundedFlashTarget(t *testing.T) {
	policy := validPolicy()
	policy.Spec.Paused = false
	policy.Spec.Flash = &attacknetv1beta1.BurnchainFlashRequest{ID: "flash-1", Blocks: 5}
	height := uint64(100)
	desired, err := compileRuntime(policy, nil, &burnchain.Status{BitcoinHeight: &height})
	if err != nil {
		t.Fatal(err)
	}
	if desired.policy.BurstTargetHeight != 105 || desired.policy.Mode != burnchain.ModePause {
		t.Fatalf("unexpected flash policy: %#v", desired.policy)
	}
	if desired.policy.Generation != 1 || desired.flashDone {
		t.Fatalf("unexpected flash generation state: %#v", desired)
	}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		annotationRuntimeGen: "1", annotationFlashID: "flash-1",
	}}, Data: map[string]string{policyKey: desired.encoded}}
	height = 103
	repeated, err := compileRuntime(policy, configMap, &burnchain.Status{BitcoinHeight: &height})
	if err != nil {
		t.Fatal(err)
	}
	if repeated.policy.BurstTargetHeight != 105 || repeated.policy.Generation != 1 {
		t.Fatalf("repeated reconcile changed the flash target: %#v", repeated.policy)
	}
	height = 105
	complete, err := compileRuntime(policy, configMap, &burnchain.Status{BitcoinHeight: &height})
	if err != nil {
		t.Fatal(err)
	}
	if !complete.flashDone {
		t.Fatal("expected the exact target height to complete the flash")
	}
}

func TestCompileRuntimeRestoresCadenceAfterAppliedFlash(t *testing.T) {
	policy := validPolicy()
	policy.Spec.Flash = &attacknetv1beta1.BurnchainFlashRequest{ID: "flash-1", Blocks: 3}
	policy.Status.AppliedFlashID = "flash-1"
	desired, err := compileRuntime(policy, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if desired.flashID != "" || desired.policy.Mode != burnchain.ModeRun || desired.policy.IntervalSeconds != 60 {
		t.Fatalf("flash was not restored to steady state: %#v", desired)
	}
}

func TestValidatePolicyRequiresCompleteCredentialsAndValidDestinationSelection(t *testing.T) {
	policy := validPolicy()
	policy.Spec.RPC.UsernameSecretRef = &attacknetv1beta1.SecretKeyReference{Name: "bitcoin-auth", Key: "rpc.user"}
	if err := validatePolicy(policy); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("expected incomplete credential failure, got %v", err)
	}
	policy.Spec.RPC.PasswordSecretRef = &attacknetv1beta1.SecretKeyReference{Name: "bitcoin-auth", Key: "rpc-password"}
	if err := validatePolicy(policy); err != nil {
		t.Fatalf("valid Secret credential pair rejected: %v", err)
	}
	policy.Spec.DestinationSelection = attacknetv1beta1.BurnchainDestinationFixed
	policy.Spec.FixedDestinationIndex = 2
	if err := validatePolicy(policy); err == nil || !strings.Contains(err.Error(), "outside destinations") {
		t.Fatalf("expected fixed-index failure, got %v", err)
	}
}

func validPolicy() *attacknetv1beta1.BurnchainPolicy {
	return &attacknetv1beta1.BurnchainPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cadence", Namespace: "test", UID: types.UID("policy-uid"), Generation: 1},
		Spec: attacknetv1beta1.BurnchainPolicySpec{
			NetworkRef: "network", BitcoinNodeRef: "bitcoin-1", BootstrapHeight: 101,
			Cadence: metav1.Duration{Duration: time.Minute},
			Destinations: []attacknetv1beta1.BurnchainDestinationSpec{
				{WalletName: "miner-1", Address: "bcrt1qexampleone"},
				{WalletName: "miner-2", Address: "bcrt1qexampletwo"},
			},
			DestinationSelection: attacknetv1beta1.BurnchainDestinationRoundRobin,
		},
	}
}
