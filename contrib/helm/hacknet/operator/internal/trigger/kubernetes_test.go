package trigger

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestReadBurnchainHeightRequiresFreshIdentityBoundPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid")},
		Spec: attacknetv1beta1.StacksNetworkSpec{Burnchain: attacknetv1beta1.BurnchainTopologySpec{
			PolicyRef: corev1.LocalObjectReference{Name: "clock"},
		}},
	}
	policy := &attacknetv1beta1.BurnchainPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "clock", Namespace: "test", UID: types.UID("clock-uid"), Generation: 3, ResourceVersion: "7"},
		Status: attacknetv1beta1.BurnchainPolicyStatus{
			Phase: "Ready", ObservedGeneration: 3, AdmittedNetworkUID: "network-uid",
			ObservedHeight: 412, LastSuccessAt: &now,
		},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(network, policy).Build()
	observed, err := ReadBurnchainHeight(t.Context(), reader, "test", network)
	if err != nil {
		t.Fatal(err)
	}
	if observed == nil || observed.Height != 412 || !observed.Source.Trusted || observed.Source.UID != "clock-uid" {
		t.Fatalf("unexpected observation: %#v", observed)
	}

	policy.Status.AdmittedNetworkUID = "replacement"
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	observed, err = ReadBurnchainHeight(t.Context(), reader, "test", network)
	if err != nil || observed != nil {
		t.Fatalf("mismatched policy produced observation %#v, err %v", observed, err)
	}
}
