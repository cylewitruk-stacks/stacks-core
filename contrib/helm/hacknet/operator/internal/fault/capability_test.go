package fault

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func clockCapabilityFixture() (*attacknetv1alpha1.FaultCampaign, attacknetv1alpha1.ResolvedTarget, corev1.Pod, *corev1.ConfigMap) {
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "clock", Namespace: "test"},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network",
			Fault:      attacknetv1alpha1.FaultSpec{Type: "clock-skew"},
		},
	}
	target := attacknetv1alpha1.ResolvedTarget{Actor: "follower-1", PodUID: "pod-uid"}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "network-follower-1-0", Namespace: "test", UID: types.UID(target.PodUID)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "actor",
				Env: []corev1.EnvVar{
					{Name: "LD_PRELOAD", Value: "/usr/lib/stacks-attacknet/libfaketime.so.1"},
					{Name: "FAKETIME_TIMESTAMP_FILE", Value: "/run/attacknet-clock/follower-1"},
					{Name: "FAKETIME_DONT_FAKE_MONOTONIC", Value: "1"},
					{Name: "FAKETIME_NO_CACHE", Value: "1"},
				},
				VolumeMounts: []corev1.VolumeMount{{Name: "clock-policy", MountPath: "/run/attacknet-clock"}},
			}},
			Volumes: []corev1.Volume{{
				Name: "clock-policy",
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "network-clock-policy"},
				}},
			}},
		},
	}
	policy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-clock-policy", Namespace: "test",
			Labels: map[string]string{NetworkLabel: "network", "testing.stacks.org/clock-policy": "true"},
		},
		Data: map[string]string{"follower-1": clockPolicyZero, "miner-1": clockPolicyZero},
	}
	return campaign, target, pod, policy
}

func TestClockPodCapabilityRequiresThePolicyConfigMapVolume(t *testing.T) {
	campaign, target, pod, _ := clockCapabilityFixture()
	if supported, reason := clockPodCapability(campaign, target, []corev1.Pod{pod}); !supported {
		t.Fatalf("valid clock contract rejected: %s", reason)
	}
	pod.Spec.Volumes[0].ConfigMap.Name = "unrelated-policy"
	if supported, _ := clockPodCapability(campaign, target, []corev1.Pod{pod}); supported {
		t.Fatal("same-path mount backed by an unrelated ConfigMap was accepted")
	}
}

func TestClockPolicyCapabilityRequiresEveryActorAtZero(t *testing.T) {
	campaign, target, _, policy := clockCapabilityFixture()
	if supported, reason := clockPolicyCapability(campaign, target, policy); !supported {
		t.Fatalf("clean policy rejected: %s", reason)
	}
	policy.Data["miner-1"] = "+1s\n"
	if supported, _ := clockPolicyCapability(campaign, target, policy); supported {
		t.Fatal("non-target actor with a non-zero policy was accepted")
	}
}

func TestClockCapabilityEvidenceRejectsAContaminatedSharedPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign, target, pod, policy := clockCapabilityFixture()
	policy.Data["miner-1"] = "+1s\n"
	reconciler := &Reconciler{
		APIReader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Now:       func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	observations := reconciler.capabilityEvidence(t.Context(), campaign, []corev1.Pod{pod}, []attacknetv1alpha1.ResolvedTarget{target})
	if len(observations) != 1 || observations[0].Supported {
		t.Fatalf("contaminated policy produced capability evidence: %#v", observations)
	}
	if observations[0].Reason != "application clock policy is not globally at zero offset" {
		t.Fatalf("unexpected diagnostic: %q", observations[0].Reason)
	}
}
