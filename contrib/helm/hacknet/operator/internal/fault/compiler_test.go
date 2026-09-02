package fault

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func compilerManifest() Manifest {
	index1, index2 := int32(1), int32(2)
	weight1, weight2 := 80.0, 20.0
	return Manifest{Network: "attacknet", Namespace: "test", Actors: []ManifestActor{{Name: "miner-1", Role: "miner"}, {Name: "signer-1", Role: "signer", SignerIndex: &index1, SignerWeight: &weight1}, {Name: "signer-2", Role: "signer", SignerIndex: &index2, SignerWeight: &weight2}}}
}

func compilerCampaign() *attacknetv1alpha1.FaultCampaign {
	return &attacknetv1alpha1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{Name: "partition-signers", Namespace: "test"}, Spec: attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "attacknet", Target: attacknetv1alpha1.FaultTarget{Actors: []string{"signer-2"}}, Fault: attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition", Mode: "one", Duration: "30s", Parameters: apixv1.JSON{Raw: []byte(`{"externalTargets":["10.0.0.0/8"]}`)}}, Safety: attacknetv1alpha1.FaultSafety{MaxUnavailableSignerPercent: 30, MaxUnavailableMinerPercent: 50, AllowUnenrolledTargets: true}}}
}

func TestCompileBuildsBoundedChaosResource(t *testing.T) {
	compiled, err := Compile(compilerCampaign(), compilerManifest())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Resource.GetKind() != "NetworkChaos" || compiled.Resource.GetAPIVersion() != "chaos-mesh.org/v1alpha1" {
		t.Fatalf("unexpected resource: %#v", compiled.Resource.Object)
	}
	if compiled.Evidence.SignerImpact.Percent != 20 {
		t.Fatalf("unexpected signer impact: %#v", compiled.Evidence.SignerImpact)
	}
	if got, _, _ := unstructuredString(compiled.Resource.Object, "spec", "selector", "labelSelectors", NetworkLabel); got != "attacknet" {
		t.Fatalf("network selector = %q", got)
	}
}

func TestCompileRejectsSignerQuorumAndBurnchainRisk(t *testing.T) {
	campaign := compilerCampaign()
	campaign.Spec.Target.Actors = []string{"signer-1"}
	if _, err := Compile(campaign, compilerManifest()); err == nil {
		t.Fatal("unsafe signer fault compiled")
	}
	campaign.Spec.Target = attacknetv1alpha1.FaultTarget{Roles: []string{"burnchain"}}
	manifest := compilerManifest()
	manifest.Actors = append(manifest.Actors, ManifestActor{Name: "bitcoin", Role: "burnchain"})
	if _, err := Compile(campaign, manifest); err == nil {
		t.Fatal("burnchain fault compiled without opt-in")
	}
}

func TestCompileRejectsUntrustedIOPressureExecutionInputs(t *testing.T) {
	campaign := compilerCampaign()
	campaign.Spec.Target.Actors = []string{"miner-1"}
	campaign.Spec.Fault = attacknetv1alpha1.FaultSpec{Type: "io-pressure", Action: "disk-pressure", Mode: "one", Duration: "30s", Parameters: apixv1.JSON{Raw: []byte(`{"containerNames":["actor"],"severity":"low","workers":1,"bytesMiB":32,"writeSizeKiB":256,"minimumLatencyMultiplier":1.5,"minimumAddedLatencyMs":2,"command":["sh"]}`)}}
	if _, err := Compile(campaign, compilerManifest()); err == nil {
		t.Fatal("untrusted command field was accepted")
	}
}

func TestCompileCoversEverySupportedFaultContract(t *testing.T) {
	tests := []struct {
		name, faultType, action, parameters, expectedKind string
	}{
		{name: "pod", faultType: "pod", action: "pod-kill", parameters: `{}`, expectedKind: "PodChaos"},
		{name: "network", faultType: "network", action: "delay", parameters: `{"peerTarget":{"actors":["miner-1"]},"delay":{"latency":"100ms"}}`, expectedKind: "NetworkChaos"},
		{name: "dns", faultType: "dns", action: "error", parameters: `{"patterns":["example.invalid"]}`, expectedKind: "DNSChaos"},
		{name: "io", faultType: "io", action: "latency", parameters: `{"volumePath":"/data","delay":"10ms"}`, expectedKind: "IOChaos"},
		{name: "time", faultType: "time", parameters: `{"timeOffset":"+1m","clockIds":["CLOCK_REALTIME"]}`, expectedKind: "TimeChaos"},
		{name: "io pressure", faultType: "io-pressure", action: "disk-pressure", parameters: `{"containerNames":["actor"],"severity":"low","workers":1,"bytesMiB":32,"writeSizeKiB":256,"minimumLatencyMultiplier":1.5,"minimumAddedLatencyMs":2}`, expectedKind: "IOPressurePod"},
		{name: "application clock", faultType: "clock-skew", parameters: `{"timeOffset":"+1m","clockIds":["CLOCK_REALTIME"],"containerNames":["actor"]}`, expectedKind: "ClockSkewPolicy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			campaign := compilerCampaign()
			campaign.Spec.Fault = attacknetv1alpha1.FaultSpec{
				Type:       test.faultType,
				Action:     test.action,
				Mode:       "one",
				Duration:   "30s",
				Parameters: apixv1.JSON{Raw: []byte(test.parameters)},
			}
			compiled, err := Compile(campaign, compilerManifest())
			if err != nil {
				t.Fatal(err)
			}
			if compiled.Resource.GetKind() != test.expectedKind {
				t.Fatalf("kind = %s, want %s; resource=%s", compiled.Resource.GetKind(), test.expectedKind, fmt.Sprint(compiled.Resource.Object))
			}
		})
	}
}

func TestCompileRejectsDurationOutsideEstablishedGrammar(t *testing.T) {
	for _, duration := range []string{"1.5s", "100us", "-1s", "0s"} {
		campaign := compilerCampaign()
		campaign.Spec.Fault.Duration = duration
		if _, err := Compile(campaign, compilerManifest()); err == nil {
			t.Fatalf("accepted fault duration %q outside the integer ms/s/m/h contract", duration)
		}
	}
}

func TestResolveTargetsRequiresImmutableRuntimeImageIdentity(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "attacknet-miner-1-0", UID: types.UID("pod-uid"),
			Labels: map[string]string{NetworkLabel: "attacknet", ActorLabel: "miner-1", RoleLabel: "miner"},
		},
		Spec: corev1.PodSpec{
			NodeName:   "worker",
			Containers: []corev1.Container{{Name: "actor", Image: "example.invalid/stacks:dev"}},
		},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			PodIP:             "10.0.0.1",
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "actor", Ready: true}},
		},
	}
	manifest := Manifest{Network: "attacknet", Namespace: "test", Actors: []ManifestActor{{Name: "miner-1", Role: "miner"}}}
	if _, err := ResolveTargets(manifest, []string{"miner-1"}, []corev1.Pod{pod}); err == nil {
		t.Fatal("Ready Pod without an immutable runtime image ID was admitted")
	}
	pod.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("a", 64)
	if _, err := ResolveTargets(manifest, []string{"miner-1"}, []corev1.Pod{pod}); err != nil {
		t.Fatalf("immutable runtime image ID was rejected: %v", err)
	}
}

func unstructuredString(value map[string]any, fields ...string) (string, bool, error) {
	current := any(value)
	for _, field := range fields {
		object, ok := current.(map[string]any)
		if !ok {
			return "", false, nil
		}
		current, ok = object[field]
		if !ok {
			return "", false, nil
		}
	}
	result, ok := current.(string)
	return result, ok, nil
}
