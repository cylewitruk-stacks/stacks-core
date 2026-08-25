package fault

import (
	"encoding/json"
	"testing"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestNetworkEffectRequiresObservedDataPlaneDeltaAndRecovery(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{Name: "partition"}, Spec: attacknetv1alpha1.FaultCampaignSpec{Fault: attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition", Mode: "one"}}}
	compiled := Compiled{Evidence: Evidence{Parameters: map[string]any{}, PeerSelectedActors: []string{"miner-1"}}}
	targets := []attacknetv1alpha1.ResolvedTarget{{Actor: "signer-1", PodUID: "pod-1"}}
	observation := func(successes float64) map[string]any {
		return map[string]any{"actor": "signer-1", "status": "ok", "probe": "network", "probeName": "peer", "peerActor": "miner-1", "attempts": float64(4), "successes": successes, "latencyMsP95": float64(10), "protocolErrors": float64(0)}
	}
	artifacts := map[string]string{
		"beforeJson": phaseJSON(t, "before", observation(4)),
		"duringJson": phaseJSON(t, "during", observation(0)),
		"afterJson":  phaseJSON(t, "after", observation(4)),
	}
	report, err := evaluateProbeEvidence(campaign, compiled, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != "Proven" || report.RecoveryVerdict != "Proven" {
		t.Fatalf("effect and recovery were not proven: %#v", report)
	}
	artifacts["duringJson"] = phaseJSON(t, "during", observation(4))
	report, err = evaluateProbeEvidence(campaign, compiled, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict == "Proven" {
		t.Fatal("Chaos bookkeeping without a data-plane delta proved an effect")
	}
}

func TestClockInjectionRequiresTheRequestedProcessClockOffset(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{Spec: attacknetv1alpha1.FaultCampaignSpec{Fault: attacknetv1alpha1.FaultSpec{
		Type: "clock-skew", Mode: "all", Parameters: apixv1.JSON{Raw: []byte(`{"timeOffset":"-30s"}`)},
	}}}
	targets := []attacknetv1alpha1.ResolvedTarget{{Actor: "follower-1"}}
	clock := func(actor string, control bool, wall, monotonic float64) map[string]any {
		return map[string]any{"actor": actor, "status": "ok", "probe": "clock", "control": control, "wallEpochSeconds": wall, "monotonicSeconds": monotonic}
	}
	artifacts := map[string]string{
		"beforeJson": phaseJSON(t, "before", clock("follower-1", false, 1000, 100), clock("miner-1", true, 1000, 100)),
		"duringJson": phaseJSON(t, "during", clock("follower-1", false, 980, 110), clock("miner-1", true, 1010, 110)),
	}
	proven, err := clockInjectionProven(campaign, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if !proven {
		t.Fatal("requested process-clock offset was not accepted")
	}
	artifacts["duringJson"] = phaseJSON(t, "during", clock("follower-1", false, 1010, 110), clock("miner-1", true, 1010, 110))
	proven, err = clockInjectionProven(campaign, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if proven {
		t.Fatal("ConfigMap bookkeeping without a process-clock shift proved injection")
	}
}

func TestBandwidthEffectRequiresThroughputReductionAndRecovery(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{Spec: attacknetv1alpha1.FaultCampaignSpec{Fault: attacknetv1alpha1.FaultSpec{Type: "network", Action: "bandwidth", Mode: "one"}}}
	compiled := Compiled{Evidence: Evidence{Parameters: map[string]any{
		"bandwidth": map[string]any{"rate": "1mbps"},
	}, PeerSelectedActors: []string{"miner-1"}}}
	targets := []attacknetv1alpha1.ResolvedTarget{{Actor: "signer-1"}}
	observation := func(throughput float64) map[string]any {
		return map[string]any{
			"actor": "signer-1", "status": "ok", "probe": "network", "probeName": "peer",
			"peerActor": "miner-1", "attempts": float64(3), "successes": float64(3),
			"latencyMsP95": float64(10), "protocolErrors": float64(0),
			"throughputBytesPerSecond": throughput,
		}
	}
	artifacts := map[string]string{
		"beforeJson": phaseJSON(t, "before", observation(1_000_000)),
		"duringJson": phaseJSON(t, "during", observation(120_000)),
		"afterJson":  phaseJSON(t, "after", observation(900_000)),
	}
	report, err := evaluateProbeEvidence(campaign, compiled, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != "Proven" || report.RecoveryVerdict != "Proven" {
		t.Fatalf("bandwidth effect and recovery were not proven: %#v", report)
	}
	artifacts["duringJson"] = phaseJSON(t, "during", observation(900_000))
	report, err = evaluateProbeEvidence(campaign, compiled, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict == "Proven" {
		t.Fatal("bandwidth bookkeeping without a throughput reduction proved an effect")
	}
}

func TestIOEffectRequiresCompiledPathAndMethod(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{Spec: attacknetv1alpha1.FaultCampaignSpec{Fault: attacknetv1alpha1.FaultSpec{Type: "io", Action: "latency", Mode: "one"}}}
	compiled := Compiled{Evidence: Evidence{Parameters: map[string]any{
		"volumePath": "/data", "path": "/data/db-*", "methods": []any{"READ"}, "delay": "100ms",
	}}}
	targets := []attacknetv1alpha1.ResolvedTarget{{Actor: "node", PodUID: "pod"}}
	observation := func(path, operation string, latency float64) map[string]any {
		return map[string]any{
			"actor": "node", "status": "ok", "probe": "io", "probeName": "operation",
			"path": path, "operation": operation, "attempts": float64(5), "successes": float64(5),
			"latencyMsP95": latency, "errorCounts": map[string]any{},
		}
	}
	for _, invalid := range []map[string]any{
		observation("/data/other", "READ", 100),
		observation("/data/db-main", "FSYNC", 100),
	} {
		artifacts := map[string]string{
			"beforeJson": phaseJSON(t, "before", observation("/data/db-main", "READ", 5)),
			"duringJson": phaseJSON(t, "during", invalid),
			"afterJson":  phaseJSON(t, "after", observation("/data/db-main", "READ", 5)),
		}
		report, err := evaluateProbeEvidence(campaign, compiled, targets, artifacts)
		if err != nil {
			t.Fatal(err)
		}
		if report.Verdict == "Proven" {
			t.Fatalf("unrelated I/O operation proved the compiled effect: %#v", invalid)
		}
	}
}

func TestProbeEvidenceRejectsMalformedAuthorityAndDuplicateKeys(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{Spec: attacknetv1alpha1.FaultCampaignSpec{Fault: attacknetv1alpha1.FaultSpec{Type: "network", Action: "partition", Mode: "one"}}}
	targets := []attacknetv1alpha1.ResolvedTarget{{Actor: "signer-1"}}
	observation := map[string]any{
		"actor": "signer-1", "status": "ok", "probe": "network", "probeName": "peer",
		"peerActor": "miner-1", "attempts": float64(3), "successes": float64(3),
		"latencyMsP95": float64(10), "protocolErrors": float64(0),
	}
	before := phaseJSON(t, "before", cloneObservation(t, observation), cloneObservation(t, observation))
	artifacts := map[string]string{
		"beforeJson": before,
		"duringJson": phaseJSON(t, "during", cloneObservation(t, observation)),
		"afterJson":  phaseJSON(t, "after", cloneObservation(t, observation)),
	}
	if _, err := evaluateProbeEvidence(campaign, Compiled{}, targets, artifacts); err == nil {
		t.Fatal("duplicate observation keys were accepted")
	}

	phase := decodePhaseMap(t, phaseJSON(t, "before", cloneObservation(t, observation)))
	phase["source"].(map[string]any)["trust"] = "actor-supplied"
	encoded, err := json.Marshal(phase)
	if err != nil {
		t.Fatal(err)
	}
	artifacts["beforeJson"] = string(encoded)
	if _, err := evaluateProbeEvidence(campaign, Compiled{}, targets, artifacts); err == nil {
		t.Fatal("actor-supplied probe authority was accepted")
	}
}

func TestClockEvidenceRequiresStableIndependentControls(t *testing.T) {
	campaign := &attacknetv1alpha1.FaultCampaign{Spec: attacknetv1alpha1.FaultCampaignSpec{Fault: attacknetv1alpha1.FaultSpec{
		Type: "clock-skew", Mode: "all", Parameters: apixv1.JSON{Raw: []byte(`{"timeOffset":"-30s"}`)},
	}}}
	targets := []attacknetv1alpha1.ResolvedTarget{{Actor: "follower-1"}}
	clock := func(actor string, control bool, wall, monotonic float64) map[string]any {
		return map[string]any{"actor": actor, "status": "ok", "probe": "clock", "control": control, "wallEpochSeconds": wall, "monotonicSeconds": monotonic}
	}
	artifacts := map[string]string{
		"beforeJson": phaseJSON(t, "before", clock("follower-1", false, 1000, 100), clock("miner-1", true, 1000, 100)),
		"duringJson": phaseJSON(t, "during", clock("follower-1", false, 980, 110), clock("miner-1", false, 1010, 110)),
		"afterJson":  phaseJSON(t, "after", clock("follower-1", false, 1020, 120), clock("miner-1", true, 1020, 120)),
	}
	report, err := evaluateProbeEvidence(campaign, Compiled{}, targets, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != "Inconclusive" {
		t.Fatalf("control that lost its control designation proved an effect: %#v", report)
	}

	artifacts["duringJson"] = phaseJSON(t, "during", clock("follower-1", true, 980, 110), clock("miner-1", true, 1010, 110))
	if _, err := evaluateProbeEvidence(campaign, Compiled{}, targets, artifacts); err == nil {
		t.Fatal("selected actor marked as a clock control was accepted")
	}
}

func cloneObservation(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func decodePhaseMap(t *testing.T, value string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func phaseJSON(t *testing.T, phase string, observations ...map[string]any) string {
	t.Helper()
	probe := ""
	if len(observations) > 0 {
		probe, _ = observations[0]["probe"].(string)
	}
	authority, injectionAuthority := "active-probe", "chaos-mesh-status"
	for _, observation := range observations {
		switch probe {
		case "network":
			if _, ok := observation["latencyMsP50"]; !ok {
				observation["latencyMsP50"] = observation["latencyMsP95"]
			}
			if _, ok := observation["throughputBytesPerSecond"]; !ok {
				observation["throughputBytesPerSecond"] = nil
			}
		case "io":
			if _, ok := observation["latencyMsP50"]; !ok {
				observation["latencyMsP50"] = observation["latencyMsP95"]
			}
			if _, ok := observation["contentDigest"]; !ok {
				observation["contentDigest"] = nil
			}
			if _, ok := observation["attributesDigest"]; !ok {
				observation["attributesDigest"] = nil
			}
		case "clock":
			authority, injectionAuthority = "application-process-metric", "controller-clock-policy"
			observation["sampleWindowMs"] = float64(10)
			observation["metric"] = "stacks_node_process_wall_clock_seconds"
		}
	}
	source := map[string]any{
		"trust": "orchestrator-observed", "authority": authority, "collector": "test/v1",
	}
	if probe == "clock" {
		source["contentTrust"] = "actor-self-reported"
	}
	encoded, err := json.Marshal(map[string]any{
		"schemaVersion": faultProbeSchema,
		"phase":         phase,
		"capturedAt":    "2026-08-25T12:00:00Z",
		"source":        source,
		"injection": map[string]any{
			"allInjectedObserved": phase == "during",
			"source": map[string]any{
				"trust": "orchestrator-observed", "authority": injectionAuthority,
				"collector": "test-controller/v1",
			},
		},
		"observations": observations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
