package fault

import (
	"errors"
	"testing"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestProbeRequestPreservesCompiledTargetContract(t *testing.T) {
	network := &attacknetv1alpha1.StacksNetwork{}
	network.Name, network.Namespace = "network", "test"
	network.Spec.Actors = []attacknetv1alpha1.ActorSpec{
		{Name: "target", Role: "companion"},
		{Name: "peer-z", Role: "follower", Ports: []attacknetv1alpha1.ActorPort{{Name: "metrics"}, {Name: "p2p"}}},
		{Name: "peer-a", Role: "miner"},
	}
	target := attacknetv1alpha1.ResolvedTarget{Actor: "target"}
	campaign := &attacknetv1alpha1.FaultCampaign{}
	campaign.Name = "fault"

	request, err := probeRequest("NetworkChaos", campaign, target, network, Compiled{Evidence: Evidence{PeerSelectedActors: []string{"attacknet-prometheus"}}})
	if err != nil {
		t.Fatal(err)
	}
	if request["peer"] != "attacknet-prometheus" || request["port"] != "http" {
		t.Fatalf("harness target lost its named endpoint: %#v", request)
	}

	request, err = probeRequest("NetworkChaos", campaign, target, network, Compiled{})
	if err != nil {
		t.Fatal(err)
	}
	if request["peer"] != "peer-a" || request["port"] != "p2p" {
		t.Fatalf("network probe selection is not stable and P2P-preferring: %#v", request)
	}

	enabled := true
	network.Spec.Probe = &attacknetv1alpha1.ProbeSpec{Enabled: &enabled}
	campaign.Spec.Fault.Action = "bandwidth"
	request, err = probeRequest("NetworkChaos", campaign, target, network, Compiled{})
	if err != nil {
		t.Fatal(err)
	}
	if request["peer"] != "peer-a" || request["port"] != "probe" || request["throughputBytes"] != 65536 {
		t.Fatalf("bandwidth probe did not select a bounded enrolled probe endpoint: %#v", request)
	}
	campaign.Spec.Fault.Action = ""

	request, err = probeRequest("DNSChaos", campaign, target, network, Compiled{Evidence: Evidence{Parameters: map[string]any{
		"patterns": []any{"network-peer-z.test.svc.cluster.local"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if request["peer"] != "peer-z" {
		t.Fatalf("DNS probe did not bind a service matching the compiled pattern: %#v", request)
	}

	request, err = probeRequest("IOChaos", campaign, target, network, Compiled{Evidence: Evidence{Parameters: map[string]any{
		"methods": []any{"OPEN", "READ", "FSYNC"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if request["operation"] != "READ" {
		t.Fatalf("I/O probe ignored the compiled operation set: %#v", request)
	}
}

func TestBaselineUsabilityRejectsProbeErrorsAndUnhealthyControls(t *testing.T) {
	phase := func(observations ...map[string]any) []byte {
		return []byte(phaseJSON(t, "before", observations...))
	}
	if !baselineUsable("NetworkChaos", phase(map[string]any{
		"actor": "node", "probe": "network", "status": "ok", "probeName": "peer",
		"peerActor": "peer", "attempts": float64(5), "successes": float64(5),
		"latencyMsP95": float64(10), "protocolErrors": float64(0),
	}), []string{"node"}) {
		t.Fatal("healthy named network baseline was rejected")
	}
	if baselineUsable("NetworkChaos", phase(probeErrorObservation("node", "network", errors.New("unreachable"))), []string{"node"}) {
		t.Fatal("probe transport error was admitted as a healthy baseline")
	}
	if baselineUsable("DNSChaos", phase(map[string]any{
		"actor": "node", "probe": "dns", "status": "ok", "probeName": "dns",
		"query": "target", "controlQuery": "control", "querySucceeded": true,
		"controlSucceeded": false, "answers": []any{"127.0.0.1"},
		"controlAnswers": []any{"127.0.0.1"},
	}), []string{"node"}) {
		t.Fatal("DNS baseline without an independent control was accepted")
	}
	clock := phase(
		map[string]any{"actor": "node", "probe": "clock", "status": "ok", "control": false, "wallEpochSeconds": float64(1), "monotonicSeconds": float64(1)},
		map[string]any{"actor": "control", "probe": "clock", "status": "ok", "control": true, "wallEpochSeconds": float64(1), "monotonicSeconds": float64(1)},
	)
	if !baselineUsable("ClockSkewPolicy", clock, []string{"node"}) {
		t.Fatal("clock baseline with a distinct healthy control was rejected")
	}
}
