package fault

import (
	"strings"
	"testing"
	"time"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestParameterValidationRejectsUnboundedOrAmbiguousFaults(t *testing.T) {
	manifest := compilerManifest()
	tests := []struct {
		name, kind, action string
		parameters         map[string]any
		safety             attacknetv1alpha1.FaultSafety
	}{
		{name: "partition without boundary", kind: "network", action: "partition", parameters: map[string]any{}},
		{name: "two traffic boundaries", kind: "network", action: "partition", parameters: map[string]any{"peerTarget": map[string]any{"actors": []any{"miner-1"}}, "externalTargets": []any{"10.0.0.0/8"}}, safety: attacknetv1alpha1.FaultSafety{AllowUnenrolledTargets: true}},
		{name: "raw target without opt in", kind: "network", action: "partition", parameters: map[string]any{"externalTargets": []any{"10.0.0.0/8"}}},
		{name: "both without peer boundary", kind: "network", action: "delay", parameters: map[string]any{"direction": "both", "delay": map[string]any{"latency": "100ms"}}},
		{name: "from without peer boundary", kind: "network", action: "loss", parameters: map[string]any{"direction": "from", "loss": map[string]any{"loss": "10"}}},
		{name: "empty netem", kind: "network", action: "netem", parameters: map[string]any{}},
		{name: "non-string peer mode", kind: "network", action: "partition", parameters: map[string]any{"peerTarget": map[string]any{"actors": []any{"miner-1"}, "mode": float64(1)}}},
		{name: "unknown pod execution input", kind: "pod", action: "pod-kill", parameters: map[string]any{"command": []any{"sh"}}},
		{name: "relative IO volume", kind: "io", action: "latency", parameters: map[string]any{"volumePath": "data", "delay": "10ms"}},
		{name: "negative IO latency", kind: "io", action: "latency", parameters: map[string]any{"volumePath": "/data", "delay": "-10ms"}},
		{name: "fractional IO latency", kind: "io", action: "latency", parameters: map[string]any{"volumePath": "/data", "delay": "1.5s"}},
		{name: "unsupported IO latency unit", kind: "io", action: "latency", parameters: map[string]any{"volumePath": "/data", "delay": "10us"}},
		{name: "negative network latency", kind: "network", action: "delay", parameters: map[string]any{"delay": map[string]any{"latency": "-10ms"}}},
		{name: "unsupported DNS field", kind: "dns", action: "error", parameters: map[string]any{"patterns": []any{"*.invalid"}, "server": "1.1.1.1"}},
		{name: "oversized application clock offset", kind: "clock-skew", parameters: map[string]any{"timeOffset": "+25h"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateParameters(test.kind, test.action, test.parameters, test.safety, 30*time.Second, manifest); err == nil {
				t.Fatal("unsafe parameters were accepted")
			}
		})
	}
}

func TestNetworkPeerTargetCompilesToEnrolledSelector(t *testing.T) {
	parameters := map[string]any{"peerTarget": map[string]any{"actors": []any{"miner-1"}}, "delay": map[string]any{"latency": "100ms", "jitter": "10ms"}}
	result, err := validateParameters("network", "delay", parameters, attacknetv1alpha1.FaultSafety{}, 30*time.Second, compilerManifest())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.PeerSelectedActors, ",") != "miner-1" || result.Parameters["peerTarget"] != nil || result.Parameters["target"] == nil {
		t.Fatalf("peer target did not compile to an enrolled selector: %#v", result)
	}
}
