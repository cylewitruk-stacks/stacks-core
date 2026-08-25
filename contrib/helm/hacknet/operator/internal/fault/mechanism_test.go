package fault

import (
	"testing"
)

func TestMechanismRegistryIsCompleteAndRoundTrips(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"pod": "PodChaos", "network": "NetworkChaos", "dns": "DNSChaos",
		"io": "IOChaos", "time": "TimeChaos", "io-pressure": "IOPressurePod",
		"clock-skew": "ClockSkewPolicy",
	}
	definitions := registeredMechanisms()
	if len(definitions) != len(want) {
		t.Fatalf("registered %d mechanisms, want %d", len(definitions), len(want))
	}
	for _, definition := range definitions {
		if want[definition.FaultType] != definition.MutationKind {
			t.Fatalf("unexpected registration %s -> %s", definition.FaultType, definition.MutationKind)
		}
		byKind, err := mechanismForMutationKind(definition.MutationKind)
		if err != nil || byKind.FaultType != definition.FaultType {
			t.Fatalf("mutation kind %s does not round-trip: %#v, %v", definition.MutationKind, byKind, err)
		}
		if definition.EffectKind == "pod" && definition.ProbeKind != "" {
			t.Fatalf("pod mechanism unexpectedly declares an active probe")
		}
		delete(want, definition.FaultType)
	}
	if len(want) != 0 {
		t.Fatalf("mechanisms were not registered: %v", want)
	}
}

func TestMechanismRegistryRejectsIncompleteAndDuplicateDefinitions(t *testing.T) {
	t.Parallel()
	valid := mustMechanismForType("pod")
	tests := []struct {
		name        string
		definitions []mechanism
	}{
		{name: "incomplete", definitions: []mechanism{{FaultType: "missing"}}},
		{name: "duplicate type", definitions: []mechanism{valid, valid}},
		{name: "duplicate kind", definitions: []mechanism{valid, {
			FaultType: "other", MutationKind: valid.MutationKind, EffectKind: "pod",
			Backend: chaosMeshBackend, Capability: noCapability, Parameters: podParameterValidator,
		}}},
		{name: "unknown backend", definitions: []mechanism{{
			FaultType: "other", MutationKind: "OtherChaos", EffectKind: "pod",
			Backend: "other", Capability: noCapability, Parameters: podParameterValidator,
		}}},
		{name: "unknown capability", definitions: []mechanism{{
			FaultType: "other", MutationKind: "OtherChaos", EffectKind: "pod",
			Backend: chaosMeshBackend, Capability: "other", Parameters: podParameterValidator,
		}}},
		{name: "unknown effect", definitions: []mechanism{{
			FaultType: "other", MutationKind: "OtherChaos", EffectKind: "other",
			Backend: chaosMeshBackend, Capability: noCapability, Parameters: podParameterValidator,
		}}},
		{name: "unknown probe", definitions: []mechanism{{
			FaultType: "other", MutationKind: "OtherChaos", ProbeKind: "other", EffectKind: "network",
			Backend: chaosMeshBackend, Capability: noCapability, Parameters: networkParameterValidator,
		}}},
		{name: "active effect without probe", definitions: []mechanism{{
			FaultType: "other", MutationKind: "OtherChaos", EffectKind: "network",
			Backend: chaosMeshBackend, Capability: noCapability, Parameters: networkParameterValidator,
		}}},
		{name: "pod effect with probe", definitions: []mechanism{{
			FaultType: "other", MutationKind: "OtherChaos", ProbeKind: "network", EffectKind: "pod",
			Backend: chaosMeshBackend, Capability: noCapability, Parameters: podParameterValidator,
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deferred := false
			func() {
				defer func() { deferred = recover() != nil }()
				mustMechanismRegistry(test.definitions)
			}()
			if !deferred {
				t.Fatal("invalid registry did not panic")
			}
		})
	}
}
