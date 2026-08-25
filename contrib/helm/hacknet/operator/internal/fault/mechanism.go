package fault

import (
	"fmt"
	"sort"
	"time"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

// mutationBackend identifies the Kubernetes mutation lifecycle used by a fault
// mechanism. Multiple fault types may share one backend.
type mutationBackend string

const (
	chaosMeshBackend   mutationBackend = "chaos-mesh"
	clockPolicyBackend mutationBackend = "clock-policy"
	ioPressureBackend  mutationBackend = "io-pressure"
)

// capabilityKind identifies the admission-time platform contract for a fault.
type capabilityKind string

const (
	noCapability              capabilityKind = "none"
	ioChaosCapability         capabilityKind = "io-chaos"
	timeChaosCapability       capabilityKind = "time-chaos"
	clockPolicyCapabilityKind capabilityKind = "clock-policy"
	ioPressureCapability      capabilityKind = "io-pressure"
)

type parameterValidator func(string, map[string]any, attacknetv1alpha1.FaultSafety, time.Duration, Manifest) (parameterResult, error)

// mechanism is the closed, validated extension point for one supported fault
// type. Generic campaign safety and lifecycle remain in the reconciler.
type mechanism struct {
	FaultType      string
	MutationKind   string
	ProbeKind      string
	EffectKind     string
	Backend        mutationBackend
	Capability     capabilityKind
	AllowedActions map[string]bool
	Parameters     parameterValidator
}

var mechanismRegistry = mustMechanismRegistry([]mechanism{
	{FaultType: "pod", MutationKind: "PodChaos", EffectKind: "pod", Backend: chaosMeshBackend, Capability: noCapability, AllowedActions: stringSet("pod-kill", "pod-failure", "container-kill"), Parameters: podParameterValidator},
	{FaultType: "network", MutationKind: "NetworkChaos", ProbeKind: "network", EffectKind: "network", Backend: chaosMeshBackend, Capability: noCapability, AllowedActions: stringSet("netem", "delay", "loss", "duplicate", "corrupt", "partition", "bandwidth"), Parameters: networkParameterValidator},
	{FaultType: "dns", MutationKind: "DNSChaos", ProbeKind: "dns", EffectKind: "dns", Backend: chaosMeshBackend, Capability: noCapability, AllowedActions: stringSet("error", "random"), Parameters: dnsParameterValidator},
	{FaultType: "io", MutationKind: "IOChaos", ProbeKind: "io", EffectKind: "io", Backend: chaosMeshBackend, Capability: ioChaosCapability, AllowedActions: stringSet("latency", "fault", "attrOverride", "mistake"), Parameters: ioParameterValidator},
	{FaultType: "time", MutationKind: "TimeChaos", ProbeKind: "clock", EffectKind: "clock", Backend: chaosMeshBackend, Capability: timeChaosCapability, Parameters: timeParameterValidator},
	{FaultType: "io-pressure", MutationKind: "IOPressurePod", ProbeKind: "io", EffectKind: "io-pressure", Backend: ioPressureBackend, Capability: ioPressureCapability, AllowedActions: stringSet("disk-pressure"), Parameters: ioPressureParameterValidator},
	{FaultType: "clock-skew", MutationKind: "ClockSkewPolicy", ProbeKind: "clock", EffectKind: "clock", Backend: clockPolicyBackend, Capability: clockPolicyCapabilityKind, Parameters: clockSkewParameterValidator},
})

func mustMechanismRegistry(definitions []mechanism) map[string]mechanism {
	registry := make(map[string]mechanism, len(definitions))
	kinds := make(map[string]string, len(definitions))
	for _, definition := range definitions {
		if definition.FaultType == "" || definition.MutationKind == "" || definition.EffectKind == "" || definition.Backend == "" || definition.Capability == "" || definition.Parameters == nil {
			panic("fault mechanism registration is incomplete")
		}
		if _, exists := registry[definition.FaultType]; exists {
			panic("duplicate fault mechanism type " + definition.FaultType)
		}
		if existing, exists := kinds[definition.MutationKind]; exists {
			panic(fmt.Sprintf("mutation kind %s is registered by both %s and %s", definition.MutationKind, existing, definition.FaultType))
		}
		if !validMutationBackend(definition.Backend) {
			panic("unsupported mutation backend " + definition.Backend)
		}
		if !validCapabilityKind(definition.Capability) {
			panic("unsupported capability kind " + definition.Capability)
		}
		if !validEffectKind(definition.EffectKind) {
			panic("unsupported effect kind " + definition.EffectKind)
		}
		if !validProbeKind(definition.ProbeKind) {
			panic("unsupported probe kind " + definition.ProbeKind)
		}
		if definition.EffectKind == "pod" && definition.ProbeKind != "" {
			panic("pod fault mechanism must not declare an active probe")
		}
		if definition.EffectKind != "pod" && definition.ProbeKind == "" {
			panic("non-pod fault mechanism must declare an active probe")
		}
		registry[definition.FaultType] = definition
		kinds[definition.MutationKind] = definition.FaultType
	}
	return registry
}

func validMutationBackend(backend mutationBackend) bool {
	switch backend {
	case chaosMeshBackend, clockPolicyBackend, ioPressureBackend:
		return true
	default:
		return false
	}
}

func validCapabilityKind(kind capabilityKind) bool {
	switch kind {
	case noCapability, ioChaosCapability, timeChaosCapability, clockPolicyCapabilityKind, ioPressureCapability:
		return true
	default:
		return false
	}
}

func validEffectKind(kind string) bool {
	switch kind {
	case "pod", "network", "dns", "io", "io-pressure", "clock":
		return true
	default:
		return false
	}
}

func validProbeKind(kind string) bool {
	switch kind {
	case "", "network", "dns", "io", "clock":
		return true
	default:
		return false
	}
}

func mechanismForType(faultType string) (mechanism, error) {
	definition, ok := mechanismRegistry[faultType]
	if !ok {
		return mechanism{}, fmt.Errorf("unsupported fault type %s", faultType)
	}
	return definition, nil
}

func mustMechanismForType(faultType string) mechanism {
	definition, err := mechanismForType(faultType)
	if err != nil {
		panic(err)
	}
	return definition
}

func mechanismForMutationKind(kind string) (mechanism, error) {
	for _, definition := range mechanismRegistry {
		if definition.MutationKind == kind {
			return definition, nil
		}
	}
	return mechanism{}, fmt.Errorf("unsupported mutation kind %s", kind)
}

func registeredMechanisms() []mechanism {
	result := make([]mechanism, 0, len(mechanismRegistry))
	for _, definition := range mechanismRegistry {
		result = append(result, definition)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FaultType < result[j].FaultType })
	return result
}
