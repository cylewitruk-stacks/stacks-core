package fault

import (
	"context"
	"encoding/json"
	"errors"

	corev1 "k8s.io/api/core/v1"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func (r *Reconciler) captureProbePhase(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod, targets []attacknetv1alpha1.ResolvedTarget, compiled Compiled, phase string, injected bool) ([]byte, error) {
	probe := r.Probes
	if probe == nil {
		probe = HTTPProbeClient{}
	}
	observations := []any{}
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	kind := definition.MutationKind
	probeKind := definition.ProbeKind
	for _, target := range targets {
		request, err := probeRequest(kind, campaign, target, network, compiled)
		if err != nil {
			observations = append(observations, probeErrorObservation(target.Actor, probeKind, err))
			continue
		}
		response, err := probe.Probe(ctx, target, request)
		if err != nil {
			observations = append(observations, probeErrorObservation(target.Actor, probeKind, err))
			continue
		}
		observation, ok := response["observation"].(map[string]any)
		if !ok {
			observations = append(observations, probeErrorObservation(target.Actor, probeKind, errors.New("probe response omitted its observation object")))
			continue
		}
		observations = append(observations, observation)
	}
	if definition.EffectKind == "clock" {
		control, err := controlTarget(network, targets, pods)
		if err != nil {
			observations = append(observations, probeErrorObservation("clock-control", probeKind, err))
		} else {
			response, probeErr := probe.Probe(ctx, control, map[string]any{"kind": "processClock", "peer": control.Actor, "port": "metrics", "metric": "stacks_node_process_wall_clock_seconds", "control": true})
			if probeErr != nil {
				observations = append(observations, probeErrorObservation(control.Actor, probeKind, probeErr))
			} else if observation, ok := response["observation"].(map[string]any); ok {
				observations = append(observations, observation)
			} else {
				observations = append(observations, probeErrorObservation(control.Actor, probeKind, errors.New("control probe response omitted its observation object")))
			}
		}
	}
	authority := "active-probe"
	if definition.EffectKind == "clock" {
		authority = "application-process-metric"
	}
	injectionAuthority := "chaos-mesh-status"
	if definition.Backend == ioPressureBackend {
		injectionAuthority = "kubernetes-pod-status"
	} else if definition.Backend == clockPolicyBackend {
		injectionAuthority = "controller-clock-policy"
	}
	source := map[string]any{"trust": "orchestrator-observed", "authority": authority, "collector": "attacknet-probe/v1"}
	if authority == "application-process-metric" {
		source["contentTrust"] = "actor-self-reported"
	}
	return json.Marshal(map[string]any{
		"schemaVersion": "stacks-attacknet-fault-probe/v1",
		"phase":         phase,
		"capturedAt":    r.now(),
		"source":        source,
		"injection": map[string]any{
			"allInjectedObserved": injected,
			"source": map[string]any{
				"trust": "orchestrator-observed", "authority": injectionAuthority,
				"collector": "attacknet-run-operator/v1",
			},
		},
		"observations": observations,
	})
}

func probeErrorObservation(actor, probe string, err error) map[string]any {
	return map[string]any{"actor": actor, "probe": probe, "status": "error", "error": truncate(err.Error(), 4096)}
}

func baselineUsable(kind string, encoded []byte, selectedActors []string) bool {
	definition, err := mechanismForMutationKind(kind)
	if err != nil {
		return false
	}
	selected := set(selectedActors)
	phase, err := decodeProbePhase(string(encoded), "before", kind, selected)
	if err != nil {
		return false
	}
	observed := map[string]map[string]any{}
	for _, observation := range phase.Observations {
		actor := text(observation["actor"])
		if selected[actor] {
			if observed[actor] != nil {
				return false
			}
			observed[actor] = observation
		}
	}
	if len(observed) != len(selected) {
		return false
	}
	for _, observation := range observed {
		if observation["status"] != "ok" {
			return false
		}
		switch definition.ProbeKind {
		case "network", "io":
			if number(observation["successes"]) <= 0 {
				return false
			}
		case "dns":
			if !boolean(observation["querySucceeded"]) || !boolean(observation["controlSucceeded"]) {
				return false
			}
		}
	}
	if definition.EffectKind == "clock" {
		for _, observation := range phase.Observations {
			if observation["status"] == "ok" && boolean(observation["control"]) && !selected[text(observation["actor"])] {
				return true
			}
		}
		return false
	}
	return true
}
