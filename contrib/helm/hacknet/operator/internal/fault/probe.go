package fault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

const maxProbeResponseBytes = 128 << 10

// ProbeClient obtains bounded observations from credential-free actor probe sidecars.
type ProbeClient interface {
	Probe(context.Context, attacknetv1alpha1.ResolvedTarget, map[string]any) (map[string]any, error)
}

// HTTPProbeClient calls the trusted probe sidecar directly by admitted Pod IP.
type HTTPProbeClient struct {
	Client *http.Client
	Port   int
}

// Probe submits one bounded request and verifies response identity and schema.
func (p HTTPProbeClient) Probe(ctx context.Context, target attacknetv1alpha1.ResolvedTarget, body map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	port := p.Port
	if port == 0 {
		port = 18080
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s:%d/v1/probe", target.PodIP, port), bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("probe %s: %w", target.Actor, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe %s returned HTTP %d", target.Actor, response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxProbeResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxProbeResponseBytes {
		return nil, errors.New("probe response exceeds 128 KiB")
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, fmt.Errorf("decode probe response: %w", err)
	}
	if parsed["schemaVersion"] != "stacks-attacknet-probe-response/v1" || parsed["actor"] != target.Actor || parsed["kind"] != body["kind"] || parsed["observation"] == nil {
		return nil, fmt.Errorf("probe %s returned mismatched identity or schema", target.Actor)
	}
	return parsed, nil
}

func probeRequest(kind string, campaign *attacknetv1alpha1.FaultCampaign, target attacknetv1alpha1.ResolvedTarget, network *attacknetv1alpha1.StacksNetwork, compiled Compiled) (map[string]any, error) {
	switch kind {
	case "NetworkChaos":
		if len(compiled.Evidence.PeerSelectedActors) == 1 && compiled.Evidence.PeerSelectedActors[0] == "attacknet-prometheus" {
			return map[string]any{"kind": "network", "peer": "attacknet-prometheus", "port": "http", "attempts": 5, "timeoutMs": 2000}, nil
		}
		preferred := set(compiled.Evidence.PeerSelectedActors)
		throughput := campaign.Spec.Fault.Action == "bandwidth"
		candidates := make([]attacknetv1alpha1.ActorSpec, 0, len(network.Spec.Actors))
		for _, actor := range network.Spec.Actors {
			if actor.Name != target.Actor && (len(preferred) == 0 || preferred[actor.Name]) && ((!throughput && preferredPort(actor) != "") || (throughput && actorProbeEnabled(network, actor))) {
				candidates = append(candidates, actor)
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
		if len(candidates) > 0 {
			if throughput {
				return map[string]any{"kind": "network", "peer": candidates[0].Name, "port": "probe", "attempts": 3, "timeoutMs": 10000, "throughputBytes": 65536}, nil
			}
			return map[string]any{"kind": "network", "peer": candidates[0].Name, "port": preferredPort(candidates[0]), "attempts": 5, "timeoutMs": 2000}, nil
		}
		return nil, fmt.Errorf("no enrolled peer endpoint is available for %s", target.Actor)
	case "DNSChaos":
		patterns, _ := stringsValue(compiled.Evidence.Parameters["patterns"], "patterns", true, nil)
		candidates := make([]attacknetv1alpha1.ActorSpec, 0, len(network.Spec.Actors))
		for _, actor := range network.Spec.Actors {
			if actor.Name == target.Actor {
				continue
			}
			fqdn := fmt.Sprintf("%s-%s.%s.svc.cluster.local", network.Name, actor.Name, network.Namespace)
			for _, pattern := range patterns {
				if glob(pattern, fqdn) {
					candidates = append(candidates, actor)
					break
				}
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no enrolled service name matches the DNS fault patterns for %s", target.Actor)
		}
		return map[string]any{"kind": "dns", "peer": candidates[0].Name}, nil
	case "IOChaos":
		operation := "FSYNC"
		if methods, ok := compiled.Evidence.Parameters["methods"].([]any); ok {
			for _, candidate := range methods {
				name, _ := candidate.(string)
				if name == "READ" || name == "WRITE" || name == "FSYNC" {
					operation = name
					break
				}
			}
		}
		return map[string]any{"kind": "io", "operation": operation, "attempts": 5, "bytes": 4096, "file": campaign.Name + ".dat"}, nil
	case "IOPressurePod":
		return map[string]any{"kind": "io", "operation": "FSYNC", "attempts": 5, "bytes": 4096, "file": campaign.Name + ".dat"}, nil
	case "TimeChaos", "ClockSkewPolicy":
		return map[string]any{"kind": "processClock", "peer": target.Actor, "port": "metrics", "metric": "stacks_node_process_wall_clock_seconds", "control": false}, nil
	default:
		return nil, fmt.Errorf("no active probe contract for %s", kind)
	}
}

func actorProbeEnabled(network *attacknetv1alpha1.StacksNetwork, actor attacknetv1alpha1.ActorSpec) bool {
	enabled := false
	if network.Spec.Probe != nil && network.Spec.Probe.Enabled != nil {
		enabled = *network.Spec.Probe.Enabled
	}
	if actor.Probe != nil && actor.Probe.Enabled != nil {
		enabled = *actor.Probe.Enabled
	}
	return enabled
}

func controlTarget(network *attacknetv1alpha1.StacksNetwork, targets []attacknetv1alpha1.ResolvedTarget, pods []corev1.Pod) (attacknetv1alpha1.ResolvedTarget, error) {
	selected := map[string]bool{}
	for _, target := range targets {
		selected[target.Actor] = true
	}
	type candidate struct {
		actor attacknetv1alpha1.ActorSpec
		pod   corev1.Pod
	}
	candidates := []candidate{}
	for _, actor := range network.Spec.Actors {
		if selected[actor.Name] {
			continue
		}
		for _, pod := range pods {
			if pod.DeletionTimestamp != nil || pod.Labels[ActorLabel] != actor.Name || pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" || !podIsReady(pod) {
				continue
			}
			actorReady, probeReady := false, false
			for index := range pod.Status.ContainerStatuses {
				status := &pod.Status.ContainerStatuses[index]
				if status.Name == "actor" && status.Ready && inventory.HasImmutableImageID(status.ImageID) {
					actorReady = true
				}
				if status.Name == "attacknet-probe" && status.Ready {
					probeReady = true
				}
			}
			if actorReady && probeReady {
				candidates = append(candidates, candidate{actor: actor, pod: pod})
			}
		}
	}
	roleOrder := map[string]int{"follower": 0, "companion": 1, "miner": 2, "signer": 3}
	sort.Slice(candidates, func(i, j int) bool {
		left, leftKnown := roleOrder[candidates[i].actor.Role]
		right, rightKnown := roleOrder[candidates[j].actor.Role]
		if !leftKnown {
			left = 9
		}
		if !rightKnown {
			right = 9
		}
		return left < right || (left == right && candidates[i].actor.Name < candidates[j].actor.Name)
	})
	if len(candidates) > 0 {
		selected := candidates[0]
		requested, resolved, restartCount := actorContainerImage(selected.pod), "", int32(0)
		for _, status := range selected.pod.Status.ContainerStatuses {
			if status.Name == "actor" {
				resolved, restartCount = status.ImageID, status.RestartCount
			}
		}
		return attacknetv1alpha1.ResolvedTarget{Actor: selected.actor.Name, Role: selected.actor.Role, Pod: selected.pod.Name, PodUID: string(selected.pod.UID), PodIP: selected.pod.Status.PodIP, Node: selected.pod.Spec.NodeName, RequestedImage: &requested, ResolvedImageID: &resolved, RestartCount: restartCount}, nil
	}
	return attacknetv1alpha1.ResolvedTarget{}, errors.New("no independent Ready clock-control actor is available")
}

func preferredPort(actor attacknetv1alpha1.ActorSpec) string {
	ports := effectiveManifestPorts(actor)
	for _, port := range ports {
		if port == "p2p" {
			return port
		}
	}
	if len(ports) > 0 {
		return ports[0]
	}
	return ""
}

func effectiveManifestPorts(actor attacknetv1alpha1.ActorSpec) []string {
	if len(actor.Ports) > 0 {
		result := make([]string, len(actor.Ports))
		for index, port := range actor.Ports {
			result[index] = port.Name
		}
		return result
	}
	switch actor.Role {
	case "signer":
		return []string{"events", "metrics"}
	case "burnchain":
		return []string{"rpc", "p2p"}
	case "miner", "companion", "follower", "adversary":
		return []string{"p2p", "rpc", "metrics"}
	default:
		return nil
	}
}
