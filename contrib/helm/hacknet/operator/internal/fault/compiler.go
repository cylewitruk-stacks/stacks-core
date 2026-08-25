// Package fault compiles bounded FaultCampaign declarations into mutation objects.
package fault

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

const (
	NetworkLabel = "testing.stacks.org/network"
	ActorLabel   = "testing.stacks.org/actor"
	RoleLabel    = "testing.stacks.org/role"
)

var kindByType = map[string]string{"pod": "PodChaos", "network": "NetworkChaos", "dns": "DNSChaos", "io": "IOChaos", "time": "TimeChaos", "io-pressure": "IOPressurePod", "clock-skew": "ClockSkewPolicy"}

// ManifestActor is one declared network actor used for selection and safety accounting.
type ManifestActor struct {
	Name, Role   string
	SignerIndex  *int32
	SignerWeight *float64
}

// Manifest is the canonical campaign compilation view of a StacksNetwork.
type Manifest struct {
	Network, Namespace string
	Actors             []ManifestActor
}

// SignerImpact records the worst-case canonical signer weight affected.
type SignerImpact struct {
	TotalWeight    float64 `json:"totalWeight"`
	AffectedWeight float64 `json:"affectedWeight"`
	Percent        float64 `json:"percent"`
}

// MinerImpact records the worst-case number of miners affected.
type MinerImpact struct {
	TotalCount    int     `json:"totalCount"`
	AffectedCount int     `json:"affectedCount"`
	Percent       float64 `json:"percent"`
}

// Evidence records bounded compilation facts needed for admission and review.
type Evidence struct {
	SelectedActors        []string                      `json:"selectedActors"`
	PeerSelectedActors    []string                      `json:"peerSelectedActors,omitempty"`
	MaximumAffectedActors int                           `json:"maximumAffectedActors"`
	SignerImpact          SignerImpact                  `json:"signerImpact"`
	MinerImpact           MinerImpact                   `json:"minerImpact"`
	Safety                attacknetv1alpha1.FaultSafety `json:"safety"`
	IOPressure            map[string]any                `json:"ioPressure,omitempty"`
	Parameters            map[string]any                `json:"-"`
}

// Compiled is one trusted mutation descriptor plus its safety evidence.
type Compiled struct {
	Resource *unstructured.Unstructured
	Evidence Evidence
}

// ManifestFromNetwork derives the campaign compiler view from a typed network.
func ManifestFromNetwork(network *attacknetv1alpha1.StacksNetwork) Manifest {
	actors := make([]ManifestActor, len(network.Spec.Actors))
	for index, actor := range network.Spec.Actors {
		actors[index] = ManifestActor{Name: actor.Name, Role: actor.Role, SignerIndex: actor.SignerIndex, SignerWeight: actor.SignerWeight}
	}
	return Manifest{Network: network.Name, Namespace: network.Namespace, Actors: actors}
}

// Compile validates and compiles one FaultCampaign against an admitted manifest.
func Compile(campaign *attacknetv1alpha1.FaultCampaign, manifest Manifest) (Compiled, error) {
	if campaign.Spec.NetworkRef != manifest.Network {
		return Compiled{}, fmt.Errorf("networkRef %s does not match manifest %s", campaign.Spec.NetworkRef, manifest.Network)
	}
	kind, ok := kindByType[campaign.Spec.Fault.Type]
	if !ok {
		return Compiled{}, fmt.Errorf("unsupported fault type %s", campaign.Spec.Fault.Type)
	}
	selected, err := selectActors(campaign.Spec.Target, manifest.Actors)
	if err != nil {
		return Compiled{}, err
	}
	maximum, modeValue, err := normalizeMode(campaign.Spec.Fault, len(selected))
	if err != nil {
		return Compiled{}, err
	}
	if campaign.Spec.Fault.Type == "io-pressure" && (len(selected) != 1 || maximum != 1) {
		return Compiled{}, errors.New("disk-pressure must resolve to exactly one actor target")
	}
	duration, err := boundedDuration(campaign.Spec.Fault.Duration, "fault.duration", false)
	if err != nil || duration > 24*time.Hour {
		return Compiled{}, fmt.Errorf("fault duration must be an integer ms/s/m/h value within 1ms..24h: %q", campaign.Spec.Fault.Duration)
	}
	if duration > 10*time.Minute && !campaign.Spec.Safety.AllowExtendedDuration {
		return Compiled{}, errors.New("faults longer than 10m require safety.allowExtendedDuration=true")
	}
	if duration > time.Hour && !campaign.Spec.Safety.AllowExtremeSeverity {
		return Compiled{}, errors.New("faults longer than 1h require safety.allowExtremeSeverity=true")
	}
	for _, actor := range selected {
		if actor.Role == "burnchain" && !campaign.Spec.Safety.AllowBurnchain {
			return Compiled{}, errors.New("burnchain faults require safety.allowBurnchain=true")
		}
	}
	signer := weightedImpact(selected, manifest.Actors, maximum)
	miner := countedImpact(selected, manifest.Actors, maximum, "miner")
	if signer.Percent > campaign.Spec.Safety.MaxUnavailableSignerPercent && !campaign.Spec.Safety.AllowQuorumLoss {
		return Compiled{}, fmt.Errorf("selected signer impact %.1f%% exceeds %.1f%%", signer.Percent, campaign.Spec.Safety.MaxUnavailableSignerPercent)
	}
	if miner.Percent > campaign.Spec.Safety.MaxUnavailableMinerPercent && !campaign.Spec.Safety.AllowMinerMajorityOutage {
		return Compiled{}, fmt.Errorf("selected miner impact %.1f%% exceeds %.1f%%", miner.Percent, campaign.Spec.Safety.MaxUnavailableMinerPercent)
	}
	parameters := map[string]any{}
	if len(campaign.Spec.Fault.Parameters.Raw) > 0 {
		if err := json.Unmarshal(campaign.Spec.Fault.Parameters.Raw, &parameters); err != nil {
			return Compiled{}, fmt.Errorf("decode fault parameters: %w", err)
		}
	}
	normalized, err := validateParameters(campaign.Spec.Fault.Type, campaign.Spec.Fault.Action, parameters, campaign.Spec.Safety, duration, manifest)
	if err != nil {
		return Compiled{}, err
	}
	parameters = normalized.Parameters
	selector := map[string]any{"namespaces": []any{manifest.Namespace}, "labelSelectors": map[string]any{NetworkLabel: manifest.Network}}
	expressions := []any{}
	if len(campaign.Spec.Target.Actors) > 0 {
		expressions = append(expressions, map[string]any{"key": ActorLabel, "operator": "In", "values": stringAny(campaign.Spec.Target.Actors)})
	}
	if len(campaign.Spec.Target.Roles) > 0 {
		expressions = append(expressions, map[string]any{"key": RoleLabel, "operator": "In", "values": stringAny(campaign.Spec.Target.Roles)})
	}
	selector["expressionSelectors"] = expressions
	spec := map[string]any{"mode": campaign.Spec.Fault.Mode, "duration": campaign.Spec.Fault.Duration, "selector": selector}
	if spec["mode"] == "" {
		spec["mode"] = "one"
	}
	if modeValue != "" {
		spec["value"] = modeValue
	}
	if campaign.Spec.Fault.Type != "time" && campaign.Spec.Fault.Type != "clock-skew" && campaign.Spec.Fault.Type != "io-pressure" {
		spec["action"] = campaign.Spec.Fault.Action
	}
	for key, value := range parameters {
		spec[key] = value
	}
	apiVersion := "chaos-mesh.org/v1alpha1"
	if campaign.Spec.Fault.Type == "io-pressure" || campaign.Spec.Fault.Type == "clock-skew" {
		apiVersion = "testing.stacks.org/internal"
	}
	metadata := map[string]any{"name": campaign.Name, "namespace": manifest.Namespace, "labels": map[string]any{NetworkLabel: manifest.Network, "testing.stacks.org/campaign": campaign.Name}}
	if normalized.IOPressure != nil {
		encoded, marshalErr := json.Marshal(normalized.IOPressure)
		if marshalErr != nil {
			return Compiled{}, marshalErr
		}
		metadata["annotations"] = map[string]any{"testing.stacks.org/io-pressure-contract": string(encoded)}
	}
	resource := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": metadata, "spec": spec}}
	selectedNames := make([]string, len(selected))
	for index, actor := range selected {
		selectedNames[index] = actor.Name
	}
	sort.Strings(selectedNames)
	return Compiled{Resource: resource, Evidence: Evidence{
		SelectedActors:        selectedNames,
		PeerSelectedActors:    normalized.PeerSelectedActors,
		MaximumAffectedActors: maximum,
		SignerImpact:          signer,
		MinerImpact:           miner,
		Safety:                campaign.Spec.Safety,
		IOPressure:            normalized.IOPressure,
		Parameters:            parameters,
	}}, nil
}

func selectActors(target attacknetv1alpha1.FaultTarget, actors []ManifestActor) ([]ManifestActor, error) {
	if len(target.Actors) == 0 && len(target.Roles) == 0 {
		return nil, errors.New("target requires actors or roles")
	}
	names, roles := set(target.Actors), set(target.Roles)
	known := map[string]bool{}
	for _, actor := range actors {
		known[actor.Name] = true
	}
	for name := range names {
		if !known[name] {
			return nil, fmt.Errorf("unknown target actor %s", name)
		}
	}
	result := []ManifestActor{}
	for _, actor := range actors {
		if (len(names) == 0 || names[actor.Name]) && (len(roles) == 0 || roles[actor.Role]) {
			result = append(result, actor)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("target selector matches no actors")
	}
	return result, nil
}

func normalizeMode(spec attacknetv1alpha1.FaultSpec, candidates int) (int, string, error) {
	mode := spec.Mode
	if mode == "" {
		mode = "one"
	}
	switch mode {
	case "one":
		if spec.Value != nil {
			return 0, "", errors.New("fault.value is forbidden when mode is one")
		}
		return 1, "", nil
	case "all":
		if spec.Value != nil {
			return 0, "", errors.New("fault.value is forbidden when mode is all")
		}
		return candidates, "", nil
	case "fixed", "fixed-percent", "random-max-percent":
		if spec.Value == nil {
			return 0, "", fmt.Errorf("fault.value is required when mode is %s", mode)
		}
		value := spec.Value.String()
		number, err := strconv.Atoi(value)
		if err != nil || number < 1 {
			return 0, "", fmt.Errorf("fault.value must be a positive integer for mode %s", mode)
		}
		if mode == "fixed" {
			if number > candidates {
				return 0, "", errors.New("fixed fault.value exceeds candidate count")
			}
			return number, value, nil
		}
		if number > 100 {
			return 0, "", errors.New("percentage fault.value exceeds 100")
		}
		return int(math.Ceil(float64(candidates) * float64(number) / 100)), value, nil
	default:
		return 0, "", fmt.Errorf("unsupported fault mode %s", mode)
	}
}

func weightedImpact(selected, all []ManifestActor, maximum int) SignerImpact {
	weights, affected := map[int32]float64{}, map[int32]float64{}
	for _, actor := range all {
		if actor.SignerIndex != nil && actor.SignerWeight != nil {
			weights[*actor.SignerIndex] = *actor.SignerWeight
		}
	}
	for _, actor := range selected {
		if actor.SignerIndex != nil && actor.SignerWeight != nil {
			affected[*actor.SignerIndex] = *actor.SignerWeight
		}
	}
	total := 0.0
	for _, weight := range weights {
		total += weight
	}
	ordered := make([]float64, 0, len(affected))
	for _, weight := range affected {
		ordered = append(ordered, weight)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(ordered)))
	if maximum < len(ordered) {
		ordered = ordered[:maximum]
	}
	changed := 0.0
	for _, weight := range ordered {
		changed += weight
	}
	percent := 0.0
	if total > 0 {
		percent = changed * 100 / total
	}
	return SignerImpact{TotalWeight: total, AffectedWeight: changed, Percent: percent}
}

func countedImpact(selected, all []ManifestActor, maximum int, role string) MinerImpact {
	total, candidates := 0, 0
	for _, actor := range all {
		if actor.Role == role {
			total++
		}
	}
	for _, actor := range selected {
		if actor.Role == role {
			candidates++
		}
	}
	affected := min(candidates, maximum)
	percent := 0.0
	if total > 0 {
		percent = float64(affected) * 100 / float64(total)
	}
	return MinerImpact{TotalCount: total, AffectedCount: affected, Percent: percent}
}

// ResolveTargets binds selected logical actors to exact Ready Pod identities.
func ResolveTargets(manifest Manifest, selected []string, pods []corev1.Pod) ([]attacknetv1alpha1.ResolvedTarget, error) {
	result := make([]attacknetv1alpha1.ResolvedTarget, 0, len(selected))
	for _, actor := range selected {
		matches := []corev1.Pod{}
		for _, pod := range pods {
			if pod.DeletionTimestamp == nil && pod.Labels[NetworkLabel] == manifest.Network && pod.Labels[ActorLabel] == actor {
				matches = append(matches, pod)
			}
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("selected actor %s resolves to %d admitted Pods", actor, len(matches))
		}
		pod := matches[0]
		var status *corev1.ContainerStatus
		for index := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[index].Name == "actor" {
				status = &pod.Status.ContainerStatuses[index]
			}
		}
		if pod.Status.Phase != corev1.PodRunning || !podIsReady(pod) || status == nil || !status.Ready || pod.UID == "" || pod.Spec.NodeName == "" || pod.Status.PodIP == "" || !inventory.HasImmutableImageID(status.ImageID) {
			return nil, fmt.Errorf("selected actor %s is not admitted Running and Ready with an immutable runtime image ID", actor)
		}
		requested := actorContainerImage(pod)
		resolved := status.ImageID
		result = append(result, attacknetv1alpha1.ResolvedTarget{Actor: actor, Role: pod.Labels[RoleLabel], Pod: pod.Name, PodUID: string(pod.UID), PodIP: pod.Status.PodIP, Node: pod.Spec.NodeName, RequestedImage: &requested, ResolvedImageID: &resolved, RestartCount: status.RestartCount})
	}
	return result, nil
}

func actorContainerImage(pod corev1.Pod) string {
	for _, container := range pod.Spec.Containers {
		if container.Name == "actor" {
			return container.Image
		}
	}
	return ""
}

func podIsReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func set(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}
func stringAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
