package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const (
	maximumCampaignStages              = 16
	maximumSignerBehaviorTargetWindows = 32
)

var stageIDPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// CompiledAction is one independently named mutation and its bounded impact.
type CompiledAction struct {
	ID       string
	Resource *unstructured.Unstructured
	Evidence Evidence
}

// CompiledStage is one trigger-coordinated collection of mutations.
type CompiledStage struct {
	ID      string
	Trigger attacknetv1beta1.StageTriggerSpec
	Actions []CompiledAction
}

// AggregateImpact is the conservative maximum impact of possibly overlapping stages.
type AggregateImpact struct {
	ConcurrentFaults             int32    `json:"concurrentFaults"`
	SignerTotalWeight            float64  `json:"signerTotalWeight"`
	SignerAffectedWeight         float64  `json:"signerAffectedWeight"`
	SignerAffectedBasisPoints    int32    `json:"signerAffectedBasisPoints"`
	MinerTotalCount              int32    `json:"minerTotalCount"`
	MinerAffectedCount           int32    `json:"minerAffectedCount"`
	MinerAffectedBasisPoints     int32    `json:"minerAffectedBasisPoints"`
	PotentiallyOverlappingStages []string `json:"potentiallyOverlappingStages"`
}

// CompiledCampaign is the immutable result of compiling every stage as a set.
type CompiledCampaign struct {
	Stages          []CompiledStage
	AggregateImpact AggregateImpact
}

// CompileV1Beta1 compiles all actions and enforces safety over every stage set
// that can overlap according to completed-stage dependency barriers.
func CompileV1Beta1(campaign *attacknetv1beta1.FaultCampaign, manifest Manifest) (CompiledCampaign, error) {
	if err := ValidateV1Beta1Structure(campaign); err != nil {
		return CompiledCampaign{}, err
	}
	if campaign.Spec.NetworkRef != manifest.Network {
		return CompiledCampaign{}, fmt.Errorf("networkRef %s does not match manifest %s", campaign.Spec.NetworkRef, manifest.Network)
	}
	stages := make([]CompiledStage, 0, len(campaign.Spec.Stages))
	signerBehaviorTargetWindows := 0
	for stageIndex := range campaign.Spec.Stages {
		stage := &campaign.Spec.Stages[stageIndex]
		compiled := CompiledStage{ID: stage.ID, Trigger: *stage.Trigger.DeepCopy()}
		for actionIndex := range stage.Faults {
			action := &stage.Faults[actionIndex]
			item, err := compileV1Beta1Action(campaign, stage, action, manifest)
			if err != nil {
				return CompiledCampaign{}, fmt.Errorf("stage %q action %q: %w", stage.ID, action.ID, err)
			}
			compiled.Actions = append(compiled.Actions, item)
			if action.Fault.Type == "signer-behavior" {
				signerBehaviorTargetWindows += len(item.Evidence.SelectedActors)
				if signerBehaviorTargetWindows > maximumSignerBehaviorTargetWindows {
					return CompiledCampaign{}, fmt.Errorf("signer-behavior target windows %d exceed bounded status-evidence maximum %d", signerBehaviorTargetWindows, maximumSignerBehaviorTargetWindows)
				}
			}
		}
		stages = append(stages, compiled)
	}
	if err := validateSharedMutationCompatibility(stages, campaign.Spec.Stages); err != nil {
		return CompiledCampaign{}, err
	}
	impact := maximumAggregateImpact(stages, campaign.Spec.Stages, manifest)
	if impact.ConcurrentFaults > campaign.Spec.Safety.MaxConcurrentFaults {
		return CompiledCampaign{}, fmt.Errorf("aggregate concurrent faults %d exceed safety maximum %d", impact.ConcurrentFaults, campaign.Spec.Safety.MaxConcurrentFaults)
	}
	if impact.SignerAffectedBasisPoints > campaign.Spec.Safety.MaxUnavailableSignerBasisPoints && !campaign.Spec.Safety.AllowQuorumLoss {
		return CompiledCampaign{}, fmt.Errorf("aggregate signer impact %d basis points exceeds safety maximum %d", impact.SignerAffectedBasisPoints, campaign.Spec.Safety.MaxUnavailableSignerBasisPoints)
	}
	if impact.MinerAffectedBasisPoints > campaign.Spec.Safety.MaxUnavailableMinerBasisPoints && !campaign.Spec.Safety.AllowMinerMajorityOutage {
		return CompiledCampaign{}, fmt.Errorf("aggregate miner impact %d basis points exceeds safety maximum %d", impact.MinerAffectedBasisPoints, campaign.Spec.Safety.MaxUnavailableMinerBasisPoints)
	}
	return CompiledCampaign{Stages: stages, AggregateImpact: impact}, nil
}

func validateAssertionScope(scope string, assertions []attacknetv1beta1.CampaignAssertion, actionIDs map[string]struct{}, requireAction bool) error {
	for _, assertion := range assertions {
		if assertion.Type == "" {
			return fmt.Errorf("%s assertion type is required", scope)
		}
		if !knownAssertionTypes[assertion.Type] {
			return fmt.Errorf("%s assertion type %q is unsupported", scope, assertion.Type)
		}
		if assertion.TimeoutSeconds < 0 {
			return fmt.Errorf("%s assertion timeoutSeconds cannot be negative", scope)
		}
		if requireAction && assertion.Action == "" {
			return fmt.Errorf("%s assertion must name an action when the scope contains multiple actions", scope)
		}
		if assertion.Action != "" {
			if _, exists := actionIDs[assertion.Action]; !exists {
				return fmt.Errorf("%s assertion references unknown action %q", scope, assertion.Action)
			}
		}
	}
	return nil
}

var knownAssertionTypes = map[string]bool{
	"PodRestarted": true, "PodUnavailable": true, "ContainerRestarted": true,
	"TargetReady": true, "NetworkDegraded": true, "NetworkRecovered": true,
	"DNSDegraded": true, "DNSRecovered": true, "IODegraded": true,
	"IORecovered": true, "IOPressureObserved": true, "IOPressureRecovered": true,
	"ClockSkewObserved": true, "ClockSkewCleared": true,
	"BurnchainReorgProven": true, "BurnchainPolicyRestored": true,
	"SignerBehaviorObserved": true, "SignerBehaviorWindowClosed": true,
}

func campaignActionCount(stages []attacknetv1beta1.FaultStageSpec) int {
	count := 0
	for _, stage := range stages {
		count += len(stage.Faults)
	}
	return count
}

func validateSharedMutationCompatibility(compiled []CompiledStage, specs []attacknetv1beta1.FaultStageSpec) error {
	sharedTargets := make([]map[string]string, len(compiled))
	for stageIndex := range compiled {
		sharedTargets[stageIndex] = map[string]string{}
		for _, action := range compiled[stageIndex].Actions {
			kind := action.Resource.GetKind()
			if kind != "ClockSkewPolicy" && kind != "BurnchainReorgWorker" {
				continue
			}
			for _, actor := range action.Evidence.SelectedActors {
				owner := compiled[stageIndex].ID + "/" + action.ID
				key := kind + "\x00" + actor
				if previous, exists := sharedTargets[stageIndex][key]; exists && previous != owner {
					return sharedMutationConflict(kind, previous, owner, actor)
				}
				sharedTargets[stageIndex][key] = owner
			}
		}
	}
	for left := range compiled {
		for right := left + 1; right < len(compiled); right++ {
			if !stagesCanOverlap([]int{left, right}, specs) {
				continue
			}
			for key, leftOwner := range sharedTargets[left] {
				if rightOwner := sharedTargets[right][key]; rightOwner != "" {
					parts := strings.SplitN(key, "\x00", 2)
					return sharedMutationConflict(parts[0], leftOwner, rightOwner, parts[1])
				}
			}
		}
	}
	return nil
}

func sharedMutationConflict(kind, left, right, actor string) error {
	mechanism := "clock-skew"
	policy := "clock"
	if kind == "BurnchainReorgWorker" {
		mechanism = "burnchain-reorg"
		policy = "burnchain"
	}
	return fmt.Errorf("overlapping %s actions %s and %s target actor %s through the shared %s policy", mechanism, left, right, actor, policy)
}

func compileV1Beta1Action(campaign *attacknetv1beta1.FaultCampaign, stage *attacknetv1beta1.FaultStageSpec, action *attacknetv1beta1.FaultActionSpec, manifest Manifest) (CompiledAction, error) {
	if action.Fault.Type == "burnchain-reorg" {
		return compileBurnchainReorgAction(campaign, stage, action, manifest)
	}
	if action.Fault.Type == "signer-behavior" {
		return compileSignerBehaviorAction(campaign, stage, action, manifest)
	}
	legacy := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: mutationName(campaign.Name, stage.ID, action.ID), Namespace: campaign.Namespace},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: campaign.Spec.NetworkRef,
			Target: attacknetv1alpha1.FaultTarget{
				Actors: append([]string(nil), action.Target.Actors...),
				Roles:  append([]string(nil), action.Target.Roles...),
			},
			Fault: attacknetv1alpha1.FaultSpec{
				Type: action.Fault.Type, Action: action.Fault.Action, Mode: action.Fault.Mode,
				Value: action.Fault.Value, Duration: legacyDuration(action.Fault.Duration.Duration),
				Parameters: action.Fault.Parameters,
			},
			Safety: attacknetv1alpha1.FaultSafety{
				MaxUnavailableSignerPercent: 100, MaxUnavailableMinerPercent: 100,
				AllowQuorumLoss: true, AllowMinerMajorityOutage: true,
				AllowBurnchain:         campaign.Spec.Safety.AllowBurnchain,
				AllowExtendedDuration:  campaign.Spec.Safety.AllowExtendedDuration,
				AllowExtremeSeverity:   campaign.Spec.Safety.AllowExtremeSeverity,
				AllowUnenrolledTargets: campaign.Spec.Safety.AllowUnenrolledTargets,
			},
		},
	}
	compiled, err := Compile(legacy, manifest)
	if err != nil {
		return CompiledAction{}, err
	}
	compiled.Resource.SetName(legacy.Name)
	compiled.Resource.SetLabels(mergeLabels(compiled.Resource.GetLabels(), map[string]string{
		"testing.stacks.org/campaign": campaign.Name,
		"testing.stacks.org/stage":    stage.ID,
		"testing.stacks.org/action":   action.ID,
	}))
	return CompiledAction{ID: action.ID, Resource: compiled.Resource, Evidence: compiled.Evidence}, nil
}

func compileSignerBehaviorAction(campaign *attacknetv1beta1.FaultCampaign, stage *attacknetv1beta1.FaultStageSpec, action *attacknetv1beta1.FaultActionSpec, manifest Manifest) (CompiledAction, error) {
	target := attacknetv1alpha1.FaultTarget{Actors: append([]string(nil), action.Target.Actors...), Roles: append([]string(nil), action.Target.Roles...)}
	selected, err := selectActors(target, manifest.Actors)
	if err != nil {
		return CompiledAction{}, err
	}
	if len(selected) != 1 {
		return CompiledAction{}, errors.New("signer-behavior must resolve exactly one signer per independently attributable action")
	}
	names := make([]string, 0, len(selected))
	for _, actor := range selected {
		if actor.Role != "signer" {
			return CompiledAction{}, fmt.Errorf("signer-behavior target %s has role %s, want signer", actor.Name, actor.Role)
		}
		if actor.AdversarialPolicyDigest != action.Fault.SignerBehavior.PolicyDigest {
			return CompiledAction{}, fmt.Errorf("signer-behavior target %s policy digest does not match the requested digest", actor.Name)
		}
		if actor.AdversarialBehavior != action.Fault.Action {
			return CompiledAction{}, fmt.Errorf("signer-behavior target %s policy behavior %q does not match requested action %q", actor.Name, actor.AdversarialBehavior, action.Fault.Action)
		}
		names = append(names, actor.Name)
	}
	sort.Strings(names)
	resource := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "testing.stacks.org/internal", "kind": "SignerBehaviorSession",
		"metadata": map[string]any{"name": mutationName(campaign.Name, stage.ID, action.ID), "namespace": campaign.Namespace, "labels": map[string]any{
			NetworkLabel: campaign.Spec.NetworkRef, "testing.stacks.org/campaign": campaign.Name, "testing.stacks.org/stage": stage.ID, "testing.stacks.org/action": action.ID,
		}},
		"spec": map[string]any{"action": action.Fault.Action, "policyDigest": action.Fault.SignerBehavior.PolicyDigest, "actors": stringSliceAny(names)},
	}}
	evidence := Evidence{SelectedActors: names, MaximumAffectedActors: len(names)}
	selectedActors := make([]ManifestActor, 0, len(names))
	for _, actor := range selected {
		selectedActors = append(selectedActors, actor)
	}
	evidence.SignerImpact = weightedImpact(selectedActors, manifest.Actors, len(names))
	return CompiledAction{ID: action.ID, Resource: resource, Evidence: evidence}, nil
}

func stringSliceAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func compileBurnchainReorgAction(campaign *attacknetv1beta1.FaultCampaign, stage *attacknetv1beta1.FaultStageSpec, action *attacknetv1beta1.FaultActionSpec, manifest Manifest) (CompiledAction, error) {
	target := attacknetv1alpha1.FaultTarget{Actors: append([]string(nil), action.Target.Actors...)}
	selected, err := selectActors(target, manifest.Actors)
	if err != nil {
		return CompiledAction{}, err
	}
	if len(selected) != 1 || selected[0].Role != "burnchain" {
		return CompiledAction{}, errors.New("burnchain-reorg target must resolve to exactly one burnchain actor")
	}
	request := action.Fault.BurnchainReorg
	resource := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "testing.stacks.org/internal",
		"kind":       "BurnchainReorgWorker",
		"metadata": map[string]any{
			"name":      mutationName(campaign.Name, stage.ID, action.ID),
			"namespace": campaign.Namespace,
			"labels": map[string]any{
				NetworkLabel:                  campaign.Spec.NetworkRef,
				"testing.stacks.org/campaign": campaign.Name,
				"testing.stacks.org/stage":    stage.ID,
				"testing.stacks.org/action":   action.ID,
			},
		},
		"spec": map[string]any{
			"actor":                          selected[0].Name,
			"depth":                          int64(request.Depth),
			"replacementBlocks":              int64(request.ReplacementBlocks),
			"replacementIntervalNanoseconds": request.ReplacementInterval.Duration.Nanoseconds(),
			"destinationIndex":               int64(request.DestinationIndex),
		},
	}}
	evidence := Evidence{
		SelectedActors: []string{selected[0].Name}, MaximumAffectedActors: 1,
		Safety: attacknetv1alpha1.FaultSafety{AllowBurnchain: true},
	}
	return CompiledAction{ID: action.ID, Resource: resource, Evidence: evidence}, nil
}

func legacyDuration(value time.Duration) string {
	for _, unit := range []struct {
		duration time.Duration
		suffix   string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}, {time.Millisecond, "ms"}} {
		if value%unit.duration == 0 {
			return fmt.Sprintf("%d%s", value/unit.duration, unit.suffix)
		}
	}
	return value.String()
}

func validateStageTrigger(trigger attacknetv1beta1.StageTriggerSpec) error {
	count := 0
	if trigger.AfterCampaignStart != nil {
		count++
		if trigger.AfterCampaignStart.Duration < 0 {
			return errors.New("afterCampaignStart cannot be negative")
		}
	}
	if trigger.AfterStage != nil {
		count++
	}
	if trigger.BurnHeight != nil {
		count++
		if *trigger.BurnHeight < 0 {
			return errors.New("burnHeight cannot be negative")
		}
	}
	if trigger.StacksHeight != nil {
		count++
		if *trigger.StacksHeight < 0 {
			return errors.New("stacksHeight cannot be negative")
		}
	}
	if trigger.Observation != nil {
		count++
		if trigger.Observation.Type == "" || trigger.Observation.TimeoutSeconds < 1 {
			return errors.New("observation requires type and a positive timeoutSeconds")
		}
	}
	if count > 1 {
		return errors.New("exactly zero or one trigger variant may be set")
	}
	return nil
}

func validateStageDependencies(stages []attacknetv1beta1.FaultStageSpec, indexes map[string]int) error {
	for index := range stages {
		dependency := stages[index].Trigger.AfterStage
		if dependency == nil {
			continue
		}
		dependencyIndex, found := indexes[dependency.Stage]
		if !found {
			return fmt.Errorf("stage %q depends on unknown stage %q", stages[index].ID, dependency.Stage)
		}
		if dependencyIndex >= index {
			return fmt.Errorf("stage %q must depend on an earlier stage, got %q", stages[index].ID, dependency.Stage)
		}
		if dependency.State != "Injected" && dependency.State != "Effective" && dependency.State != "Recovered" && dependency.State != "Terminal" {
			return fmt.Errorf("stage %q dependency state must be Injected, Effective, Recovered, or Terminal", stages[index].ID)
		}
		if dependency.Delay.Duration < 0 {
			return fmt.Errorf("stage %q dependency delay cannot be negative", stages[index].ID)
		}
	}
	return nil
}

func maximumAggregateImpact(compiled []CompiledStage, specs []attacknetv1beta1.FaultStageSpec, manifest Manifest) AggregateImpact {
	maximum := AggregateImpact{}
	for _, weight := range signerWeights(manifest.Actors) {
		maximum.SignerTotalWeight += weight
	}
	for _, actor := range manifest.Actors {
		if actor.Role == "miner" {
			maximum.MinerTotalCount++
		}
	}
	stageFaults := make([]int32, len(compiled))
	stageSignerWeight := make([]float64, len(compiled))
	stageMinerCount := make([]int32, len(compiled))
	conflicts := make([]int, len(compiled))
	for index := range compiled {
		for _, action := range compiled[index].Actions {
			stageFaults[index]++
			stageSignerWeight[index] += action.Evidence.SignerImpact.AffectedWeight
			stageMinerCount[index] += int32(action.Evidence.MinerImpact.AffectedCount)
		}
		for other := 0; other < index; other++ {
			if !stagesCanOverlap([]int{other, index}, specs) {
				conflicts[index] |= 1 << other
				conflicts[other] |= 1 << index
			}
		}
	}
	total := 1 << len(compiled)
	valid := make([]bool, total)
	concurrent := make([]int32, total)
	signerWeight := make([]float64, total)
	minerCount := make([]int32, total)
	valid[0] = true
	for mask := 1; mask < 1<<len(compiled); mask++ {
		stageIndex := bits.TrailingZeros(uint(mask))
		stageBit := 1 << stageIndex
		rest := mask &^ stageBit
		if !valid[rest] || conflicts[stageIndex]&rest != 0 {
			continue
		}
		valid[mask] = true
		concurrent[mask] = concurrent[rest] + stageFaults[stageIndex]
		signerWeight[mask] = min(maximum.SignerTotalWeight, signerWeight[rest]+stageSignerWeight[stageIndex])
		minerCount[mask] = min(maximum.MinerTotalCount, minerCount[rest]+stageMinerCount[stageIndex])
		if concurrent[mask] > maximum.ConcurrentFaults {
			maximum.ConcurrentFaults = concurrent[mask]
			maximum.PotentiallyOverlappingStages = stageNamesForMask(mask, compiled)
		}
		signerBasisPoints := int32(0)
		if maximum.SignerTotalWeight > 0 {
			signerBasisPoints = int32(signerWeight[mask] * 10_000 / maximum.SignerTotalWeight)
		}
		if signerBasisPoints > maximum.SignerAffectedBasisPoints {
			maximum.SignerAffectedBasisPoints = signerBasisPoints
			maximum.SignerAffectedWeight = signerWeight[mask]
		}
		minerBasisPoints := int32(0)
		if maximum.MinerTotalCount > 0 {
			minerBasisPoints = minerCount[mask] * 10_000 / maximum.MinerTotalCount
		}
		if minerBasisPoints > maximum.MinerAffectedBasisPoints {
			maximum.MinerAffectedBasisPoints = minerBasisPoints
			maximum.MinerAffectedCount = minerCount[mask]
		}
	}
	return maximum
}

func stageNamesForMask(mask int, stages []CompiledStage) []string {
	result := make([]string, 0, bits.OnesCount(uint(mask)))
	for index := range stages {
		if mask&(1<<index) != 0 {
			result = append(result, stages[index].ID)
		}
	}
	sort.Strings(result)
	return result
}

func stagesCanOverlap(indexes []int, stages []attacknetv1beta1.FaultStageSpec) bool {
	selected := make(map[string]struct{}, len(indexes))
	for _, index := range indexes {
		selected[stages[index].ID] = struct{}{}
	}
	for _, index := range indexes {
		for current := &stages[index]; current.Trigger.AfterStage != nil; {
			dependency := current.Trigger.AfterStage
			if dependency.State == "Recovered" || dependency.State == "Terminal" {
				if _, found := selected[dependency.Stage]; found {
					return false
				}
			}
			next := -1
			for candidate := range stages {
				if stages[candidate].ID == dependency.Stage {
					next = candidate
					break
				}
			}
			if next < 0 {
				break
			}
			current = &stages[next]
		}
	}
	return true
}

func mutationName(campaign, stage, action string) string {
	prefix := strings.Trim(strings.Join([]string{campaign, stage, action}, "-"), "-")
	if len(prefix) <= 63 {
		return prefix
	}
	digest := sha256.Sum256([]byte(prefix))
	return strings.TrimRight(prefix[:54], "-") + "-" + hex.EncodeToString(digest[:4])
}

func mergeLabels(left, right map[string]string) map[string]string {
	result := make(map[string]string, len(left)+len(right))
	for key, value := range left {
		result[key] = value
	}
	for key, value := range right {
		result[key] = value
	}
	return result
}
