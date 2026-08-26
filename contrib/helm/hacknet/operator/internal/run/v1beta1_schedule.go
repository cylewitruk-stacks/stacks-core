package run

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

const (
	betaScheduleSchema    = "stacks-attacknet-schedule/v2"
	betaDecisionAlgorithm = "dependency-trigger-scheduler/v1"
)

// betaSchedule is the immutable execution input persisted before a run starts.
type betaSchedule struct {
	SchemaVersion    string                      `json:"schemaVersion"`
	Run              betaScheduleRun             `json:"run"`
	Network          betaScheduleNetwork         `json:"network"`
	CatalogDigest    string                      `json:"catalogDigest"`
	ExecutionDigest  string                      `json:"executionDigest"`
	ImageConstraints []imageConstraint           `json:"imageConstraints"`
	Executions       []betaExecution             `json:"executions"`
	Budgets          attacknetv1beta1.RunBudgets `json:"budgets"`
	Replay           betaReplayMetadata          `json:"replay"`
	Integrity        scheduleIntegrity           `json:"integrity,omitempty"`
}

type betaScheduleRun struct {
	Name              string `json:"name"`
	Seed              string `json:"seed"`
	DecisionAlgorithm string `json:"decisionAlgorithm"`
}

type betaScheduleNetwork struct {
	Name           string                            `json:"name"`
	UID            string                            `json:"uid"`
	Generation     int64                             `json:"generation"`
	Inventory      attacknetv1beta1.NetworkInventory `json:"inventory"`
	ManifestDigest string                            `json:"manifestDigest"`
}

type betaExecution struct {
	ID                      string                                    `json:"id"`
	CampaignAlias           string                                    `json:"campaignAlias"`
	Source                  sourceIdentity                            `json:"source"`
	Trigger                 attacknetv1beta1.RunTriggerSpec           `json:"trigger"`
	Dependencies            []attacknetv1beta1.RunExecutionDependency `json:"dependencies,omitempty"`
	CampaignSpec            attacknetv1beta1.FaultCampaignSpec        `json:"campaignSpec"`
	CampaignSpecDigest      string                                    `json:"campaignSpecDigest"`
	MaximumActiveFaults     int32                                     `json:"maximumActiveFaults"`
	FaultDurationMillis     int64                                     `json:"faultDurationMillis"`
	SignerImpactBasisPoints int32                                     `json:"signerImpactBasisPoints"`
	BurnchainFaults         int32                                     `json:"burnchainFaults"`
}

type betaReplayMetadata struct {
	Enabled              bool   `json:"enabled"`
	Strategy             string `json:"strategy,omitempty"`
	SourceRunRef         string `json:"sourceRunRef,omitempty"`
	SourceScheduleDigest string `json:"sourceScheduleDigest,omitempty"`
	FreshNetwork         bool   `json:"freshNetwork,omitempty"`
}

func buildBetaSchedule(
	run *attacknetv1beta1.AttacknetRun,
	network *attacknetv1beta1.StacksNetwork,
	published attacknetv1beta1.NetworkInventory,
	templates map[string]*attacknetv1beta1.FaultCampaign,
	manifest fault.Manifest,
) (betaSchedule, error) {
	if err := ValidateV1Beta1Structure(run); err != nil {
		return betaSchedule{}, err
	}
	algorithm := run.Spec.DecisionAlgorithm
	if algorithm == "" {
		algorithm = betaDecisionAlgorithm
	}
	if algorithm != betaDecisionAlgorithm {
		return betaSchedule{}, fmt.Errorf("unsupported decision algorithm %q", algorithm)
	}
	if err := validateBetaRunBudgets(run.Spec.Budgets); err != nil {
		return betaSchedule{}, err
	}
	if err := validateBetaRunPolicies(run.Spec.StopPolicy, run.Spec.AttributionPolicy); err != nil {
		return betaSchedule{}, err
	}
	catalog := make(map[string]attacknetv1beta1.CampaignCatalogEntry, len(run.Spec.CampaignCatalog))
	for _, entry := range run.Spec.CampaignCatalog {
		if entry.Name == "" || entry.CampaignRef == "" {
			return betaSchedule{}, errors.New("campaign catalog names and references must be non-empty")
		}
		if _, duplicate := catalog[entry.Name]; duplicate {
			return betaSchedule{}, fmt.Errorf("duplicate campaign alias %q", entry.Name)
		}
		catalog[entry.Name] = entry
	}
	if len(catalog) == 0 {
		return betaSchedule{}, errors.New("campaign catalog must not be empty")
	}

	executionIDs := make(map[string]int, len(run.Spec.Executions))
	enabledExecutions := make(map[string]bool, len(run.Spec.Executions))
	for index, execution := range run.Spec.Executions {
		if execution.ID == "" || execution.Campaign == "" {
			return betaSchedule{}, errors.New("execution IDs and campaign aliases must be non-empty")
		}
		if _, duplicate := executionIDs[execution.ID]; duplicate {
			return betaSchedule{}, fmt.Errorf("duplicate execution ID %q", execution.ID)
		}
		executionIDs[execution.ID] = index
		enabledExecutions[execution.ID] = execution.Enabled == nil || *execution.Enabled
	}

	images := betaImageConstraints(published)
	executions := make([]betaExecution, 0, len(run.Spec.Executions))
	clockTargets := make(map[string]map[string]struct{}, len(run.Spec.Executions))
	for index, execution := range run.Spec.Executions {
		if execution.Enabled != nil && !*execution.Enabled {
			continue
		}
		if _, err := trigger.ForRunExecution(execution); err != nil {
			return betaSchedule{}, err
		}
		for _, dependency := range execution.DependsOn {
			dependencyIndex, found := executionIDs[dependency.Execution]
			if !found {
				return betaSchedule{}, fmt.Errorf("execution %q depends on unknown execution %q", execution.ID, dependency.Execution)
			}
			if dependencyIndex >= index {
				return betaSchedule{}, fmt.Errorf("execution %q must depend on an earlier execution, got %q", execution.ID, dependency.Execution)
			}
			if !enabledExecutions[dependency.Execution] {
				return betaSchedule{}, fmt.Errorf("execution %q depends on disabled execution %q", execution.ID, dependency.Execution)
			}
			if dependency.State != string(trigger.DependencyInjected) && dependency.State != string(trigger.DependencyEffective) && dependency.State != string(trigger.DependencyRecovered) && dependency.State != string(trigger.DependencyTerminal) {
				return betaSchedule{}, fmt.Errorf("execution %q dependency state must be Injected, Effective, Recovered, or Terminal", execution.ID)
			}
		}
		entry, found := catalog[execution.Campaign]
		if !found {
			return betaSchedule{}, fmt.Errorf("execution %q references unknown campaign alias %q", execution.ID, execution.Campaign)
		}
		source := templates[entry.CampaignRef]
		if source == nil || !source.Spec.Template {
			return betaSchedule{}, fmt.Errorf("campaign source %q is absent or is not a template", entry.CampaignRef)
		}
		if source.Spec.NetworkRef != "" && source.Spec.NetworkRef != run.Spec.NetworkRef {
			return betaSchedule{}, fmt.Errorf("campaign source %q targets another network", source.Name)
		}
		sourceDigest, err := canonical.ArtifactDigest(source.Spec)
		if err != nil {
			return betaSchedule{}, err
		}
		if entry.ExpectedUID != "" && entry.ExpectedUID != string(source.UID) {
			return betaSchedule{}, fmt.Errorf("campaign %q UID constraint does not match", entry.Name)
		}
		if entry.ExpectedGeneration != nil && *entry.ExpectedGeneration != source.Generation {
			return betaSchedule{}, fmt.Errorf("campaign %q generation constraint does not match", entry.Name)
		}
		if entry.ExpectedSpecDigest != "" && entry.ExpectedSpecDigest != sourceDigest {
			return betaSchedule{}, fmt.Errorf("campaign %q digest constraint does not match", entry.Name)
		}
		campaignSpec := *source.Spec.DeepCopy()
		campaignSpec.Template = false
		campaignSpec.NetworkRef = run.Spec.NetworkRef
		resolved := source.DeepCopy()
		resolved.Spec = campaignSpec
		compiled, err := fault.CompileV1Beta1(resolved, manifest)
		if err != nil {
			return betaSchedule{}, fmt.Errorf("compile campaign %q: %w", source.Name, err)
		}
		campaignDigest, err := canonical.ArtifactDigest(campaignSpec)
		if err != nil {
			return betaSchedule{}, err
		}
		executions = append(executions, betaExecution{
			ID: execution.ID, CampaignAlias: execution.Campaign,
			Source:  sourceIdentity{Name: source.Name, UID: string(source.UID), Generation: source.Generation, SpecDigest: sourceDigest},
			Trigger: *execution.Trigger.DeepCopy(), Dependencies: append([]attacknetv1beta1.RunExecutionDependency(nil), execution.DependsOn...),
			CampaignSpec: campaignSpec, CampaignSpecDigest: campaignDigest,
			MaximumActiveFaults:     compiled.AggregateImpact.ConcurrentFaults,
			FaultDurationMillis:     betaCampaignDurationMillis(campaignSpec),
			SignerImpactBasisPoints: compiled.AggregateImpact.SignerAffectedBasisPoints,
			BurnchainFaults:         betaBurnchainFaults(compiled, manifest),
		})
		clockTargets[execution.ID] = betaClockTargets(compiled)
	}
	if len(executions) == 0 {
		return betaSchedule{}, errors.New("run resolves to no enabled executions")
	}
	if int32(len(executions)) > run.Spec.Budgets.MaxCampaigns {
		return betaSchedule{}, fmt.Errorf("resolved campaign count %d exceeds budget %d", len(executions), run.Spec.Budgets.MaxCampaigns)
	}
	if err := validateBetaPlannedBudget(executions, run.Spec.Budgets); err != nil {
		return betaSchedule{}, err
	}
	if err := validateBetaCrossExecutionCompatibility(executions, clockTargets); err != nil {
		return betaSchedule{}, err
	}
	catalogDigest, err := canonical.ArtifactDigest(normalizedBetaCatalog(run.Spec.CampaignCatalog))
	if err != nil {
		return betaSchedule{}, err
	}
	executionDigest, err := canonical.ArtifactDigest(normalizedBetaExecutions(run.Spec.Executions))
	if err != nil {
		return betaSchedule{}, err
	}
	manifestDigest, err := canonical.ArtifactDigest(manifest)
	if err != nil {
		return betaSchedule{}, err
	}
	schedule := betaSchedule{
		SchemaVersion: betaScheduleSchema,
		Run:           betaScheduleRun{Name: run.Name, Seed: run.Spec.Seed, DecisionAlgorithm: algorithm},
		Network: betaScheduleNetwork{
			Name: network.Name, UID: string(network.UID), Generation: network.Generation,
			Inventory: published, ManifestDigest: manifestDigest,
		},
		CatalogDigest: catalogDigest, ExecutionDigest: executionDigest,
		ImageConstraints: images, Executions: executions, Budgets: run.Spec.Budgets,
		Replay: betaReplayMetadata{},
	}
	return sealBetaSchedule(schedule)
}

func sealBetaSchedule(schedule betaSchedule) (betaSchedule, error) {
	schedule.Integrity = scheduleIntegrity{Algorithm: "sha256-canonical-json/v1"}
	digest, err := canonical.ArtifactDigest(schedule)
	if err != nil {
		return betaSchedule{}, err
	}
	schedule.Integrity.Digest = digest
	return schedule, validateBetaSchedule(schedule)
}

func validateBetaSchedule(schedule betaSchedule) error {
	if schedule.SchemaVersion != betaScheduleSchema || schedule.Integrity.Algorithm != "sha256-canonical-json/v1" || schedule.Integrity.Digest == "" {
		return errors.New("resolved schedule has unsupported schema or integrity metadata")
	}
	expected := schedule.Integrity.Digest
	schedule.Integrity.Digest = ""
	digest, err := canonical.ArtifactDigest(schedule)
	if err != nil {
		return err
	}
	if digest != expected {
		return errors.New("resolved schedule digest does not match its contents")
	}
	return nil
}

func validateBetaRunBudgets(value attacknetv1beta1.RunBudgets) error {
	switch {
	case value.MaxCampaigns < 1 || value.MaxCampaigns > 1024:
		return errors.New("maxCampaigns must be within 1..1024")
	case value.MaxWallTimeSeconds < 1 || value.MaxWallTimeSeconds > 604800:
		return errors.New("maxWallTimeSeconds must be within 1..604800")
	case value.MaxCumulativeFaultSeconds < 1 || value.MaxCumulativeFaultSeconds > 604800:
		return errors.New("maxCumulativeFaultSeconds must be within 1..604800")
	case value.MaxActiveFaults < 1 || value.MaxActiveFaults > 512:
		return errors.New("maxActiveFaults must be within 1..512")
	case value.MaxSignerImpactPercent < 0 || value.MaxSignerImpactPercent > 100:
		return errors.New("maxSignerImpactPercent must be between zero and 100")
	case value.MaxBurnchainFaults < 0 || value.MaxBurnchainFaults > 10:
		return errors.New("maxBurnchainFaults must be within 0..10")
	case value.MaxInconclusiveCampaigns < 0 || value.MaxInconclusiveCampaigns > 64:
		return errors.New("maxInconclusiveCampaigns must be within 0..64")
	}
	return nil
}

func validateBetaRunPolicies(stop attacknetv1beta1.StopPolicy, attribution attacknetv1beta1.AttributionPolicy) error {
	if stop.OnCampaignFailure != "Continue" && stop.OnCampaignFailure != "Stop" && stop.OnCampaignFailure != "PauseForTriage" {
		return errors.New("onCampaignFailure must be Continue, Stop, or PauseForTriage")
	}
	if stop.OnInconclusive != "Continue" && stop.OnInconclusive != "Stop" && stop.OnInconclusive != "PauseForTriage" {
		return errors.New("onInconclusive must be Continue, Stop, or PauseForTriage")
	}
	if stop.OnBudgetExhausted != "Stop" && stop.OnBudgetExhausted != "Pause" {
		return errors.New("onBudgetExhausted must be Stop or Pause")
	}
	if stop.OnSuccess != "Continue" && stop.OnSuccess != "Stop" {
		return errors.New("onSuccess must be Continue or Stop")
	}
	seen := map[string]bool{}
	for _, phase := range attribution.AllowedTerminalStates {
		if phase != "Triaged" && phase != "Remediated" && phase != "Inconclusive" {
			return fmt.Errorf("unsupported allowed terminal state %q", phase)
		}
		if seen[phase] {
			return fmt.Errorf("duplicate allowed terminal state %q", phase)
		}
		seen[phase] = true
	}
	return nil
}

func validateBetaPlannedBudget(executions []betaExecution, limits attacknetv1beta1.RunBudgets) error {
	var cumulativeMillis int64
	var burnchainFaults int32
	for _, execution := range executions {
		cumulativeMillis += execution.FaultDurationMillis
		burnchainFaults += execution.BurnchainFaults
		if execution.SignerImpactBasisPoints > limits.MaxSignerImpactPercent*100 {
			return fmt.Errorf("execution %q signer impact %d basis points exceeds run budget", execution.ID, execution.SignerImpactBasisPoints)
		}
		if execution.MaximumActiveFaults > limits.MaxActiveFaults {
			return fmt.Errorf("execution %q requires %d active faults, exceeding run budget %d", execution.ID, execution.MaximumActiveFaults, limits.MaxActiveFaults)
		}
	}
	if cumulativeMillis > int64(limits.MaxCumulativeFaultSeconds)*1000 {
		return errors.New("planned cumulative fault duration exceeds run budget")
	}
	if burnchainFaults > limits.MaxBurnchainFaults {
		return errors.New("planned burnchain fault count exceeds run budget")
	}
	return nil
}

func betaCampaignDurationMillis(spec attacknetv1beta1.FaultCampaignSpec) int64 {
	var total time.Duration
	for _, stage := range spec.Stages {
		for _, action := range stage.Faults {
			total += action.Fault.Duration.Duration
		}
	}
	return total.Milliseconds()
}

func betaBurnchainFaults(compiled fault.CompiledCampaign, manifest fault.Manifest) int32 {
	roles := make(map[string]string, len(manifest.Actors))
	for _, actor := range manifest.Actors {
		roles[actor.Name] = actor.Role
	}
	var count int32
	for _, stage := range compiled.Stages {
		for _, action := range stage.Actions {
			for _, actor := range action.Evidence.SelectedActors {
				if roles[actor] == "burnchain" {
					count++
					break
				}
			}
		}
	}
	return count
}

func betaClockTargets(compiled fault.CompiledCampaign) map[string]struct{} {
	result := map[string]struct{}{}
	for _, stage := range compiled.Stages {
		for _, action := range stage.Actions {
			if action.Resource.GetKind() != "ClockSkewPolicy" {
				continue
			}
			for _, actor := range action.Evidence.SelectedActors {
				result[actor] = struct{}{}
			}
		}
	}
	return result
}

// validateBetaCrossExecutionCompatibility rejects shared-resource mutations
// that can overlap even though each source campaign is independently valid.
func validateBetaCrossExecutionCompatibility(executions []betaExecution, clockTargets map[string]map[string]struct{}) error {
	terminalBefore := make(map[string]map[string]struct{}, len(executions))
	for _, execution := range executions {
		predecessors := map[string]struct{}{}
		for _, dependency := range execution.Dependencies {
			for predecessor := range terminalBefore[dependency.Execution] {
				predecessors[predecessor] = struct{}{}
			}
			if dependency.State == string(trigger.DependencyTerminal) {
				predecessors[dependency.Execution] = struct{}{}
			}
		}
		terminalBefore[execution.ID] = predecessors
	}
	for left := 0; left < len(executions); left++ {
		for right := left + 1; right < len(executions); right++ {
			leftID, rightID := executions[left].ID, executions[right].ID
			if contains(terminalBefore[rightID], leftID) || contains(terminalBefore[leftID], rightID) {
				continue
			}
			for actor := range clockTargets[leftID] {
				if contains(clockTargets[rightID], actor) {
					return fmt.Errorf("executions %q and %q can overlap clock-skew mutations for actor %q", leftID, rightID, actor)
				}
			}
		}
	}
	return nil
}

func contains(values map[string]struct{}, value string) bool {
	_, found := values[value]
	return found
}

func betaImageConstraints(inventory attacknetv1beta1.NetworkInventory) []imageConstraint {
	result := make([]imageConstraint, 0, len(inventory.Actors))
	for _, actor := range inventory.Actors {
		result = append(result, imageConstraint{Scope: actor.Name, RequestedRef: actor.RequestedImage, ResolvedRef: actor.RuntimeImageID, ResolvedDigest: digestIn(actor.RuntimeImageID)})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Scope < result[right].Scope })
	return result
}

func normalizedBetaCatalog(value []attacknetv1beta1.CampaignCatalogEntry) []attacknetv1beta1.CampaignCatalogEntry {
	result := append([]attacknetv1beta1.CampaignCatalogEntry(nil), value...)
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}

func normalizedBetaExecutions(value []attacknetv1beta1.RunExecutionSpec) []attacknetv1beta1.RunExecutionSpec {
	result := make([]attacknetv1beta1.RunExecutionSpec, len(value))
	for index := range value {
		result[index] = *value[index].DeepCopy()
		if result[index].Enabled == nil {
			result[index].Enabled = ptr(true)
		}
		sort.Slice(result[index].DependsOn, func(left, right int) bool {
			return result[index].DependsOn[left].Execution < result[index].DependsOn[right].Execution
		})
	}
	// Execution declaration order is semantically meaningful for deterministic
	// tie-breaking, so only dependency lists are normalized.
	return result
}

func executionByID(schedule betaSchedule, id string) (betaExecution, bool) {
	for _, execution := range schedule.Executions {
		if execution.ID == id {
			return execution, true
		}
	}
	return betaExecution{}, false
}

func betaChildName(runName, executionID string) string {
	return stableName(runName, "execution", strings.ToLower(executionID))
}
