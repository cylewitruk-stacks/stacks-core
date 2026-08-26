package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
)

func (r *V1Beta1Reconciler) deriveBetaSchedule(
	ctx context.Context,
	run *attacknetv1beta1.AttacknetRun,
	candidate betaSchedule,
	manifest fault.Manifest,
) (betaSchedule, error) {
	if run.Spec.Resume.Enabled {
		return r.deriveBetaResume(ctx, run, candidate)
	}
	sourceName := run.Spec.Replay.SourceRunRef
	if run.Spec.Minimization.Enabled {
		sourceName = run.Spec.Minimization.SourceRunRef
	}
	sourceRun, source, err := r.readBetaSourceRun(ctx, run.Namespace, sourceName)
	if err != nil {
		return betaSchedule{}, err
	}
	if source.Network.UID == candidate.Network.UID {
		return betaSchedule{}, errors.New("replay and minimization require a fresh network UID")
	}
	if !reflect.DeepEqual(source.ImageConstraints, candidate.ImageConstraints) {
		return betaSchedule{}, errors.New("resolved images differ from source schedule")
	}
	if !reflect.DeepEqual(source.Budgets, candidate.Budgets) {
		return betaSchedule{}, errors.New("replay and minimization budgets must equal immutable source budgets")
	}
	if err := validateBetaSourceTemplates(source.Executions, candidate.Executions); err != nil {
		return betaSchedule{}, err
	}
	if run.Spec.Replay.Enabled {
		expectedURI := fmt.Sprintf("k8s://attacknetruns/%s/resolved-schedule", sourceRun.Name)
		if run.Spec.Replay.DescriptorURI != expectedURI || run.Spec.Replay.DescriptorDigest != source.Integrity.Digest {
			return betaSchedule{}, errors.New("replay descriptor URI or digest does not match source schedule")
		}
	}
	result := source
	result.Run = candidate.Run
	result.Network = candidate.Network
	result.Budgets = candidate.Budgets
	result.ImageConstraints = candidate.ImageConstraints
	result.Replay = betaReplayMetadata{Enabled: true, Strategy: "resolved-schedule/v2", SourceRunRef: sourceRun.Name, SourceScheduleDigest: source.Integrity.Digest, FreshNetwork: true}
	result.Integrity = scheduleIntegrity{}
	if run.Spec.Minimization.Enabled {
		if run.Spec.Minimization.Strategy != "DeltaDebug" || run.Spec.Minimization.MaxAttempts != 1 || !run.Spec.Minimization.RequireFreshNetwork {
			return betaSchedule{}, errors.New("minimization must be one bounded fresh-network DeltaDebug attempt")
		}
		if run.Spec.Minimization.SourceScheduleDigest != source.Integrity.Digest {
			return betaSchedule{}, errors.New("minimization sourceScheduleDigest does not match source schedule")
		}
		result.Executions, err = minimizedBetaExecutions(source.Executions, run.Spec.Minimization.Retained)
		if err != nil {
			return betaSchedule{}, err
		}
		result.Replay.Strategy = "delta-debug-removal/v2"
	}
	if err := rebindBetaExecutionNetwork(result.Executions, candidate.Network.Name); err != nil {
		return betaSchedule{}, err
	}
	if run.Spec.Minimization.Enabled {
		if err := recomputeBetaExecutionBudgets(result.Executions, manifest, result.Budgets); err != nil {
			return betaSchedule{}, err
		}
	}
	result.ExecutionDigest, err = canonical.ArtifactDigest(result.Executions)
	if err != nil {
		return betaSchedule{}, err
	}
	sealed, err := sealBetaSchedule(result)
	if err != nil {
		return betaSchedule{}, err
	}
	if run.Spec.Minimization.Enabled && run.Spec.Minimization.CandidateScheduleDigest != "" && run.Spec.Minimization.CandidateScheduleDigest != sealed.Integrity.Digest {
		return betaSchedule{}, errors.New("minimization candidateScheduleDigest does not match the removal-only schedule")
	}
	return sealed, nil
}

func rebindBetaExecutionNetwork(executions []betaExecution, network string) error {
	if network == "" {
		return errors.New("replay target network is required")
	}
	for index := range executions {
		executions[index].CampaignSpec.NetworkRef = network
		digest, err := canonical.ArtifactDigest(executions[index].CampaignSpec)
		if err != nil {
			return err
		}
		executions[index].CampaignSpecDigest = digest
	}
	return nil
}

func recomputeBetaExecutionBudgets(executions []betaExecution, manifest fault.Manifest, budgets attacknetv1beta1.RunBudgets) error {
	for index := range executions {
		campaign := &attacknetv1beta1.FaultCampaign{
			ObjectMeta: metav1.ObjectMeta{Name: executions[index].Source.Name, UID: types.UID(executions[index].Source.UID)},
			Spec:       *executions[index].CampaignSpec.DeepCopy(),
		}
		compiled, err := fault.CompileV1Beta1(campaign, manifest)
		if err != nil {
			return fmt.Errorf("compile minimized execution %q: %w", executions[index].ID, err)
		}
		executions[index].MaximumActiveFaults = compiled.AggregateImpact.ConcurrentFaults
		executions[index].FaultDurationMillis = betaCampaignDurationMillis(campaign.Spec)
		executions[index].SignerImpactBasisPoints = compiled.AggregateImpact.SignerAffectedBasisPoints
		executions[index].BurnchainFaults = betaBurnchainFaults(compiled, manifest)
	}
	return validateBetaPlannedBudget(executions, budgets)
}

func validateBetaSourceTemplates(source, candidate []betaExecution) error {
	current := make(map[string]sourceIdentity, len(candidate))
	for _, execution := range candidate {
		if prior, duplicate := current[execution.Source.Name]; duplicate && prior != execution.Source {
			return fmt.Errorf("candidate campaign source %q has conflicting identities", execution.Source.Name)
		}
		current[execution.Source.Name] = execution.Source
	}
	for _, execution := range source {
		identity, found := current[execution.Source.Name]
		if !found || identity != execution.Source {
			return fmt.Errorf("source campaign template %q differs from current immutable identity", execution.Source.Name)
		}
	}
	return nil
}

func (r *V1Beta1Reconciler) deriveBetaResume(ctx context.Context, run *attacknetv1beta1.AttacknetRun, candidate betaSchedule) (betaSchedule, error) {
	sourceRun, source, err := r.readBetaSourceRun(ctx, run.Namespace, run.Spec.Resume.SourceRunRef)
	if err != nil {
		return betaSchedule{}, err
	}
	if run.Spec.Resume.RequireSameSeed && source.Run.Seed != candidate.Run.Seed {
		return betaSchedule{}, errors.New("resume seed differs from source schedule")
	}
	if run.Spec.Resume.RequireSameResolvedImages && !reflect.DeepEqual(source.ImageConstraints, candidate.ImageConstraints) {
		return betaSchedule{}, errors.New("resume images differ from source schedule")
	}
	_, completed, err := betaDecisions(sourceRun.Status.Decisions)
	if err != nil {
		return betaSchedule{}, fmt.Errorf("resume source decisions are invalid: %w", err)
	}
	if !completed[run.Spec.Resume.AfterExecutionID] {
		return betaSchedule{}, errors.New("resume boundary was not completed by source run")
	}
	boundary := -1
	for index, execution := range source.Executions {
		if execution.ID == run.Spec.Resume.AfterExecutionID {
			boundary = index
			break
		}
	}
	if boundary < 0 {
		return betaSchedule{}, errors.New("resume boundary is absent from source schedule")
	}
	expected := source.Executions[boundary+1:]
	if len(expected) != len(candidate.Executions) {
		return betaSchedule{}, errors.New("resume schedule differs from source suffix")
	}
	for index := range expected {
		if expected[index].ID != candidate.Executions[index].ID || expected[index].Source != candidate.Executions[index].Source || expected[index].CampaignSpecDigest != candidate.Executions[index].CampaignSpecDigest {
			return betaSchedule{}, fmt.Errorf("resume execution %d differs from immutable source suffix", index+1)
		}
		candidate.Executions[index].Dependencies = retainedResumeDependencies(candidate.Executions[index].Dependencies, completed)
	}
	candidate.Replay = betaReplayMetadata{Enabled: true, Strategy: "resume/v2", SourceRunRef: sourceRun.Name, SourceScheduleDigest: source.Integrity.Digest}
	candidate.ExecutionDigest, err = canonical.ArtifactDigest(candidate.Executions)
	if err != nil {
		return betaSchedule{}, err
	}
	candidate.Integrity = scheduleIntegrity{}
	return sealBetaSchedule(candidate)
}

func (r *V1Beta1Reconciler) readBetaSourceRun(ctx context.Context, namespace, name string) (*attacknetv1beta1.AttacknetRun, betaSchedule, error) {
	if name == "" {
		return nil, betaSchedule{}, errors.New("source run reference is required")
	}
	sourceRun := &attacknetv1beta1.AttacknetRun{}
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, sourceRun); err != nil {
		return nil, betaSchedule{}, err
	}
	if !betaTerminal(sourceRun.Status.Phase) || sourceRun.Status.ScheduleRef == nil {
		return nil, betaSchedule{}, errors.New("source run must be terminal with a persisted schedule")
	}
	source, err := r.store().read(ctx, sourceRun, *sourceRun.Status.ScheduleRef)
	return sourceRun, source, err
}

func minimizedBetaExecutions(source []betaExecution, retained []attacknetv1beta1.RetainedExecution) ([]betaExecution, error) {
	if len(retained) == 0 {
		return nil, errors.New("minimization must retain at least one execution")
	}
	sourceByID := make(map[string]betaExecution, len(source))
	order := make(map[string]int, len(source))
	for index, execution := range source {
		sourceByID[execution.ID], order[execution.ID] = execution, index
	}
	result := make([]betaExecution, 0, len(retained))
	seen := map[string]bool{}
	previous := -1
	materialRemoval := len(retained) < len(source)
	for _, rule := range retained {
		execution, found := sourceByID[rule.ExecutionID]
		if !found || seen[rule.ExecutionID] {
			return nil, fmt.Errorf("minimization references unknown or duplicate execution %q", rule.ExecutionID)
		}
		if order[rule.ExecutionID] <= previous {
			return nil, errors.New("minimization may not reorder source executions")
		}
		seen[rule.ExecutionID], previous = true, order[rule.ExecutionID]
		modified, changed, err := minimizeBetaCampaign(execution.CampaignSpec, rule)
		if err != nil {
			return nil, fmt.Errorf("execution %q: %w", execution.ID, err)
		}
		materialRemoval = materialRemoval || changed
		execution.CampaignSpec = modified
		execution.CampaignSpecDigest, err = canonical.ArtifactDigest(modified)
		if err != nil {
			return nil, err
		}
		execution.FaultDurationMillis = betaCampaignDurationMillis(modified)
		result = append(result, execution)
	}
	if !materialRemoval {
		return nil, errors.New("minimization candidate must remove schedule material")
	}
	retainedIDs := map[string]bool{}
	for _, execution := range result {
		retainedIDs[execution.ID] = true
	}
	for index := range result {
		dependencies := result[index].Dependencies[:0]
		for _, dependency := range result[index].Dependencies {
			if retainedIDs[dependency.Execution] {
				dependencies = append(dependencies, dependency)
			}
		}
		result[index].Dependencies = dependencies
	}
	return result, nil
}

func minimizeBetaCampaign(spec attacknetv1beta1.FaultCampaignSpec, rule attacknetv1beta1.RetainedExecution) (attacknetv1beta1.FaultCampaignSpec, bool, error) {
	result := *spec.DeepCopy()
	removedStages := stringSet(rule.RemovedStages)
	removedActions := stringSet(rule.RemovedActions)
	removedTargets := stringSet(rule.RemovedTargets)
	removedParameters := stringSet(rule.RemovedParameters)
	changed := len(removedStages)+len(removedActions)+len(removedTargets)+len(removedParameters) > 0
	stages := result.Stages[:0]
	for _, stage := range result.Stages {
		if removedStages[stage.ID] {
			continue
		}
		actions := stage.Faults[:0]
		for _, action := range stage.Faults {
			qualified := stage.ID + "/" + action.ID
			if removedActions[action.ID] || removedActions[qualified] {
				continue
			}
			actors := action.Target.Actors[:0]
			for _, actor := range action.Target.Actors {
				if !removedTargets[actor] && !removedTargets[qualified+"/"+actor] {
					actors = append(actors, actor)
				}
			}
			action.Target.Actors = actors
			if len(removedParameters) > 0 && len(action.Fault.Parameters.Raw) > 0 {
				parameters := map[string]any{}
				if err := json.Unmarshal(action.Fault.Parameters.Raw, &parameters); err != nil {
					return result, false, err
				}
				for parameter := range removedParameters {
					delete(parameters, strings.TrimPrefix(parameter, qualified+"/"))
				}
				encoded, err := json.Marshal(parameters)
				if err != nil {
					return result, false, err
				}
				action.Fault.Parameters.Raw = encoded
			}
			if len(action.Target.Actors) == 0 && len(action.Target.Roles) == 0 {
				return result, false, fmt.Errorf("removal leaves action %s with no targets", qualified)
			}
			actions = append(actions, action)
		}
		stage.Faults = actions
		if len(stage.Faults) == 0 {
			return result, false, fmt.Errorf("removal leaves stage %s with no actions", stage.ID)
		}
		stages = append(stages, stage)
	}
	result.Stages = stages
	if len(result.Stages) == 0 {
		return result, false, errors.New("removal leaves campaign with no stages")
	}
	return result, changed, nil
}

func retainedResumeDependencies(value []attacknetv1beta1.RunExecutionDependency, completed map[string]bool) []attacknetv1beta1.RunExecutionDependency {
	result := make([]attacknetv1beta1.RunExecutionDependency, 0, len(value))
	for _, dependency := range value {
		if !completed[dependency.Execution] {
			result = append(result, dependency)
		}
	}
	return result
}
