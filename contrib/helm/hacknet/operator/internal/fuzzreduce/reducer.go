// Package fuzzreduce plans bounded hierarchical removal-only experiments.
// Controller admission remains authoritative for every emitted candidate.
package fuzzreduce

import (
	"errors"
	"fmt"
	"sort"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const Algorithm = "deterministic-hierarchical-ddmin/v1"

// Outcome is the trusted confirmation result of one candidate.
type Outcome string

const (
	OutcomeReproduced    Outcome = "Reproduced"
	OutcomeNotReproduced Outcome = "NotReproduced"
	OutcomeInconclusive  Outcome = "Inconclusive"
)

// SourceAction describes removable material without exposing mutation logic.
type SourceAction struct {
	ID             string   `json:"id"`
	Actors         []string `json:"actors,omitempty"`
	HasRoleTargets bool     `json:"hasRoleTargets,omitempty"`
}

// SourceStage describes one ordered fault stage.
type SourceStage struct {
	ID        string         `json:"id"`
	DependsOn string         `json:"dependsOn,omitempty"`
	Actions   []SourceAction `json:"actions"`
}

// SourceExecution describes one ordered fault execution.
type SourceExecution struct {
	ID     string        `json:"id"`
	Stages []SourceStage `json:"stages"`
}

// SourceFromRun translates one fault-only materialized run and its immutable
// template specifications into the reducer's structural model. Mixed upgrade
// schedules are intentionally rejected because changing version context is
// not a removal-only fault reduction.
func SourceFromRun(
	executions []attacknetv1beta1.RunExecutionSpec,
	campaigns map[string]attacknetv1beta1.FaultCampaignSpec,
) ([]SourceExecution, error) {
	if len(executions) == 0 {
		return nil, errors.New("source run has no executions")
	}
	result := make([]SourceExecution, 0, len(executions))
	for _, execution := range executions {
		if execution.Upgrade != "" || execution.Campaign == "" {
			return nil, errors.New("automatic reduction supports fault-only schedules")
		}
		spec, found := campaigns[execution.Campaign]
		if !found || len(spec.Stages) == 0 {
			return nil, fmt.Errorf("execution %s has no retained fault template", execution.ID)
		}
		source := SourceExecution{ID: execution.ID}
		for _, stage := range spec.Stages {
			item := SourceStage{ID: stage.ID}
			if stage.Trigger.AfterStage != nil {
				item.DependsOn = stage.Trigger.AfterStage.Stage
			}
			for _, action := range stage.Faults {
				actors := append([]string(nil), action.Target.Actors...)
				sort.Strings(actors)
				item.Actions = append(item.Actions, SourceAction{
					ID: action.ID, Actors: actors,
					HasRoleTargets: len(action.Target.Roles) > 0,
				})
			}
			source.Stages = append(source.Stages, item)
		}
		result = append(result, source)
	}
	return result, nil
}

// Candidate is one controller-validatable removal request.
type Candidate struct {
	Algorithm string                               `json:"algorithm"`
	Attempt   int32                                `json:"attempt"`
	Level     string                               `json:"level"`
	Retained  []attacknetv1beta1.RetainedExecution `json:"retained"`
	Digest    string                               `json:"digest"`
}

// Attempt records every evaluated candidate, including ambiguity.
type Attempt struct {
	Candidate Candidate `json:"candidate"`
	Outcome   Outcome   `json:"outcome"`
}

// Result is the best confirmed removal found within bounds.
type Result struct {
	Algorithm               string                               `json:"algorithm"`
	SourceDigest            string                               `json:"sourceDigest"`
	Retained                []attacknetv1beta1.RetainedExecution `json:"retained"`
	Attempts                []Attempt                            `json:"attempts"`
	CausalMinimalityClaimed bool                                 `json:"causalMinimalityClaimed"`
}

type atom struct {
	execution string
	stage     string
	action    string
	value     string
}

// Reducer is one deterministic adaptive ddmin state machine.
type Reducer struct {
	source       []SourceExecution
	sourceDigest string
	current      []attacknetv1beta1.RetainedExecution
	maxAttempts  int32
	attempts     []Attempt
	level        int
	granularity  int
	chunks       [][]atom
	nextChunk    int
	pending      *Candidate
}

// Keep the v1 algorithm identity: the previously listed parameter level never
// emitted a candidate. Automatic parameter reduction remains deferred until a
// fault mechanism can register and validate monotone semantics.
var levels = []string{"execution", "stage", "action", "actor"}

// New validates and initializes a removal-only reducer.
func New(source []SourceExecution, maximumAttempts int32) (*Reducer, error) {
	if len(source) < 1 || len(source) > 1024 ||
		maximumAttempts < 1 || maximumAttempts > 1024 {
		return nil, errors.New("source and maximum attempts must be within 1..1024")
	}
	copySource := deepCopySource(source)
	seen := map[string]struct{}{}
	retained := make([]attacknetv1beta1.RetainedExecution, 0, len(copySource))
	for _, execution := range copySource {
		if _, duplicate := seen[execution.ID]; duplicate {
			return nil, fmt.Errorf("duplicate execution %s", execution.ID)
		}
		seen[execution.ID] = struct{}{}
		if err := validateSourceExecution(execution); err != nil {
			return nil, err
		}
		retained = append(retained, attacknetv1beta1.RetainedExecution{ExecutionID: execution.ID})
	}
	digest, err := canonical.Digest(copySource)
	if err != nil {
		return nil, err
	}
	return &Reducer{
		source: copySource, sourceDigest: digest, current: retained,
		maxAttempts: maximumAttempts, granularity: 2,
	}, nil
}

// Next returns the next candidate or nil when the bound or hierarchy is
// exhausted. Record must be called exactly once before requesting another.
func (reducer *Reducer) Next() (*Candidate, error) {
	if reducer.pending != nil {
		return nil, errors.New("previous reduction candidate has no recorded outcome")
	}
	if int32(len(reducer.attempts)) >= reducer.maxAttempts {
		return nil, nil
	}
	for reducer.level < len(levels) {
		if reducer.chunks == nil {
			atoms := reducer.atoms(levels[reducer.level])
			if len(atoms) == 0 || levels[reducer.level] == "execution" && len(atoms) == 1 {
				reducer.advanceLevel()
				continue
			}
			if reducer.granularity > len(atoms) {
				reducer.advanceLevel()
				continue
			}
			reducer.chunks = partition(atoms, reducer.granularity)
		}
		for reducer.nextChunk < len(reducer.chunks) {
			removed := reducer.chunks[reducer.nextChunk]
			reducer.nextChunk++
			retained, material := reducer.remove(levels[reducer.level], removed)
			if !material || len(retained) == 0 || !reducer.validRetained(retained) {
				continue
			}
			candidate := Candidate{
				Algorithm: Algorithm, Attempt: int32(len(reducer.attempts) + 1),
				Level: levels[reducer.level], Retained: retained,
			}
			// Candidate identity covers exactly the executable removal request.
			// Algorithm, attempt, and level remain provenance in the reduction graph,
			// while the admitted fresh-network schedule receives its own digest.
			digest, err := canonical.Digest(candidate.Retained)
			if err != nil {
				return nil, err
			}
			candidate.Digest = digest
			reducer.pending = &candidate
			return &candidate, nil
		}
		atomCount := len(reducer.atoms(levels[reducer.level]))
		if reducer.granularity < atomCount {
			reducer.granularity *= 2
			if reducer.granularity > atomCount {
				reducer.granularity = atomCount
			}
			reducer.chunks = nil
			reducer.nextChunk = 0
			continue
		}
		reducer.advanceLevel()
	}
	return nil, nil
}

// Record advances the reducer using one trusted fresh-network outcome.
func (reducer *Reducer) Record(outcome Outcome) error {
	if reducer.pending == nil {
		return errors.New("no reduction candidate is pending")
	}
	switch outcome {
	case OutcomeReproduced, OutcomeNotReproduced, OutcomeInconclusive:
	default:
		return errors.New("unsupported reduction outcome")
	}
	reducer.attempts = append(reducer.attempts, Attempt{Candidate: *reducer.pending, Outcome: outcome})
	if outcome == OutcomeReproduced {
		reducer.current = deepCopyRetained(reducer.pending.Retained)
		reducer.granularity = 2
		reducer.chunks = nil
		reducer.nextChunk = 0
	}
	reducer.pending = nil
	return nil
}

// Result returns the complete bounded graph and never claims causality.
func (reducer *Reducer) Result() Result {
	return Result{
		Algorithm: Algorithm, SourceDigest: reducer.sourceDigest,
		Retained:                deepCopyRetained(reducer.current),
		Attempts:                append([]Attempt(nil), reducer.attempts...),
		CausalMinimalityClaimed: false,
	}
}

func (reducer *Reducer) advanceLevel() {
	reducer.level++
	reducer.granularity = 2
	reducer.chunks = nil
	reducer.nextChunk = 0
}

func (reducer *Reducer) atoms(level string) []atom {
	active := activeSet(reducer.current)
	result := []atom{}
	for _, execution := range reducer.source {
		rule, retained := active[execution.ID]
		if !retained {
			continue
		}
		if level == "execution" {
			result = append(result, atom{execution: execution.ID})
			continue
		}
		removedStages := stringSet(rule.RemovedStages)
		removedActions := stringSet(rule.RemovedActions)
		removedTargets := stringSet(rule.RemovedTargets)
		for _, stage := range execution.Stages {
			if removedStages[stage.ID] {
				continue
			}
			if level == "stage" {
				result = append(result, atom{execution: execution.ID, stage: stage.ID})
				continue
			}
			for _, action := range stage.Actions {
				qualified := stage.ID + "/" + action.ID
				if removedActions[qualified] {
					continue
				}
				switch level {
				case "action":
					result = append(result, atom{execution: execution.ID, stage: stage.ID, action: action.ID})
				case "actor":
					for _, actor := range action.Actors {
						key := qualified + "/" + actor
						if !removedTargets[key] {
							result = append(result, atom{execution: execution.ID, stage: stage.ID, action: action.ID, value: actor})
						}
					}
				}
			}
		}
	}
	return result
}

func (reducer *Reducer) remove(level string, removed []atom) ([]attacknetv1beta1.RetainedExecution, bool) {
	result := deepCopyRetained(reducer.current)
	byExecution := activeSet(result)
	material := false
	for _, item := range removed {
		rule, found := byExecution[item.execution]
		if !found {
			continue
		}
		switch level {
		case "execution":
			delete(byExecution, item.execution)
		case "stage":
			rule.RemovedStages = append(rule.RemovedStages, item.stage)
		case "action":
			rule.RemovedActions = append(rule.RemovedActions, item.stage+"/"+item.action)
		case "actor":
			rule.RemovedTargets = append(rule.RemovedTargets, item.stage+"/"+item.action+"/"+item.value)
		}
		if level != "execution" {
			byExecution[item.execution] = rule
		}
		material = true
	}
	if level == "stage" {
		for executionID, rule := range byExecution {
			source, found := reducer.sourceExecution(executionID)
			if !found {
				continue
			}
			removedStages := stringSet(rule.RemovedStages)
			for changed := true; changed; {
				changed = false
				for _, stage := range source.Stages {
					if stage.DependsOn != "" && removedStages[stage.DependsOn] && !removedStages[stage.ID] {
						removedStages[stage.ID] = true
						changed = true
					}
				}
			}
			rule.RemovedStages = sortedKeys(removedStages)
			byExecution[executionID] = rule
		}
	}
	result = result[:0]
	for _, execution := range reducer.source {
		if rule, retained := byExecution[execution.ID]; retained {
			rule.RemovedStages = sortedKeys(stringSet(rule.RemovedStages))
			rule.RemovedActions = sortedKeys(stringSet(rule.RemovedActions))
			rule.RemovedTargets = sortedKeys(stringSet(rule.RemovedTargets))
			result = append(result, rule)
		}
	}
	return result, material
}

func (reducer *Reducer) validRetained(retained []attacknetv1beta1.RetainedExecution) bool {
	for _, rule := range retained {
		execution, found := reducer.sourceExecution(rule.ExecutionID)
		if !found {
			return false
		}
		removedStages := stringSet(rule.RemovedStages)
		removedActions := stringSet(rule.RemovedActions)
		removedTargets := stringSet(rule.RemovedTargets)
		stages := 0
		for _, stage := range execution.Stages {
			if removedStages[stage.ID] {
				continue
			}
			if stage.DependsOn != "" && removedStages[stage.DependsOn] {
				return false
			}
			stages++
			actions := 0
			for _, action := range stage.Actions {
				qualified := stage.ID + "/" + action.ID
				if removedActions[qualified] {
					continue
				}
				actions++
				actors := 0
				for _, actor := range action.Actors {
					if !removedTargets[qualified+"/"+actor] {
						actors++
					}
				}
				if actors == 0 && !action.HasRoleTargets {
					return false
				}
			}
			if actions == 0 {
				return false
			}
		}
		if stages == 0 {
			return false
		}
	}
	return true
}

func (reducer *Reducer) sourceExecution(id string) (SourceExecution, bool) {
	for _, execution := range reducer.source {
		if execution.ID == id {
			return execution, true
		}
	}
	return SourceExecution{}, false
}

func validateSourceExecution(execution SourceExecution) error {
	if execution.ID == "" || len(execution.Stages) == 0 {
		return errors.New("source execution is incomplete")
	}
	stages := map[string]int{}
	for stageIndex, stage := range execution.Stages {
		if stage.ID == "" || len(stage.Actions) == 0 {
			return fmt.Errorf("source execution %s has an incomplete stage", execution.ID)
		}
		if _, duplicate := stages[stage.ID]; duplicate {
			return fmt.Errorf("source execution %s repeats stage %s", execution.ID, stage.ID)
		}
		stages[stage.ID] = stageIndex
		if stage.DependsOn != "" {
			dependency, found := stages[stage.DependsOn]
			if !found || dependency >= stageIndex {
				return fmt.Errorf("source stage %s has an invalid dependency %s", stage.ID, stage.DependsOn)
			}
		}
		actions := map[string]bool{}
		for _, action := range stage.Actions {
			if action.ID == "" || len(action.Actors) == 0 && !action.HasRoleTargets {
				return fmt.Errorf("source stage %s has an incomplete action", stage.ID)
			}
			if actions[action.ID] {
				return fmt.Errorf("source stage %s repeats action %s", stage.ID, action.ID)
			}
			actions[action.ID] = true
			actors := map[string]bool{}
			for _, actor := range action.Actors {
				if actor == "" || actors[actor] {
					return fmt.Errorf("source action %s has an invalid actor", action.ID)
				}
				actors[actor] = true
			}
		}
	}
	return nil
}

func deepCopySource(source []SourceExecution) []SourceExecution {
	result := make([]SourceExecution, len(source))
	for executionIndex, execution := range source {
		result[executionIndex] = execution
		result[executionIndex].Stages = make([]SourceStage, len(execution.Stages))
		for stageIndex, stage := range execution.Stages {
			result[executionIndex].Stages[stageIndex] = stage
			result[executionIndex].Stages[stageIndex].Actions = make([]SourceAction, len(stage.Actions))
			for actionIndex, action := range stage.Actions {
				result[executionIndex].Stages[stageIndex].Actions[actionIndex] = action
				result[executionIndex].Stages[stageIndex].Actions[actionIndex].Actors = append([]string(nil), action.Actors...)
			}
		}
	}
	return result
}

func sortedKeys(value map[string]bool) []string {
	result := make([]string, 0, len(value))
	for item := range value {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func partition(atoms []atom, count int) [][]atom {
	result := make([][]atom, 0, count)
	for index := 0; index < count; index++ {
		start := index * len(atoms) / count
		end := (index + 1) * len(atoms) / count
		if start < end {
			result = append(result, append([]atom(nil), atoms[start:end]...))
		}
	}
	return result
}

func activeSet(value []attacknetv1beta1.RetainedExecution) map[string]attacknetv1beta1.RetainedExecution {
	result := make(map[string]attacknetv1beta1.RetainedExecution, len(value))
	for _, item := range value {
		result[item.ExecutionID] = item
	}
	return result
}

func deepCopyRetained(value []attacknetv1beta1.RetainedExecution) []attacknetv1beta1.RetainedExecution {
	result := make([]attacknetv1beta1.RetainedExecution, len(value))
	for index := range value {
		result[index] = *value[index].DeepCopy()
	}
	return result
}

func stringSet(value []string) map[string]bool {
	result := make(map[string]bool, len(value))
	for _, item := range value {
		result[item] = true
	}
	return result
}
