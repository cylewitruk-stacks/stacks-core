package fuzzreduce

import (
	"reflect"
	"testing"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestReducerIsAdaptiveBoundedAndNeverAddsOrReorders(t *testing.T) {
	source := []SourceExecution{
		{ID: "one", Stages: []SourceStage{{ID: "stage-a", Actions: []SourceAction{{ID: "fault-a", Actors: []string{"a", "b"}}}}}},
		{ID: "two", Stages: []SourceStage{{ID: "stage-b", Actions: []SourceAction{{ID: "fault-b", Actors: []string{"c"}}}}}},
		{ID: "three", Stages: []SourceStage{{ID: "stage-c", Actions: []SourceAction{{ID: "fault-c", Actors: []string{"d"}}}}}},
	}
	reducer, err := New(source, 8)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reducer.Next()
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first.Level != "execution" || len(first.Retained) >= len(source) {
		t.Fatalf("first candidate is not a material execution removal: %#v", first)
	}
	executableDigest, err := canonical.Digest(first.Retained)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != executableDigest {
		t.Fatalf("candidate digest %s does not bind retained instructions %s", first.Digest, executableDigest)
	}
	if err := reducer.Record(OutcomeReproduced); err != nil {
		t.Fatal(err)
	}
	next, err := reducer.Next()
	if err != nil {
		t.Fatal(err)
	}
	if next == nil {
		t.Fatal("adaptive reducer stopped after one accepted removal")
	}
	originalOrder := map[string]int{"one": 0, "two": 1, "three": 2}
	prior := -1
	for _, item := range next.Retained {
		order, found := originalOrder[item.ExecutionID]
		if !found || order <= prior {
			t.Fatalf("candidate added or reordered an execution: %#v", next.Retained)
		}
		prior = order
	}
	if err := reducer.Record(OutcomeInconclusive); err != nil {
		t.Fatal(err)
	}
	result := reducer.Result()
	if result.CausalMinimalityClaimed || len(result.Attempts) != 2 ||
		result.Attempts[1].Outcome != OutcomeInconclusive {
		t.Fatalf("result concealed ambiguity or claimed causality: %#v", result)
	}
}

func TestReducerEmitsMaterialCandidateAtEveryAutomaticLevel(t *testing.T) {
	expectedLevels := []string{"execution", "stage", "action", "actor"}
	if !reflect.DeepEqual(levels, expectedLevels) {
		t.Fatalf("automatic levels = %v, want implemented levels %v", levels, expectedLevels)
	}
	tests := []struct {
		name   string
		level  string
		source []SourceExecution
		check  func(*testing.T, Candidate)
	}{
		{
			name:  "execution",
			level: "execution",
			source: []SourceExecution{
				{ID: "one", Stages: []SourceStage{{ID: "stage-a", Actions: []SourceAction{{ID: "fault-a", Actors: []string{"a"}}}}}},
				{ID: "two", Stages: []SourceStage{{ID: "stage-b", Actions: []SourceAction{{ID: "fault-b", Actors: []string{"b"}}}}}},
			},
			check: func(t *testing.T, candidate Candidate) {
				t.Helper()
				if len(candidate.Retained) != 1 {
					t.Fatalf("execution candidate retained %d executions, want 1", len(candidate.Retained))
				}
			},
		},
		{
			name:  "stage",
			level: "stage",
			source: []SourceExecution{{ID: "one", Stages: []SourceStage{
				{ID: "stage-a", Actions: []SourceAction{{ID: "fault-a", Actors: []string{"a"}}}},
				{ID: "stage-b", Actions: []SourceAction{{ID: "fault-b", Actors: []string{"b"}}}},
			}}},
			check: func(t *testing.T, candidate Candidate) {
				t.Helper()
				if len(candidate.Retained) != 1 || len(candidate.Retained[0].RemovedStages) != 1 {
					t.Fatalf("stage candidate is not a material stage removal: %#v", candidate.Retained)
				}
			},
		},
		{
			name:  "action",
			level: "action",
			source: []SourceExecution{
				{ID: "one", Stages: []SourceStage{
					{ID: "stage", Actions: []SourceAction{
						{ID: "fault-a", Actors: []string{"a"}},
						{ID: "fault-b", Actors: []string{"b"}},
					}},
				}},
			},
			check: func(t *testing.T, candidate Candidate) {
				t.Helper()
				if len(candidate.Retained) != 1 || len(candidate.Retained[0].RemovedActions) != 1 {
					t.Fatalf("action candidate is not a material action removal: %#v", candidate.Retained)
				}
			},
		},
		{
			name:  "actor",
			level: "actor",
			source: []SourceExecution{
				{ID: "one", Stages: []SourceStage{
					{ID: "stage", Actions: []SourceAction{
						{ID: "fault", Actors: []string{"a", "b"}},
					}},
				}},
			},
			check: func(t *testing.T, candidate Candidate) {
				t.Helper()
				if len(candidate.Retained) != 1 || len(candidate.Retained[0].RemovedTargets) != 1 {
					t.Fatalf("actor candidate is not a material actor removal: %#v", candidate.Retained)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reducer, err := New(test.source, 1)
			if err != nil {
				t.Fatal(err)
			}
			before := deepCopyRetained(reducer.current)
			candidate, err := reducer.Next()
			if err != nil {
				t.Fatal(err)
			}
			if candidate == nil || candidate.Level != test.level {
				t.Fatalf("got candidate %#v, want level %s", candidate, test.level)
			}
			if reflect.DeepEqual(candidate.Retained, before) {
				t.Fatalf("%s candidate did not materially change the retained set", test.level)
			}
			test.check(t, *candidate)
		})
	}
}

func TestReducerClosesStageDependencyRemovals(t *testing.T) {
	source, err := SourceFromRun(
		[]attacknetv1beta1.RunExecutionSpec{{ID: "one", Campaign: "campaign"}},
		map[string]attacknetv1beta1.FaultCampaignSpec{"campaign": {Stages: []attacknetv1beta1.FaultStageSpec{
			{
				ID: "stage-a",
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "fault-a", Target: attacknetv1beta1.FaultTarget{Actors: []string{"actor-a"}},
				}},
			},
			{
				ID: "stage-b",
				Trigger: attacknetv1beta1.StageTriggerSpec{AfterStage: &attacknetv1beta1.StageDependency{
					Stage: "stage-a", State: "Recovered",
				}},
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "fault-b", Target: attacknetv1beta1.FaultTarget{Actors: []string{"actor-b"}},
				}},
			},
			{
				ID: "stage-c",
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "fault-c", Target: attacknetv1beta1.FaultTarget{Actors: []string{"actor-c"}},
				}},
			},
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := source[0].Stages[1].DependsOn; got != "stage-a" {
		t.Fatalf("source lost stage dependency: %q", got)
	}
	reducer, err := New(source, 4)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := reducer.Next()
	if err != nil {
		t.Fatal(err)
	}
	if candidate == nil || candidate.Level != "stage" ||
		len(candidate.Retained) != 1 ||
		len(candidate.Retained[0].RemovedStages) != 2 ||
		candidate.Retained[0].RemovedStages[0] != "stage-a" ||
		candidate.Retained[0].RemovedStages[1] != "stage-b" {
		t.Fatalf("stage removal is not dependency-closed: %#v", candidate)
	}
}

func TestReducerSkipsActorRemovalThatWouldEmptyAction(t *testing.T) {
	source := []SourceExecution{{
		ID: "one", Stages: []SourceStage{{
			ID: "stage", Actions: []SourceAction{
				{ID: "fault-a", Actors: []string{"actor-a"}},
				{ID: "fault-b", Actors: []string{"actor-b"}},
			},
		}},
	}}
	reducer, err := New(source, 8)
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate, err := reducer.Next()
		if err != nil {
			t.Fatal(err)
		}
		if candidate == nil {
			break
		}
		if candidate.Level == "actor" {
			t.Fatalf("reducer emitted an empty-target candidate: %#v", candidate)
		}
		if err := reducer.Record(OutcomeNotReproduced); err != nil {
			t.Fatal(err)
		}
	}
}
