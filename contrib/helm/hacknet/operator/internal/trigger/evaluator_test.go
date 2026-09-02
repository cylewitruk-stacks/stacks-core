package trigger

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

var (
	start = time.Date(2026, 8, 25, 20, 0, 0, 0, time.FixedZone("test", 2*60*60))
	now   = start.Add(30 * time.Second)
)

func TestAfterStartReturnsExactRequeueAndDeterministicReceipt(t *testing.T) {
	offset := time.Minute
	spec := Spec{Subject: "stage-a", AfterStart: &offset}
	waiting, err := Evaluate(spec, Snapshot{StartedAt: start, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	want := start.Add(time.Minute).UTC()
	if waiting.Eligible || waiting.RequeueAt == nil || !waiting.RequeueAt.Equal(want) || waiting.Reason != "WaitingForStartOffset" {
		t.Fatalf("unexpected wait decision: %#v, want %s", waiting, want)
	}

	ready, err := Evaluate(spec, Snapshot{StartedAt: start, Now: start.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Eligible || ready.Receipt == nil || !ready.Receipt.SatisfiedAt.Equal(want) {
		t.Fatalf("unexpected ready decision: %#v", ready)
	}
	if ready.Receipt.SchemaVersion != "stacks-attacknet-trigger-receipt/v1" || ready.Receipt.Trigger != AfterStart {
		t.Fatalf("receipt is not self-describing: %#v", ready.Receipt)
	}
	if ready.Receipt.SatisfiedAt.Location() != time.UTC || ready.Receipt.Evidence[0].StartedAt.Location() != time.UTC {
		t.Fatalf("receipt times were not canonicalized: %#v", ready.Receipt)
	}
}

func TestTriggerRequiresExactlyOneBoundedVariant(t *testing.T) {
	height := int64(10)
	offset := time.Second
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{"none", Spec{Subject: "stage"}, "exactly one"},
		{"multiple", Spec{Subject: "stage", AfterStart: &offset, BurnHeight: &height}, "exactly one"},
		{"negative height", Spec{Subject: "stage", BurnHeight: int64Pointer(-1)}, "must not be negative"},
		{"unbounded offset", Spec{Subject: "stage", AfterStart: durationPointer(25 * time.Hour)}, "within"},
		{"empty observation", Spec{Subject: "stage", Observation: &ObservationRequirement{Timeout: time.Second}}, "type is required"},
		{"unbounded observation", Spec{Subject: "stage", Observation: &ObservationRequirement{Type: "Invariant", Timeout: 25 * time.Hour}}, "timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Evaluate(test.spec, Snapshot{StartedAt: start, Now: now})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestDependenciesCoverActiveCompletedAndDelayedStates(t *testing.T) {
	spec := Spec{
		Subject:    "stage-c",
		AfterStart: durationPointer(0),
		Dependencies: []DependencyRequirement{
			{ID: "stage-b", State: DependencyTerminal},
			{ID: "stage-a", State: DependencyEffective, Delay: 10 * time.Second},
		},
	}
	activeAt := start.Add(20 * time.Second)
	terminalAt := start.Add(25 * time.Second)
	snapshot := Snapshot{StartedAt: start, Now: start.Add(25 * time.Second), Dependencies: []DependencyObservation{
		{ID: "stage-a", Source: trusted("FaultCampaign", "campaign", "uid-a"), Transitions: []DependencyTransition{{State: DependencyInjected, ReachedAt: start.Add(10 * time.Second)}, {State: DependencyEffective, ReachedAt: activeAt}}},
		{ID: "stage-b", Source: trusted("FaultCampaign", "campaign", "uid-b"), Transitions: []DependencyTransition{{State: DependencyRecovered, ReachedAt: start.Add(24 * time.Second)}, {State: DependencyTerminal, ReachedAt: terminalAt}}},
	}}
	waiting, err := Evaluate(spec, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := activeAt.Add(10 * time.Second).UTC()
	if waiting.RequeueAt == nil || !waiting.RequeueAt.Equal(want) || waiting.Reason != "WaitingForDependencyDelay" {
		t.Fatalf("unexpected dependency wait: %#v", waiting)
	}

	snapshot.Now = want
	ready, err := Evaluate(spec, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Eligible || len(ready.Receipt.Evidence) != 3 {
		t.Fatalf("dependencies did not become eligible: %#v", ready)
	}
	if got := ready.Receipt.Evidence[1].DependencyID; got != "stage-a" {
		t.Fatalf("dependencies were not emitted in stable ID order: %q", got)
	}
	if got := ready.Receipt.Evidence[2].DependencyState; got != DependencyTerminal {
		t.Fatalf("completed dependency receipt lost terminal state: %q", got)
	}
}

func TestDependencyContractsFailClosedAndScheduleEarliestTimeChange(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{"self", Spec{Subject: "stage", AfterDependency: &DependencyRequirement{ID: "stage", State: DependencyInjected}}, "cannot depend on itself"},
		{"unknown state", Spec{Subject: "stage", AfterDependency: &DependencyRequirement{ID: "prior", State: "Running"}}, "unsupported state"},
		{"negative delay", Spec{Subject: "stage", AfterDependency: &DependencyRequirement{ID: "prior", State: DependencyInjected, Delay: -time.Second}}, "delay must be"},
		{"duplicate", Spec{Subject: "stage", AfterStart: durationPointer(0), Dependencies: []DependencyRequirement{{ID: "prior", State: DependencyInjected}, {ID: "prior", State: DependencyTerminal}}}, "duplicate dependency"},
		{"primary duplicate", Spec{Subject: "stage", AfterDependency: &DependencyRequirement{ID: "prior", State: DependencyInjected}, Dependencies: []DependencyRequirement{{ID: "prior", State: DependencyTerminal}}}, "duplicates the primary"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Evaluate(test.spec, Snapshot{StartedAt: start, Now: now})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}

	spec := Spec{Subject: "stage-b", AfterStart: durationPointer(20 * time.Second), Dependencies: []DependencyRequirement{{
		ID: "stage-a", State: DependencyInjected, Delay: 30 * time.Second,
	}}}
	snapshot := Snapshot{StartedAt: start, Now: start.Add(10 * time.Second), Dependencies: []DependencyObservation{{
		ID: "stage-a", Source: trusted("FaultCampaign", "campaign", "uid"),
		Transitions: []DependencyTransition{{State: DependencyInjected, ReachedAt: start.Add(5 * time.Second)}},
	}}}
	decision, err := Evaluate(spec, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RequeueAt == nil || !decision.RequeueAt.Equal(start.Add(20*time.Second)) {
		t.Fatalf("got next requeue %v, want earliest time-dependent change", decision.RequeueAt)
	}
	snapshot.Now = start.Add(20 * time.Second)
	decision, err = Evaluate(spec, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RequeueAt == nil || !decision.RequeueAt.Equal(start.Add(35*time.Second)) {
		t.Fatalf("got next requeue %v after primary trigger, want dependency delay", decision.RequeueAt)
	}
}

func TestDependencyWithoutTrustedTransitionWaitsForWatch(t *testing.T) {
	spec := Spec{Subject: "stage-b", AfterDependency: &DependencyRequirement{ID: "stage-a", State: DependencyInjected}}
	decision, err := Evaluate(spec, Snapshot{StartedAt: start, Now: now, Dependencies: []DependencyObservation{{
		ID: "stage-a", Source: Source{Kind: "FaultCampaign", Name: "campaign", UID: "uid", Trusted: false},
		Transitions: []DependencyTransition{{State: DependencyInjected, ReachedAt: start.Add(time.Second)}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Eligible || decision.RequeueAt != nil || decision.Reason != "WaitingForTrustedDependency" {
		t.Fatalf("untrusted dependency did not wait for a watch event: %#v", decision)
	}
}

func TestHeightTriggersRequireFreshTrustedSource(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		set  func(*Snapshot, *HeightObservation)
		kind Type
	}{
		{"burn", Spec{Subject: "burn-stage", BurnHeight: int64Pointer(300)}, func(snapshot *Snapshot, value *HeightObservation) { snapshot.BurnHeight = value }, AtBurnHeight},
		{"stacks", Spec{Subject: "stacks-stage", StacksHeight: int64Pointer(900)}, func(snapshot *Snapshot, value *HeightObservation) { snapshot.StacksHeight = value }, AtStacksHeight},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := Snapshot{StartedAt: start, Now: now}
			value := &HeightObservation{Height: *heightFor(test.spec), ObservedAt: start.Add(time.Second), Source: trusted("StacksNetwork", "network", "network-uid")}
			test.set(&snapshot, value)
			ready, err := Evaluate(test.spec, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if !ready.Eligible || ready.Receipt.Trigger != test.kind || ready.Receipt.Evidence[0].Source.UID != "network-uid" {
				t.Fatalf("trusted height did not satisfy trigger: %#v", ready)
			}

			value.Source.Trusted = false
			waiting, err := Evaluate(test.spec, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if waiting.Eligible || waiting.Reason != "WaitingForTrustedHeight" || waiting.RequeueAt != nil {
				t.Fatalf("untrusted height was not rejected: %#v", waiting)
			}

			value.Source.Trusted = true
			value.ObservedAt = start.Add(-time.Second)
			waiting, err = Evaluate(test.spec, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if waiting.Reason != "WaitingForFreshHeight" {
				t.Fatalf("stale height was accepted: %#v", waiting)
			}
		})
	}
}

func TestObservationTriggerIsBoundedAndSelectsDeterministically(t *testing.T) {
	spec := Spec{Subject: "observe", Observation: &ObservationRequirement{Type: "Invariant", Actor: "miner-1", Expected: "failed", Timeout: time.Minute}}
	first := Observation{ID: "b", Type: "Invariant", Actor: "miner-1", Value: "failed", ObservedAt: start.Add(10 * time.Second), Source: trusted("EventJournal", "journal", "journal-b")}
	second := first
	second.ID, second.Source.UID = "a", "journal-a"
	untrusted := first
	untrusted.ID, untrusted.ObservedAt, untrusted.Source.Trusted = "earlier", start.Add(time.Second), false
	snapshot := Snapshot{StartedAt: start, Now: now, Observations: []Observation{first, untrusted, second}}
	ready, err := Evaluate(spec, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Eligible || ready.Receipt.Evidence[0].ObservationID != "a" {
		t.Fatalf("observation choice was not deterministic: %#v", ready)
	}

	empty := Snapshot{StartedAt: start, Now: now}
	waiting, err := Evaluate(spec, empty)
	if err != nil {
		t.Fatal(err)
	}
	deadline := start.Add(time.Minute).UTC()
	if waiting.RequeueAt == nil || !waiting.RequeueAt.Equal(deadline) || waiting.Reason != "WaitingForObservation" {
		t.Fatalf("observation deadline is not the precise requeue: %#v", waiting)
	}
	empty.Now = deadline
	expired, err := Evaluate(spec, empty)
	if err != nil {
		t.Fatal(err)
	}
	if !expired.Expired || expired.Eligible || expired.Reason != "ObservationTimedOut" || expired.RequeueAt != nil {
		t.Fatalf("observation timeout was not terminal: %#v", expired)
	}
}

func TestReceiptIsStableAcrossInputOrdering(t *testing.T) {
	spec := Spec{Subject: "stage-c", Observation: &ObservationRequirement{Type: "Invariant", Timeout: time.Minute}, Dependencies: []DependencyRequirement{
		{ID: "stage-b", State: DependencyTerminal}, {ID: "stage-a", State: DependencyEffective},
	}}
	observations := []Observation{
		{ID: "z", Type: "Invariant", ObservedAt: start.Add(5 * time.Second), Source: trusted("EventJournal", "events", "z")},
		{ID: "a", Type: "Invariant", ObservedAt: start.Add(5 * time.Second), Source: trusted("EventJournal", "events", "a")},
	}
	dependencies := []DependencyObservation{
		{ID: "stage-b", Source: trusted("FaultCampaign", "b", "b"), Transitions: []DependencyTransition{{State: DependencyTerminal, ReachedAt: start.Add(8 * time.Second)}}},
		{ID: "stage-a", Source: trusted("FaultCampaign", "a", "a"), Transitions: []DependencyTransition{{State: DependencyEffective, ReachedAt: start.Add(7 * time.Second)}}},
	}
	left, err := Evaluate(spec, Snapshot{StartedAt: start, Now: now, Observations: observations, Dependencies: dependencies})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Evaluate(spec, Snapshot{StartedAt: start, Now: now, Observations: reverse(observations), Dependencies: reverse(dependencies)})
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, _ := json.Marshal(left.Receipt)
	rightJSON, _ := json.Marshal(right.Receipt)
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("receipt depends on input order:\n%s\n%s", leftJSON, rightJSON)
	}
	if spec.Dependencies[0].ID != "stage-b" {
		t.Fatal("Evaluate mutated the caller's dependency order")
	}
}

func TestSnapshotValidationFailsClosed(t *testing.T) {
	base := Spec{Subject: "stage", AfterStart: durationPointer(0)}
	tests := []struct {
		name     string
		snapshot Snapshot
		want     string
	}{
		{"time before start", Snapshot{StartedAt: start, Now: start.Add(-time.Second)}, "precedes"},
		{"duplicate dependency", Snapshot{StartedAt: start, Now: now, Dependencies: []DependencyObservation{{ID: "a", Source: trusted("Run", "a", "a")}, {ID: "a", Source: trusted("Run", "a", "a")}}}, "duplicate dependency"},
		{"duplicate observation", Snapshot{StartedAt: start, Now: now, Observations: []Observation{{ID: "a", Type: "x", ObservedAt: start, Source: trusted("Event", "a", "a")}, {ID: "a", Type: "x", ObservedAt: start, Source: trusted("Event", "a", "a")}}}, "duplicate observation"},
		{"future observation", Snapshot{StartedAt: start, Now: now, Observations: []Observation{{ID: "a", Type: "x", ObservedAt: now.Add(time.Second), Source: trusted("Event", "a", "a")}}}, "invalid observation time"},
		{"future transition", Snapshot{StartedAt: start, Now: now, Dependencies: []DependencyObservation{{ID: "a", Source: trusted("Run", "a", "a"), Transitions: []DependencyTransition{{State: DependencyInjected, ReachedAt: now.Add(time.Second)}}}}}, "outside the run window"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Evaluate(base, test.snapshot)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}

	tooMany := make([]Observation, maximumInputs+1)
	_, err := Evaluate(base, Snapshot{StartedAt: start, Now: now, Observations: tooMany})
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("unbounded observations were accepted: %v", err)
	}
}

func TestV1Beta1AdaptersPreserveStageAndRunSemantics(t *testing.T) {
	stage, err := ForStage(attacknetv1beta1.FaultStageSpec{ID: "stage-b", Trigger: attacknetv1beta1.StageTriggerSpec{AfterStage: &attacknetv1beta1.StageDependency{
		Stage: "stage-a", State: "Effective", Delay: metav1.Duration{Duration: 3 * time.Second},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if stage.AfterDependency == nil || stage.AfterDependency.ID != "stage-a" || stage.AfterDependency.State != DependencyEffective || stage.AfterDependency.Delay != 3*time.Second {
		t.Fatalf("stage adapter lost dependency semantics: %#v", stage)
	}

	execution, err := ForRunExecution(attacknetv1beta1.RunExecutionSpec{
		ID: "execution-c", Trigger: attacknetv1beta1.RunTriggerSpec{BurnHeight: int64Pointer(300)},
		DependsOn: []attacknetv1beta1.RunExecutionDependency{
			{Execution: "execution-b", State: "Terminal"},
			{Execution: "execution-a", State: "Injected", Delay: metav1.Duration{Duration: time.Second}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if execution.BurnHeight == nil || *execution.BurnHeight != 300 || execution.Dependencies[0].ID != "execution-a" || execution.Dependencies[1].State != DependencyTerminal {
		t.Fatalf("run adapter lost or failed to normalize semantics: %#v", execution)
	}

	immediate, err := ForRunExecution(attacknetv1beta1.RunExecutionSpec{ID: "immediate"})
	if err != nil || immediate.AfterStart == nil || *immediate.AfterStart != 0 {
		t.Fatalf("omitted trigger was not normalized to an immediate start: %#v %v", immediate, err)
	}
}

func trusted(kind, name, uid string) Source {
	return Source{Kind: kind, Namespace: "test", Name: name, UID: uid, ResourceVersion: "7", Trusted: true}
}

func durationPointer(value time.Duration) *time.Duration { return &value }

func int64Pointer(value int64) *int64 { return &value }

func heightFor(spec Spec) *int64 {
	if spec.BurnHeight != nil {
		return spec.BurnHeight
	}
	return spec.StacksHeight
}

func reverse[T any](values []T) []T {
	result := append([]T(nil), values...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}
