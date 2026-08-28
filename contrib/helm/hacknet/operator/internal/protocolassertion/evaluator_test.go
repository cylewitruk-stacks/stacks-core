package protocolassertion

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
)

func TestStatelessAssertionsProveAndViolate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := assertionSnapshot(now)
	tests := []struct {
		name      string
		assertion attacknetv1beta1.ProtocolAssertionSpec
		mutate    func(*protocolobservation.Snapshot)
	}{
		{
			name: "cohort agreement",
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "cohort", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
				Chain: "stacks", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			}},
			mutate: func(snapshot *protocolobservation.Snapshot) {
				setGauge(snapshot, "node-2", "stacks_node_stacks_tip_height", 101)
			},
		},
		{
			name: "signer registration",
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "registered", SignerRegistration: &attacknetv1beta1.SignerRegistrationAssertion{
				Actors: []string{"signer-1"}, MinimumRegistered: 1,
			}},
			mutate: func(snapshot *protocolobservation.Snapshot) {
				setGauge(snapshot, "signer-1", "stacks_signer_registered_for_current_reward_cycle", 0)
			},
		},
		{
			name: "signer freshness",
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "fresh", SignerStateFreshness: &attacknetv1beta1.SignerStateFreshnessAssertion{
				Actors: []string{"signer-1"}, MaximumAge: metav1.Duration{Duration: 2 * time.Minute},
			}},
			mutate: func(snapshot *protocolobservation.Snapshot) {
				setGauge(snapshot, "signer-1", "stacks_signer_state_last_changed_timestamp_seconds", float64(now.Add(-3*time.Minute).Unix()))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := assertionSet(test.assertion)
			proven, err := EvaluateSet(set, nil, snapshot, now)
			if err != nil || proven.Outcome != OutcomeProven {
				t.Fatalf("expected Proven, got %#v, %v", proven, err)
			}
			changed := assertionSnapshot(now)
			test.mutate(&changed)
			violated, err := EvaluateSet(set, &proven, changed, now.Add(time.Second))
			if err != nil || violated.Outcome != OutcomeViolated {
				t.Fatalf("expected Violated, got %#v, %v", violated, err)
			}
		})
	}
}

func TestMalformedMetricDomainsRemainUnavailableWithoutPanicking(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tests := []struct {
		name      string
		assertion attacknetv1beta1.ProtocolAssertionSpec
		actor     string
		metric    string
		value     float64
	}{
		{
			name: "positive infinity", actor: "node-1", metric: "stacks_node_stacks_tip_height", value: math.Inf(1),
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "height", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
				Chain: "stacks", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			}},
		},
		{
			name: "NaN", actor: "node-1", metric: "stacks_node_stacks_tip_height", value: math.NaN(),
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "height", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
				Chain: "stacks", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			}},
		},
		{
			name: "negative height", actor: "node-1", metric: "stacks_node_stacks_tip_height", value: -1,
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "height", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
				Chain: "stacks", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			}},
		},
		{
			name: "fractional height", actor: "node-1", metric: "stacks_node_stacks_tip_height", value: 1.5,
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "height", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
				Chain: "stacks", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			}},
		},
		{
			name: "fractional count", actor: "signer-1", metric: "stacks_signer_block_responses_sent", value: 1.5,
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "responses", ProposalOutcomeVisibility: &attacknetv1beta1.ProposalOutcomeVisibilityAssertion{
				Actors: []string{"signer-1"}, Window: metav1.Duration{Duration: time.Second}, MinimumObserved: 1,
			}},
		},
		{
			name: "non-boolean registration", actor: "signer-1", metric: "stacks_signer_registered_for_current_reward_cycle", value: 2,
			assertion: attacknetv1beta1.ProtocolAssertionSpec{ID: "registration", SignerRegistration: &attacknetv1beta1.SignerRegistrationAssertion{
				Actors: []string{"signer-1"}, MinimumRegistered: 1,
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := assertionSnapshot(now)
			if test.metric == "stacks_signer_block_responses_sent" {
				setCounter(&snapshot, test.actor, test.metric, test.value)
			} else {
				setGauge(&snapshot, test.actor, test.metric, test.value)
			}
			status, err := EvaluateSet(assertionSet(test.assertion), nil, snapshot, now)
			if err != nil {
				t.Fatalf("malformed actor metric escaped as controller error: %v", err)
			}
			if status.Outcome != OutcomePending || status.Results[0].Reason != "AssertionMetricUnavailable" {
				t.Fatalf("malformed metric did not fail unavailable: %#v", status)
			}
		})
	}
}

func TestFutureSignerTimestampIsFiniteViolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	assertion := attacknetv1beta1.ProtocolAssertionSpec{ID: "fresh", SignerStateFreshness: &attacknetv1beta1.SignerStateFreshnessAssertion{
		Actors: []string{"signer-1"}, MaximumAge: metav1.Duration{Duration: 2 * time.Minute},
	}}
	snapshot := assertionSnapshot(now)
	setGauge(&snapshot, "signer-1", "stacks_signer_state_last_changed_timestamp_seconds", float64(now.Add(time.Minute).Unix()))
	status, err := EvaluateSet(assertionSet(assertion), nil, snapshot, now)
	if err != nil || status.Outcome != OutcomeViolated {
		t.Fatalf("future signer timestamp was not a finite violation: %#v, %v", status, err)
	}
	observed := evidence{}
	if err := json.Unmarshal(status.Results[0].Evidence.Raw, &observed); err != nil {
		t.Fatal(err)
	}
	if age := observed.Current["signer-1"]; age >= 0 || math.IsInf(age, 0) || math.IsNaN(age) {
		t.Fatalf("future timestamp did not retain finite signed age: %v", age)
	}
}

func TestWindowedAssertionsRetainBaselineAndRequireProgress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tests := []attacknetv1beta1.ProtocolAssertionSpec{
		{ID: "chain", ChainProgress: &attacknetv1beta1.ChainProgressAssertion{Chain: "stacks", Actors: []string{"node-1"}, Window: metav1.Duration{Duration: 5 * time.Second}, MinimumDelta: 2}},
		{ID: "proposal", ProposalOutcomeVisibility: &attacknetv1beta1.ProposalOutcomeVisibilityAssertion{Actors: []string{"signer-1"}, Window: metav1.Duration{Duration: 5 * time.Second}, MinimumObserved: 2}},
	}
	for _, assertion := range tests {
		set := assertionSet(assertion)
		pending, err := EvaluateSet(set, nil, assertionSnapshot(now), now)
		if err != nil || pending.Outcome != OutcomePending {
			t.Fatalf("expected baseline Pending for %s: %#v, %v", assertion.ID, pending, err)
		}
		advanced := assertionSnapshot(now.Add(5 * time.Second))
		if assertion.ChainProgress != nil {
			setGauge(&advanced, "node-1", "stacks_node_stacks_tip_height", 102)
		} else {
			setCounter(&advanced, "signer-1", "stacks_signer_block_responses_sent", 3)
		}
		proven, err := EvaluateSet(set, &pending, advanced, now.Add(5*time.Second))
		if err != nil || proven.Outcome != OutcomeProven {
			t.Fatalf("expected progress Proven for %s: %#v, %v", assertion.ID, proven, err)
		}
	}
}

func TestCohortConvergenceWaitsForRecoveryWithinBound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	window := metav1.Duration{Duration: 10 * time.Second}
	assertion := attacknetv1beta1.ProtocolAssertionSpec{
		ID: "cohort", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
			Chain: "burnchain", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			ConvergenceWindow: &window,
		},
	}
	diverged := assertionSnapshot(now)
	setGauge(&diverged, "node-2", "stacks_node_burn_block_height", 101)
	pending, err := EvaluateSet(assertionSet(assertion), nil, diverged, now)
	if err != nil || pending.Outcome != OutcomePending || pending.Results[0].Reason != "WaitingForEvidence" {
		t.Fatalf("transient divergence did not remain pending: %#v, %v", pending, err)
	}
	converged := assertionSnapshot(now.Add(3 * time.Second))
	proven, err := EvaluateSet(assertionSet(assertion), &pending, converged, now.Add(3*time.Second))
	if err != nil || proven.Outcome != OutcomeProven || proven.Results[0].Reason != "ConvergenceObserved" {
		t.Fatalf("bounded convergence was not proven: %#v, %v", proven, err)
	}
}

func TestCohortConvergenceViolatesAtDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	window := metav1.Duration{Duration: 10 * time.Second}
	assertion := attacknetv1beta1.ProtocolAssertionSpec{
		ID: "cohort", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
			Chain: "burnchain", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			ConvergenceWindow: &window,
		},
	}
	diverged := assertionSnapshot(now)
	setGauge(&diverged, "node-2", "stacks_node_burn_block_height", 101)
	pending, err := EvaluateSet(assertionSet(assertion), nil, diverged, now)
	if err != nil || pending.Outcome != OutcomePending {
		t.Fatalf("expected initial convergence observation to remain pending: %#v, %v", pending, err)
	}
	late := assertionSnapshot(now.Add(10 * time.Second))
	setGauge(&late, "node-2", "stacks_node_burn_block_height", 101)
	violated, err := EvaluateSet(assertionSet(assertion), &pending, late, now.Add(10*time.Second))
	if err != nil || violated.Outcome != OutcomeViolated || violated.Results[0].Reason != "ConvergenceDeadlineExceeded" {
		t.Fatalf("persistent divergence did not violate at the deadline: %#v, %v", violated, err)
	}
}

func TestWindowStartsWhenBaselineEvidenceBecomesAvailable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	assertion := attacknetv1beta1.ProtocolAssertionSpec{
		ID: "chain", ChainProgress: &attacknetv1beta1.ChainProgressAssertion{
			Chain: "stacks", Actors: []string{"node-1"},
			Window: metav1.Duration{Duration: 5 * time.Second}, MinimumDelta: 2,
		},
	}
	set := assertionSet(assertion)
	unavailable := assertionSnapshot(now)
	unavailable.Actors[0].Families = nil
	initial, err := EvaluateSet(set, nil, unavailable, now)
	if err != nil || initial.Outcome != OutcomePending {
		t.Fatalf("expected unavailable initial evidence to remain Pending: %#v, %v", initial, err)
	}
	baseline, err := EvaluateSet(set, &initial, assertionSnapshot(now.Add(4*time.Second)), now.Add(4*time.Second))
	if err != nil || baseline.Outcome != OutcomePending {
		t.Fatalf("expected late baseline to remain Pending: %#v, %v", baseline, err)
	}
	early := assertionSnapshot(now.Add(5 * time.Second))
	setGauge(&early, "node-1", "stacks_node_stacks_tip_height", 102)
	pending, err := EvaluateSet(set, &baseline, early, now.Add(5*time.Second))
	if err != nil || pending.Outcome != OutcomePending {
		t.Fatalf("progress before the complete observation window was accepted: %#v, %v", pending, err)
	}
	complete := assertionSnapshot(now.Add(9 * time.Second))
	setGauge(&complete, "node-1", "stacks_node_stacks_tip_height", 102)
	proven, err := EvaluateSet(set, &pending, complete, now.Add(9*time.Second))
	if err != nil || proven.Outcome != OutcomeProven {
		t.Fatalf("progress after the complete observation window was not accepted: %#v, %v", proven, err)
	}
}

func TestWindowedAssertionDoesNotCrossInventoryIdentity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := assertionSet(attacknetv1beta1.ProtocolAssertionSpec{
		ID: "chain", ChainProgress: &attacknetv1beta1.ChainProgressAssertion{
			Chain: "stacks", Actors: []string{"node-1"},
			Window: metav1.Duration{Duration: 5 * time.Second}, MinimumDelta: 2,
		},
	})
	baseline, err := EvaluateSet(set, nil, assertionSnapshot(now), now)
	if err != nil || baseline.Outcome != OutcomePending {
		t.Fatalf("capture baseline: %#v, %v", baseline, err)
	}
	replaced := assertionSnapshot(now.Add(5 * time.Second))
	replaced.InventoryDigest = "sha256:replacement"
	replaced.Actors[0].Source.PodUID = "replacement-pod"
	setGauge(&replaced, "node-1", "stacks_node_stacks_tip_height", 102)
	pending, err := EvaluateSet(set, &baseline, replaced, now.Add(5*time.Second))
	if err != nil || pending.Outcome != OutcomePending || pending.Results[0].Reason != "ObservationIdentityChanged" {
		t.Fatalf("cross-identity progress did not fail closed: %#v, %v", pending, err)
	}
	replaced = assertionSnapshot(now.Add(31 * time.Second))
	replaced.InventoryDigest = "sha256:replacement"
	replaced.Actors[0].Source.PodUID = "replacement-pod"
	setGauge(&replaced, "node-1", "stacks_node_stacks_tip_height", 102)
	closed, err := EvaluateSet(set, &pending, replaced, now.Add(31*time.Second))
	if err != nil || closed.Outcome != OutcomeInconclusive ||
		closed.Results[0].Reason != "ObservationIdentityChangedDeadlineExceeded" {
		t.Fatalf("cross-identity window did not close Inconclusive: %#v, %v", closed, err)
	}
}

func TestMissingStaleAndAmbiguousEvidenceExpireInconclusive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := assertionSet(attacknetv1beta1.ProtocolAssertionSpec{ID: "cohort", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
		Chain: "burnchain", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
	}})
	tests := []struct {
		name           string
		expectedReason string
		mutate         func(*protocolobservation.Snapshot)
	}{
		{"missing", "AssertionMetricUnavailableDeadlineExceeded", func(snapshot *protocolobservation.Snapshot) { snapshot.Actors[0].Families = nil }},
		{"stale", "ObservationStaleDeadlineExceeded", func(snapshot *protocolobservation.Snapshot) { snapshot.ObservedAt = now.Add(-time.Minute) }},
		{"ambiguous metric", "AssertionMetricUnavailableDeadlineExceeded", func(snapshot *protocolobservation.Snapshot) {
			family := snapshot.Actors[0].Families["stacks_node_burn_block_height"]
			family.Metric = append(family.Metric, family.Metric[0])
		}},
		{"ambiguous source", "ObservationSourceAmbiguousDeadlineExceeded", func(snapshot *protocolobservation.Snapshot) {
			snapshot.Actors[0].Source.ObservedAt = now.Add(-time.Second)
		}},
		{"endpoint error", "ActorMetricsUnavailableDeadlineExceeded", func(snapshot *protocolobservation.Snapshot) { snapshot.Actors[0].Error = "offline" }},
		{"identity unavailable", "IdentityObservationUnavailableDeadlineExceeded", func(snapshot *protocolobservation.Snapshot) {
			snapshot.UnavailableReason = protocolobservation.UnavailableIdentity
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := assertionSnapshot(now)
			test.mutate(&snapshot)
			pending, err := EvaluateSet(set, nil, snapshot, now)
			if err != nil || pending.Outcome != OutcomePending {
				t.Fatalf("expected Pending, got %#v, %v", pending, err)
			}
			expiredSnapshot := assertionSnapshot(now.Add(31 * time.Second))
			test.mutate(&expiredSnapshot)
			expired, err := EvaluateSet(set, &pending, expiredSnapshot, now.Add(31*time.Second))
			if err != nil || expired.Outcome != OutcomeInconclusive || expired.Results[0].Reason != test.expectedReason {
				t.Fatalf("expected Inconclusive, got %#v, %v", expired, err)
			}
		})
	}
}

func TestValidateSetRejectsWrongRolesAndBounds(t *testing.T) {
	actors := map[string]string{"node": "follower", "signer": "signer"}
	set := assertionSet(attacknetv1beta1.ProtocolAssertionSpec{ID: "bad", SignerRegistration: &attacknetv1beta1.SignerRegistrationAssertion{
		Actors: []string{"node"}, MinimumRegistered: 1,
	}})
	if err := ValidateSet(&set, actors); err == nil {
		t.Fatal("expected node actor to be rejected from signer assertion")
	}
	set.Assertions[0].SignerRegistration.Actors = []string{"signer"}
	set.Timeout.Duration = 0
	if err := ValidateSet(&set, actors); err == nil {
		t.Fatal("expected zero timeout to be rejected")
	}
}

func TestValidateStructureBoundsCohortConvergenceWindow(t *testing.T) {
	window := metav1.Duration{Duration: 31 * time.Second}
	set := assertionSet(attacknetv1beta1.ProtocolAssertionSpec{
		ID: "cohort", CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
			Chain: "burnchain", Actors: []string{"node-1", "node-2"}, MaximumSpread: 0,
			ConvergenceWindow: &window,
		},
	})
	if err := ValidateStructure(&set); err == nil || !strings.Contains(err.Error(), "convergence window") {
		t.Fatalf("convergence window beyond the assertion timeout was accepted: %v", err)
	}
	set.Assertions[0].CohortAgreement.ConvergenceWindow.Duration = 30 * time.Second
	if err := ValidateStructure(&set); err != nil {
		t.Fatalf("bounded convergence window was rejected: %v", err)
	}
}

func TestValidateStructureBoundsDurableActorEvidence(t *testing.T) {
	assertions := make([]attacknetv1beta1.ProtocolAssertionSpec, 0, 5)
	for index := 0; index < 5; index++ {
		actors := make([]string, 64)
		for actor := range actors {
			actors[actor] = fmt.Sprintf("node-%d-%d", index, actor)
		}
		assertions = append(assertions, attacknetv1beta1.ProtocolAssertionSpec{
			ID: fmt.Sprintf("cohort-%d", index),
			CohortAgreement: &attacknetv1beta1.CohortAgreementAssertion{
				Chain: "stacks", Actors: actors, MaximumSpread: 0,
			},
		})
	}
	set := attacknetv1beta1.ProtocolAssertionSetSpec{
		Timeout: metav1.Duration{Duration: 30 * time.Second}, Assertions: assertions,
	}
	if err := ValidateStructure(&set); err == nil || !strings.Contains(err.Error(), "256 actor references") {
		t.Fatalf("oversized durable evidence was not rejected: %v", err)
	}
}

func TestAssertionEvidenceBindsNetworkAndAdmittedInventory(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := assertionSet(attacknetv1beta1.ProtocolAssertionSpec{
		ID: "complete",
		TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{
			Actors: []string{"node-1"},
		},
	})
	status, err := EvaluateSet(set, nil, assertionSnapshot(now), now)
	if err != nil || status.Outcome != OutcomeProven {
		t.Fatalf("evaluate assertion: %#v, %v", status, err)
	}
	observed := evidence{}
	if err := json.Unmarshal(status.Results[0].Evidence.Raw, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.NetworkUID != "network" || observed.InventoryDigest != "sha256:inventory" || !observed.ObservedAt.Equal(now) {
		t.Fatalf("evidence is not inventory-bound: %#v", observed)
	}
}

func TestConcludeUnavailableFailsClosedWhenMeasurementWindowWasMissed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := assertionSet(attacknetv1beta1.ProtocolAssertionSpec{ID: "complete", TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{
		Actors: []string{"node-1"},
	}})
	closed, err := ConcludeUnavailable(set, nil, now, "EvidenceWindowClosed")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Outcome != OutcomeInconclusive || len(closed.Results) != 1 || closed.Results[0].Reason != "EvidenceWindowClosed" {
		t.Fatalf("missed measurement window did not close Inconclusive: %#v", closed)
	}
	proven, err := EvaluateSet(set, nil, assertionSnapshot(now), now)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := ConcludeUnavailable(set, &proven, now.Add(time.Second), "EvidenceWindowClosed")
	if err != nil {
		t.Fatal(err)
	}
	if retained.Outcome != OutcomeProven || retained.Results[0].Reason != "AssertionSatisfied" {
		t.Fatalf("terminal evidence was not retained: %#v", retained)
	}
}

func assertionSet(assertion attacknetv1beta1.ProtocolAssertionSpec) attacknetv1beta1.ProtocolAssertionSetSpec {
	return attacknetv1beta1.ProtocolAssertionSetSpec{Timeout: metav1.Duration{Duration: 30 * time.Second}, Assertions: []attacknetv1beta1.ProtocolAssertionSpec{assertion}}
}

func assertionSnapshot(now time.Time) protocolobservation.Snapshot {
	return protocolobservation.Snapshot{NetworkUID: "network", InventoryDigest: "sha256:inventory", ObservedAt: now, Actors: []protocolobservation.ActorSnapshot{
		actorSnapshot("node-1", "follower", now, map[string]float64{"stacks_node_burn_block_height": 50, "stacks_node_stacks_tip_height": 100}),
		actorSnapshot("node-2", "miner", now, map[string]float64{"stacks_node_burn_block_height": 50, "stacks_node_stacks_tip_height": 100}),
		actorSnapshot("signer-1", "signer", now, map[string]float64{
			"stacks_signer_registered_for_current_reward_cycle":  1,
			"stacks_signer_state_last_changed_timestamp_seconds": float64(now.Add(-time.Minute).Unix()),
			"stacks_signer_block_responses_sent":                 1,
		}),
	}}
}

func actorSnapshot(name, role string, now time.Time, values map[string]float64) protocolobservation.ActorSnapshot {
	families := make(map[string]*dto.MetricFamily, len(values))
	for metric, value := range values {
		metricType := dto.MetricType_GAUGE
		sample := &dto.Metric{Gauge: &dto.Gauge{Value: float64Pointer(value)}}
		if metric == "stacks_signer_block_responses_sent" {
			metricType = dto.MetricType_COUNTER
			sample = &dto.Metric{Counter: &dto.Counter{Value: float64Pointer(value)}}
		}
		families[metric] = &dto.MetricFamily{Name: stringPointer(metric), Type: &metricType, Metric: []*dto.Metric{sample}}
	}
	return protocolobservation.ActorSnapshot{Source: protocolobservation.Source{
		Actor: name, Role: role, PodName: name + "-0", PodUID: name + "-uid", RuntimeImageID: "sha256:image",
		ServiceName: name, ObservedAt: now, EvidenceClass: protocolobservation.EvidenceActorSelfReported,
	}, Families: families}
}

func setGauge(snapshot *protocolobservation.Snapshot, actor, metric string, value float64) {
	observed, _ := snapshot.Actor(actor)
	observed.Families[metric].Metric[0].Gauge.Value = float64Pointer(value)
}

func setCounter(snapshot *protocolobservation.Snapshot, actor, metric string, value float64) {
	observed, _ := snapshot.Actor(actor)
	observed.Families[metric].Metric[0].Counter.Value = float64Pointer(value)
}

func float64Pointer(value float64) *float64 { return &value }
func stringPointer(value string) *string    { return &value }
