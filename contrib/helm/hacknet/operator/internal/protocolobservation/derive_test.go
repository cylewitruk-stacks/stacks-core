package protocolobservation

import (
	"math"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func TestDeriveProducesConservativeHeightAndFiniteObservations(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := Snapshot{NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", ObservedAt: now, Actors: []ActorSnapshot{
		parsedActor(t, "node-1", "follower", now, `
# TYPE stacks_node_burn_block_height gauge
stacks_node_burn_block_height 50
# TYPE stacks_node_stacks_tip_height gauge
stacks_node_stacks_tip_height 101
`),
		parsedActor(t, "node-2", "miner", now, `
# TYPE stacks_node_burn_block_height gauge
stacks_node_burn_block_height 50
# TYPE stacks_node_stacks_tip_height gauge
stacks_node_stacks_tip_height 100
`),
		parsedActor(t, "signer-1", "signer", now, `
# TYPE stacks_signer_registered_for_current_reward_cycle gauge
stacks_signer_registered_for_current_reward_cycle 1
# TYPE stacks_signer_state_last_changed_timestamp_seconds gauge
stacks_signer_state_last_changed_timestamp_seconds 1699999940
# TYPE stacks_signer_block_responses_sent counter
stacks_signer_block_responses_sent{response_type="accepted"} 2
stacks_signer_block_responses_sent{response_type="rejected"} 3
`),
	}}
	derived, err := Derive(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if derived.StacksHeight == nil || derived.StacksHeight.Height != 100 || !derived.StacksHeight.Source.Trusted || derived.StacksHeight.Source.UID != snapshot.InventoryDigest {
		t.Fatalf("unexpected conservative height: %#v", derived.StacksHeight)
	}
	values := map[string]string{}
	for _, observed := range derived.Observations {
		values[observed.Type+"/"+observed.Actor] = observed.Value
	}
	for key, expected := range map[string]string{
		"telemetry-complete/": "true", "burnchain-cohort-agreement/": "true",
		"stacks-cohort-agreement/": "false", "signer-registered/signer-1": "true",
		"signer-state-fresh/signer-1": "true", "proposal-outcome-visible/signer-1": "true",
	} {
		if values[key] != expected {
			t.Fatalf("observation %s = %q, want %q", key, values[key], expected)
		}
	}
}

func TestDeriveWithholdsMalformedMetricDomains(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tests := []struct {
		name   string
		metric string
		value  float64
		absent string
	}{
		{name: "NaN height", metric: metricStacksHeight, value: math.NaN(), absent: ObservationStacksAgreement},
		{name: "infinite height", metric: metricStacksHeight, value: math.Inf(1), absent: ObservationStacksAgreement},
		{name: "negative height", metric: metricStacksHeight, value: -1, absent: ObservationStacksAgreement},
		{name: "fractional height", metric: metricStacksHeight, value: 1.5, absent: ObservationStacksAgreement},
		{name: "fractional response count", metric: metricBlockResponsesSent, value: 1.5, absent: ObservationProposalOutcomeVisible},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actor := "node-1"
			role := "follower"
			if test.metric == metricBlockResponsesSent {
				actor, role = "signer-1", "signer"
			}
			snapshot := Snapshot{NetworkUID: "network", InventoryDigest: "sha256:inventory", ObservedAt: now, Actors: []ActorSnapshot{
				parsedMetricActor(actor, role, now, test.metric, test.value),
			}}
			derived, err := Derive(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if test.metric == metricStacksHeight && derived.StacksHeight != nil {
				t.Fatalf("malformed height produced a trusted height: %#v", derived.StacksHeight)
			}
			for _, observed := range derived.Observations {
				if observed.Type == test.absent {
					t.Fatalf("malformed metric produced %s: %#v", test.absent, observed)
				}
			}
		})
	}
}

func TestDeriveTreatsFutureSignerTimestampAsNotFresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := Snapshot{NetworkUID: "network", InventoryDigest: "sha256:inventory", ObservedAt: now, Actors: []ActorSnapshot{
		parsedMetricActor("signer-1", "signer", now, metricSignerStateChanged, float64(now.Add(time.Minute).Unix())),
	}}
	derived, err := Derive(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, observed := range derived.Observations {
		if observed.Type == ObservationSignerStateFresh && observed.Value != "false" {
			t.Fatalf("future signer timestamp was reported fresh: %#v", observed)
		}
	}
}

func TestDeriveFailsClosedPerSourceCohort(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := Snapshot{NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", ObservedAt: now, Actors: []ActorSnapshot{
		parsedActor(t, "node-1", "follower", now, `
# TYPE stacks_node_burn_block_height gauge
stacks_node_burn_block_height 50
# TYPE stacks_node_stacks_tip_height gauge
stacks_node_stacks_tip_height 101
`),
		{Source: Source{Actor: "signer-1", Role: "signer", ObservedAt: now}, Error: "offline"},
	}}
	derived, err := Derive(snapshot)
	if err != nil || derived.StacksHeight == nil || derived.StacksHeight.Height != 101 {
		t.Fatalf("unrelated signer outage suppressed complete node evidence: %#v, %v", derived, err)
	}
	values := map[string]string{}
	for _, observed := range derived.Observations {
		values[observed.Type+"/"+observed.Actor] = observed.Value
	}
	if values["telemetry-complete/"] != "false" {
		t.Fatalf("partial snapshot was not reported independently: %#v", values)
	}
	if _, found := values["signer-registered/signer-1"]; found {
		t.Fatalf("unavailable signer produced a signer observation: %#v", values)
	}
}

func TestDeriveDoesNotCoupleIndependentNodeMetricFamilies(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := Snapshot{NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", ObservedAt: now, Actors: []ActorSnapshot{
		parsedActor(t, "node-1", "follower", now, `
# TYPE stacks_node_stacks_tip_height gauge
stacks_node_stacks_tip_height 101
`),
	}}
	derived, err := Derive(snapshot)
	if err != nil || derived.StacksHeight == nil || derived.StacksHeight.Height != 101 {
		t.Fatalf("missing burn metric suppressed independent Stacks evidence: %#v, %v", derived, err)
	}
	for _, observed := range derived.Observations {
		if observed.Type == ObservationBurnchainAgreement {
			t.Fatalf("incomplete burn cohort produced an observation: %#v", observed)
		}
	}
}

func parsedActor(t *testing.T, name, role string, now time.Time, body string) ActorSnapshot {
	t.Helper()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return ActorSnapshot{Source: Source{
		Actor: name, Role: role, PodName: name + "-0", PodUID: name + "-uid",
		RuntimeImageID: "sha256:image", ServiceName: name, ObservedAt: now,
		EvidenceClass: EvidenceActorSelfReported,
	}, Families: families}
}

func parsedMetricActor(name, role string, now time.Time, metric string, value float64) ActorSnapshot {
	bodyType := dto.MetricType_GAUGE
	sample := &dto.Metric{Gauge: &dto.Gauge{Value: &value}}
	if metric == metricBlockResponsesSent {
		bodyType = dto.MetricType_COUNTER
		sample = &dto.Metric{Counter: &dto.Counter{Value: &value}}
	}
	return ActorSnapshot{Source: Source{
		Actor: name, Role: role, PodName: name + "-0", PodUID: name + "-uid",
		RuntimeImageID: "sha256:image", ServiceName: name, ObservedAt: now,
		EvidenceClass: EvidenceActorSelfReported,
	}, Families: map[string]*dto.MetricFamily{
		metric: {Name: &metric, Type: &bodyType, Metric: []*dto.Metric{sample}},
	}}
}
