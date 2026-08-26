package protocolobservation

import (
	"fmt"
	"sort"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

const (
	metricBurnHeight          = "stacks_node_burn_block_height"
	metricStacksHeight        = "stacks_node_stacks_tip_height"
	metricSignerRegistered    = "stacks_signer_registered_for_current_reward_cycle"
	metricSignerStateChanged  = "stacks_signer_state_last_changed_timestamp_seconds"
	metricBlockResponsesSent  = "stacks_signer_block_responses_sent"
	defaultSignerFreshnessAge = 120 * time.Second
)

const (
	// ObservationTelemetryComplete proves that every admitted actor metrics
	// endpoint was collected inside one stable identity window.
	ObservationTelemetryComplete = "telemetry-complete"
	// ObservationBurnchainAgreement proves that node actors report one burn tip.
	ObservationBurnchainAgreement = "burnchain-cohort-agreement"
	// ObservationStacksAgreement proves that node actors report one Stacks tip.
	ObservationStacksAgreement = "stacks-cohort-agreement"
	// ObservationSignerRegistered reports one signer's current-cycle registration.
	ObservationSignerRegistered = "signer-registered"
	// ObservationSignerStateFresh reports one signer's state-update freshness.
	ObservationSignerStateFresh = "signer-state-fresh"
	// ObservationProposalOutcomeVisible reports one signer's visible proposal outcome.
	ObservationProposalOutcomeVisible = "proposal-outcome-visible"
)

// Derived contains finite trusted trigger inputs derived from one complete
// identity-bound actor snapshot.
type Derived struct {
	StacksHeight *trigger.HeightObservation
	Observations []trigger.Observation
}

// Derive creates finite trigger observations. Each value is withheld when its
// exact source cohort is incomplete; an unrelated endpoint cannot suppress a
// still-complete cohort.
func Derive(snapshot Snapshot) (Derived, error) {
	source := trigger.Source{
		Kind: "ProtocolObservation", Name: snapshot.NetworkUID,
		UID: snapshot.InventoryDigest, Trusted: true,
	}
	derived := Derived{Observations: []trigger.Observation{observation(
		ObservationTelemetryComplete, "", fmt.Sprint(snapshot.Complete()), snapshot.ObservedAt, source,
	)}}
	nodes := actorsByRole(snapshot.Actors, false)
	signers := actorsByRole(snapshot.Actors, true)
	if len(nodes) > 0 {
		burnValues, burnErr := scalarValues(nodes, metricBurnHeight)
		stacksValues, stacksErr := scalarValues(nodes, metricStacksHeight)
		if burnErr == nil && exactNonNegativeIntegers(burnValues) {
			derived.Observations = append(derived.Observations,
				observation(ObservationBurnchainAgreement, "", fmt.Sprint(allEqual(burnValues)), snapshot.ObservedAt, source))
		}
		if stacksErr == nil && exactNonNegativeIntegers(stacksValues) {
			derived.StacksHeight = &trigger.HeightObservation{
				Height: int64(minimum(stacksValues)), ObservedAt: snapshot.ObservedAt, Source: source,
			}
			derived.Observations = append(derived.Observations,
				observation(ObservationStacksAgreement, "", fmt.Sprint(allEqual(stacksValues)), snapshot.ObservedAt, source),
			)
		}
	}
	for _, signer := range signers {
		registered, registeredErr := signer.Scalar(metricSignerRegistered)
		changed, changedErr := signer.Scalar(metricSignerStateChanged)
		responses, responsesErr := signer.Sum(metricBlockResponsesSent, nil)
		if registeredErr == nil && IsBooleanGauge(registered) {
			derived.Observations = append(derived.Observations,
				observation(ObservationSignerRegistered, signer.Source.Actor, fmt.Sprint(registered >= 1), snapshot.ObservedAt, source))
		}
		if age, valid := MetricAge(snapshot.ObservedAt, changed); changedErr == nil && valid {
			fresh := age >= 0 && age <= defaultSignerFreshnessAge
			derived.Observations = append(derived.Observations,
				observation(ObservationSignerStateFresh, signer.Source.Actor, fmt.Sprint(fresh), snapshot.ObservedAt, source))
		}
		if responsesErr == nil && IsExactNonNegativeInteger(responses) {
			derived.Observations = append(derived.Observations,
				observation(ObservationProposalOutcomeVisible, signer.Source.Actor, fmt.Sprint(responses > 0), snapshot.ObservedAt, source))
		}
	}
	sort.Slice(derived.Observations, func(left, right int) bool {
		if derived.Observations[left].Type == derived.Observations[right].Type {
			return derived.Observations[left].Actor < derived.Observations[right].Actor
		}
		return derived.Observations[left].Type < derived.Observations[right].Type
	})
	return derived, nil
}

func exactNonNegativeIntegers(values []float64) bool {
	for _, value := range values {
		if !IsExactNonNegativeInteger(value) {
			return false
		}
	}
	return true
}

func observation(kind, actor, value string, observedAt time.Time, source trigger.Source) trigger.Observation {
	return trigger.Observation{
		ID: kind + "/" + actor, Type: kind, Actor: actor, Value: value,
		ObservedAt: observedAt, Source: source,
	}
}

func actorsByRole(actors []ActorSnapshot, signer bool) []ActorSnapshot {
	result := make([]ActorSnapshot, 0, len(actors))
	for _, actor := range actors {
		if (actor.Source.Role == "signer") == signer {
			result = append(result, actor)
		}
	}
	return result
}

func scalarValues(actors []ActorSnapshot, metric string) ([]float64, error) {
	values := make([]float64, 0, len(actors))
	for _, actor := range actors {
		value, err := actor.Scalar(metric)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func minimum(values []float64) float64 {
	result := values[0]
	for _, value := range values[1:] {
		if value < result {
			result = value
		}
	}
	return result
}

func allEqual(values []float64) bool {
	for _, value := range values[1:] {
		if value != values[0] {
			return false
		}
	}
	return true
}
