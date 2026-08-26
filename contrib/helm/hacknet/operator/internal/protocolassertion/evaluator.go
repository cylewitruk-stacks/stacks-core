// Package protocolassertion validates and evaluates the finite run-level
// protocol assertion vocabulary.
package protocolassertion

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
)

const maximumAssertionTimeout = time.Hour
const maximumObservationAge = 30 * time.Second
const maximumActorReferences = 256

const (
	// OutcomePending waits for sufficient trusted evidence.
	OutcomePending = "Pending"
	// OutcomeProven records a satisfied assertion.
	OutcomeProven = "Proven"
	// OutcomeViolated records a protocol value outside the declared bound.
	OutcomeViolated = "Violated"
	// OutcomeInconclusive records unavailable evidence at the assertion deadline.
	OutcomeInconclusive = "Inconclusive"
)

type evidence struct {
	NetworkUID      string                       `json:"networkUID"`
	InventoryDigest string                       `json:"inventoryDigest"`
	ObservedAt      time.Time                    `json:"observedAt"`
	Baseline        map[string]float64           `json:"baseline,omitempty"`
	Current         map[string]float64           `json:"current,omitempty"`
	Sources         []protocolobservation.Source `json:"sources,omitempty"`
}

type unavailableEvidenceError struct{ reason string }

func (e unavailableEvidenceError) Error() string { return e.reason }

// ValidateStructure checks assertion-local bounds without requiring an
// admitted actor inventory. It is shared by the CLI and schedule admission.
func ValidateStructure(set *attacknetv1beta1.ProtocolAssertionSetSpec) error {
	if set == nil {
		return nil
	}
	if set.Timeout.Duration <= 0 || set.Timeout.Duration > maximumAssertionTimeout {
		return errors.New("protocol assertion timeout must be within 1ns..1h")
	}
	if len(set.Assertions) == 0 || len(set.Assertions) > 32 {
		return errors.New("protocol assertion set requires 1..32 assertions")
	}
	seen := map[string]bool{}
	actorReferences := 0
	for _, assertion := range set.Assertions {
		if assertion.ID == "" || seen[assertion.ID] {
			return fmt.Errorf("protocol assertion IDs must be non-empty and unique: %q", assertion.ID)
		}
		seen[assertion.ID] = true
		kind, selected, err := assertionKind(assertion)
		if err != nil {
			return fmt.Errorf("protocol assertion %q: %w", assertion.ID, err)
		}
		if err := validateBounds(assertion, set.Timeout.Duration); err != nil {
			return fmt.Errorf("protocol assertion %q: %w", assertion.ID, err)
		}
		if err := validateActorList(selected, kind); err != nil {
			return fmt.Errorf("protocol assertion %q: %w", assertion.ID, err)
		}
		actorReferences += len(selected)
	}
	if actorReferences > maximumActorReferences {
		return fmt.Errorf("protocol assertion set exceeds %d actor references", maximumActorReferences)
	}
	return nil
}

// ValidateSet checks assertion-local bounds and admitted actor-role membership.
func ValidateSet(set *attacknetv1beta1.ProtocolAssertionSetSpec, actors map[string]string) error {
	if err := ValidateStructure(set); err != nil || set == nil {
		return err
	}
	for _, assertion := range set.Assertions {
		kind, selected, _ := assertionKind(assertion)
		if err := validateActorRoles(selected, actors, kind); err != nil {
			return fmt.Errorf("protocol assertion %q: %w", assertion.ID, err)
		}
	}
	return nil
}

// EvaluateSet deterministically advances one bounded assertion set. Missing
// evidence waits until the set deadline and then becomes Inconclusive.
func EvaluateSet(
	set attacknetv1beta1.ProtocolAssertionSetSpec,
	prior *attacknetv1beta1.ProtocolAssertionSetStatus,
	snapshot protocolobservation.Snapshot,
	now time.Time,
) (attacknetv1beta1.ProtocolAssertionSetStatus, error) {
	now = now.UTC()
	status := attacknetv1beta1.ProtocolAssertionSetStatus{Outcome: OutcomePending}
	if prior != nil {
		status = *prior.DeepCopy()
	}
	if status.StartedAt == nil {
		started := metav1.NewTime(now)
		status.StartedAt = &started
	}
	priorByID := make(map[string]attacknetv1beta1.ProtocolAssertionResult, len(status.Results))
	for _, result := range status.Results {
		priorByID[result.ID] = result
	}
	results := make([]attacknetv1beta1.ProtocolAssertionResult, 0, len(set.Assertions))
	for _, assertion := range set.Assertions {
		result, err := evaluate(assertion, priorByID[assertion.ID], snapshot, now)
		if err != nil {
			return attacknetv1beta1.ProtocolAssertionSetStatus{}, err
		}
		if result.Outcome == OutcomePending && now.Sub(status.StartedAt.Time) >= set.Timeout.Duration {
			result.Outcome = OutcomeInconclusive
			result.Reason += "DeadlineExceeded"
			observed := metav1.NewTime(now)
			result.ObservedAt = &observed
		}
		results = append(results, result)
	}
	status.Results = results
	status.Outcome = aggregate(results)
	if status.Outcome == OutcomeProven || status.Outcome == OutcomeViolated || status.Outcome == OutcomeInconclusive {
		completed := metav1.NewTime(now)
		status.CompletedAt = &completed
	} else {
		status.CompletedAt = nil
	}
	return status, nil
}

// ConcludeUnavailable closes an assertion set when its measurement window has
// ended before every assertion produced a terminal result. Existing terminal
// results are retained; unresolved results become Inconclusive.
func ConcludeUnavailable(
	set attacknetv1beta1.ProtocolAssertionSetSpec,
	prior *attacknetv1beta1.ProtocolAssertionSetStatus,
	now time.Time,
	reason string,
) (attacknetv1beta1.ProtocolAssertionSetStatus, error) {
	now = now.UTC()
	if err := ValidateStructure(&set); err != nil {
		return attacknetv1beta1.ProtocolAssertionSetStatus{}, err
	}
	status := attacknetv1beta1.ProtocolAssertionSetStatus{}
	if prior != nil {
		status = *prior.DeepCopy()
	}
	if status.StartedAt == nil {
		started := metav1.NewTime(now)
		status.StartedAt = &started
	}
	priorByID := make(map[string]attacknetv1beta1.ProtocolAssertionResult, len(status.Results))
	for _, result := range status.Results {
		priorByID[result.ID] = result
	}
	results := make([]attacknetv1beta1.ProtocolAssertionResult, 0, len(set.Assertions))
	for _, assertion := range set.Assertions {
		kind, _, err := assertionKind(assertion)
		if err != nil {
			return attacknetv1beta1.ProtocolAssertionSetStatus{}, err
		}
		result, found := priorByID[assertion.ID]
		if !found {
			started := metav1.NewTime(now)
			result = attacknetv1beta1.ProtocolAssertionResult{ID: assertion.ID, Type: kind, StartedAt: &started}
		}
		if result.Outcome == "" || result.Outcome == OutcomePending {
			result = terminalResult(result, OutcomeInconclusive, reason, now)
		}
		results = append(results, result)
	}
	completed := metav1.NewTime(now)
	status.Results = results
	status.Outcome = aggregate(results)
	status.CompletedAt = &completed
	return status, nil
}

func evaluate(
	assertion attacknetv1beta1.ProtocolAssertionSpec,
	prior attacknetv1beta1.ProtocolAssertionResult,
	snapshot protocolobservation.Snapshot,
	now time.Time,
) (attacknetv1beta1.ProtocolAssertionResult, error) {
	kind, actors, err := assertionKind(assertion)
	if err != nil {
		return attacknetv1beta1.ProtocolAssertionResult{}, err
	}
	result := attacknetv1beta1.ProtocolAssertionResult{ID: assertion.ID, Type: kind, Outcome: OutcomePending, Reason: "WaitingForEvidence"}
	if prior.StartedAt != nil {
		result.StartedAt = prior.StartedAt.DeepCopy()
	} else {
		started := metav1.NewTime(now)
		result.StartedAt = &started
	}
	current, sources, readErr := values(assertion, actors, snapshot, now)
	if readErr != nil {
		var unavailable unavailableEvidenceError
		if errors.As(readErr, &unavailable) {
			result.Reason = unavailable.reason
		}
		result.Evidence = prior.Evidence
		return result, nil
	}
	value := evidence{
		NetworkUID: snapshot.NetworkUID, InventoryDigest: snapshot.InventoryDigest,
		ObservedAt: snapshot.ObservedAt, Current: current, Sources: sources,
	}
	if isWindowed(assertion) {
		if prior.Outcome == OutcomeProven || prior.Outcome == OutcomeViolated {
			return prior, nil
		}
		if len(prior.Evidence.Raw) == 0 {
			value.Baseline = current
			result.Evidence, err = marshalEvidence(value)
			if err != nil {
				return result, err
			}
			return result, nil
		}
		var previous evidence
		if err := json.Unmarshal(prior.Evidence.Raw, &previous); err != nil || len(previous.Baseline) == 0 {
			return result, errors.New("protocol assertion baseline evidence is malformed")
		}
		if previous.ObservedAt.IsZero() || previous.ObservedAt.After(now) {
			return result, errors.New("protocol assertion baseline observation time is malformed")
		}
		if previous.NetworkUID != value.NetworkUID ||
			previous.InventoryDigest != value.InventoryDigest ||
			!sameSourceIdentities(previous.Sources, value.Sources) {
			result.Reason = "ObservationIdentityChanged"
			result.Evidence = prior.Evidence
			return result, nil
		}
		value.Baseline = previous.Baseline
		// The observation window is anchored to the first valid baseline. Current
		// source timestamps remain available in value.Sources.
		value.ObservedAt = previous.ObservedAt
		result.Evidence, err = marshalEvidence(value)
		if err != nil {
			return result, err
		}
		window := assertionWindow(assertion)
		if now.Sub(previous.ObservedAt) < window {
			return result, nil
		}
		if windowSatisfied(assertion, value.Baseline, current) {
			return terminalResult(result, OutcomeProven, "RequiredProgressObserved", now), nil
		}
		return terminalResult(result, OutcomeViolated, "RequiredProgressAbsent", now), nil
	}
	result.Evidence, err = marshalEvidence(value)
	if err != nil {
		return result, err
	}
	if statelessSatisfied(assertion, current) {
		return terminalResult(result, OutcomeProven, "AssertionSatisfied", now), nil
	}
	return terminalResult(result, OutcomeViolated, "AssertionViolated", now), nil
}

func sameSourceIdentities(left, right []protocolobservation.Source) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Actor != right[index].Actor ||
			left[index].Role != right[index].Role ||
			left[index].PodName != right[index].PodName ||
			left[index].PodUID != right[index].PodUID ||
			left[index].RuntimeImageID != right[index].RuntimeImageID ||
			left[index].ServiceName != right[index].ServiceName ||
			left[index].EvidenceClass != right[index].EvidenceClass {
			return false
		}
	}
	return true
}

func values(assertion attacknetv1beta1.ProtocolAssertionSpec, actors []string, snapshot protocolobservation.Snapshot, now time.Time) (map[string]float64, []protocolobservation.Source, error) {
	if snapshot.UnavailableReason != "" || snapshot.ObservedAt.IsZero() {
		return nil, nil, unavailableEvidenceError{reason: "IdentityObservationUnavailable"}
	}
	if now.Sub(snapshot.ObservedAt) > maximumObservationAge || snapshot.ObservedAt.After(now.Add(5*time.Second)) {
		return nil, nil, unavailableEvidenceError{reason: "ObservationStale"}
	}
	result := make(map[string]float64, len(actors))
	sources := make([]protocolobservation.Source, 0, len(actors))
	for _, name := range actors {
		actor, ok := snapshot.Actor(name)
		if !ok || actor.Error != "" {
			return nil, nil, unavailableEvidenceError{reason: "ActorMetricsUnavailable"}
		}
		if !actor.Source.ObservedAt.Equal(snapshot.ObservedAt) || actor.Source.EvidenceClass != protocolobservation.EvidenceActorSelfReported {
			return nil, nil, unavailableEvidenceError{reason: "ObservationSourceAmbiguous"}
		}
		var value float64
		var err error
		switch {
		case assertion.ChainProgress != nil:
			value, err = actor.Scalar(heightMetric(assertion.ChainProgress.Chain))
			if err == nil && !protocolobservation.IsExactNonNegativeInteger(value) {
				err = errors.New("invalid height metric")
			}
		case assertion.CohortAgreement != nil:
			value, err = actor.Scalar(heightMetric(assertion.CohortAgreement.Chain))
			if err == nil && !protocolobservation.IsExactNonNegativeInteger(value) {
				err = errors.New("invalid height metric")
			}
		case assertion.SignerRegistration != nil:
			value, err = actor.Scalar("stacks_signer_registered_for_current_reward_cycle")
			if err == nil && !protocolobservation.IsBooleanGauge(value) {
				err = errors.New("invalid registration metric")
			}
		case assertion.SignerStateFreshness != nil:
			var changed float64
			changed, err = actor.Scalar("stacks_signer_state_last_changed_timestamp_seconds")
			if err == nil {
				age, valid := protocolobservation.MetricAge(now, changed)
				if !valid {
					err = errors.New("invalid signer timestamp metric")
				} else {
					value = age.Seconds()
				}
			}
		case assertion.ProposalOutcomeVisibility != nil:
			value, err = actor.Sum("stacks_signer_block_responses_sent", nil)
			if err == nil && !protocolobservation.IsExactNonNegativeInteger(value) {
				err = errors.New("invalid proposal outcome metric")
			}
		case assertion.TelemetryCompleteness != nil:
			value = 1
		}
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, nil, unavailableEvidenceError{reason: "AssertionMetricUnavailable"}
		}
		result[name] = value
		sources = append(sources, actor.Source)
	}
	return result, sources, nil
}

func assertionKind(value attacknetv1beta1.ProtocolAssertionSpec) (string, []string, error) {
	kinds := 0
	kind := ""
	var actors []string
	set := func(name string, selected []string) {
		kinds++
		kind, actors = name, selected
	}
	if value.ChainProgress != nil {
		set("ChainProgress", value.ChainProgress.Actors)
	}
	if value.CohortAgreement != nil {
		set("CohortAgreement", value.CohortAgreement.Actors)
	}
	if value.SignerRegistration != nil {
		set("SignerRegistration", value.SignerRegistration.Actors)
	}
	if value.SignerStateFreshness != nil {
		set("SignerStateFreshness", value.SignerStateFreshness.Actors)
	}
	if value.ProposalOutcomeVisibility != nil {
		set("ProposalOutcomeVisibility", value.ProposalOutcomeVisibility.Actors)
	}
	if value.TelemetryCompleteness != nil {
		set("TelemetryCompleteness", value.TelemetryCompleteness.Actors)
	}
	if kinds != 1 {
		return "", nil, errors.New("exactly one protocol assertion must be configured")
	}
	return kind, append([]string(nil), actors...), nil
}

func validateActorList(selected []string, kind string) error {
	minimumActors := 1
	if kind == "CohortAgreement" {
		minimumActors = 2
	}
	if len(selected) < minimumActors || len(selected) > 64 {
		return fmt.Errorf("%s requires %d..64 actors", kind, minimumActors)
	}
	seen := map[string]bool{}
	for _, actor := range selected {
		if actor == "" || seen[actor] {
			return fmt.Errorf("actor %q is empty or duplicated", actor)
		}
		seen[actor] = true
	}
	return nil
}

func validateActorRoles(selected []string, actors map[string]string, kind string) error {
	for _, actor := range selected {
		role, ok := actors[actor]
		if !ok {
			return fmt.Errorf("actor %q is absent from the admitted inventory", actor)
		}
		if !roleSupportsMetrics(role) {
			return fmt.Errorf("actor %q role %q has no protocol metrics contract", actor, role)
		}
		if (kind == "SignerRegistration" || kind == "SignerStateFreshness" || kind == "ProposalOutcomeVisibility") && role != "signer" {
			return fmt.Errorf("actor %q must have signer role for %s", actor, kind)
		}
		if (kind == "ChainProgress" || kind == "CohortAgreement") && role == "signer" {
			return fmt.Errorf("actor %q cannot have signer role for %s", actor, kind)
		}
	}
	return nil
}

func roleSupportsMetrics(role string) bool {
	return role == "miner" || role == "follower" || role == "companion" || role == "adversary" || role == "signer"
}

func validateBounds(value attacknetv1beta1.ProtocolAssertionSpec, timeout time.Duration) error {
	switch {
	case value.ChainProgress != nil:
		if heightMetric(value.ChainProgress.Chain) == "" || value.ChainProgress.MinimumDelta < 1 || value.ChainProgress.Window.Duration <= 0 || value.ChainProgress.Window.Duration > timeout {
			return errors.New("chain progress requires a supported chain, positive delta, and window within timeout")
		}
	case value.CohortAgreement != nil:
		if heightMetric(value.CohortAgreement.Chain) == "" || value.CohortAgreement.MaximumSpread < 0 {
			return errors.New("cohort agreement requires a supported chain and non-negative spread")
		}
	case value.SignerRegistration != nil:
		if value.SignerRegistration.MinimumRegistered < 1 || int(value.SignerRegistration.MinimumRegistered) > len(value.SignerRegistration.Actors) {
			return errors.New("minimumRegistered must be within the selected signer count")
		}
	case value.SignerStateFreshness != nil:
		if value.SignerStateFreshness.MaximumAge.Duration <= 0 || value.SignerStateFreshness.MaximumAge.Duration > maximumAssertionTimeout {
			return errors.New("maximumAge must be within 1ns..1h")
		}
	case value.ProposalOutcomeVisibility != nil:
		if value.ProposalOutcomeVisibility.MinimumObserved < 1 || value.ProposalOutcomeVisibility.Window.Duration <= 0 || value.ProposalOutcomeVisibility.Window.Duration > timeout {
			return errors.New("proposal outcome visibility requires a positive count and window within timeout")
		}
	}
	return nil
}

func heightMetric(chain string) string {
	if chain == "burnchain" {
		return "stacks_node_burn_block_height"
	}
	if chain == "stacks" {
		return "stacks_node_stacks_tip_height"
	}
	return ""
}

func isWindowed(value attacknetv1beta1.ProtocolAssertionSpec) bool {
	return value.ChainProgress != nil || value.ProposalOutcomeVisibility != nil
}

func assertionWindow(value attacknetv1beta1.ProtocolAssertionSpec) time.Duration {
	if value.ChainProgress != nil {
		return value.ChainProgress.Window.Duration
	}
	return value.ProposalOutcomeVisibility.Window.Duration
}

func windowSatisfied(value attacknetv1beta1.ProtocolAssertionSpec, baseline, current map[string]float64) bool {
	minimum := float64(0)
	if value.ChainProgress != nil {
		minimum = float64(value.ChainProgress.MinimumDelta)
	} else {
		minimum = float64(value.ProposalOutcomeVisibility.MinimumObserved)
	}
	for actor, initial := range baseline {
		if current[actor]-initial < minimum {
			return false
		}
	}
	return true
}

func statelessSatisfied(value attacknetv1beta1.ProtocolAssertionSpec, current map[string]float64) bool {
	switch {
	case value.CohortAgreement != nil:
		minimumValue, maximumValue := math.Inf(1), math.Inf(-1)
		for _, observed := range current {
			minimumValue = math.Min(minimumValue, observed)
			maximumValue = math.Max(maximumValue, observed)
		}
		return maximumValue-minimumValue <= float64(value.CohortAgreement.MaximumSpread)
	case value.SignerRegistration != nil:
		count := 0
		for _, observed := range current {
			if observed >= 1 {
				count++
			}
		}
		return count >= int(value.SignerRegistration.MinimumRegistered)
	case value.SignerStateFreshness != nil:
		for _, age := range current {
			if age < 0 || age > value.SignerStateFreshness.MaximumAge.Duration.Seconds() {
				return false
			}
		}
		return true
	case value.TelemetryCompleteness != nil:
		return len(current) == len(value.TelemetryCompleteness.Actors)
	}
	return false
}

func terminalResult(result attacknetv1beta1.ProtocolAssertionResult, outcome, reason string, now time.Time) attacknetv1beta1.ProtocolAssertionResult {
	result.Outcome, result.Reason = outcome, reason
	observed := metav1.NewTime(now)
	result.ObservedAt = &observed
	return result
}

func marshalEvidence(value any) (apixv1.JSON, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return apixv1.JSON{}, fmt.Errorf("marshal protocol assertion evidence: %w", err)
	}
	return apixv1.JSON{Raw: raw}, nil
}

func aggregate(results []attacknetv1beta1.ProtocolAssertionResult) string {
	outcome := OutcomeProven
	for _, result := range results {
		if result.Outcome == OutcomeViolated {
			return OutcomeViolated
		}
		if result.Outcome == OutcomeInconclusive {
			outcome = OutcomeInconclusive
		} else if result.Outcome == OutcomePending && outcome == OutcomeProven {
			outcome = OutcomePending
		}
	}
	return outcome
}

// ActorRoles builds the validation view from the admitted inventory.
func ActorRoles(actors []attacknetv1beta1.AdmittedActorIdentity) map[string]string {
	result := make(map[string]string, len(actors))
	for _, actor := range actors {
		result[actor.Name] = actor.Role
	}
	return result
}

// SortedIDs returns the finite assertion IDs for diagnostics and tests.
func SortedIDs(set *attacknetv1beta1.ProtocolAssertionSetSpec) []string {
	if set == nil {
		return nil
	}
	result := make([]string, 0, len(set.Assertions))
	for _, assertion := range set.Assertions {
		result = append(result, assertion.ID)
	}
	sort.Strings(result)
	return result
}
