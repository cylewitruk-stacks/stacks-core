// Package trigger evaluates bounded v1beta1 campaign and run triggers without
// reading Kubernetes or advancing a controller state machine.
package trigger

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	maximumInputs       = 256
	maximumStringBytes  = 1024
	maximumTriggerDelay = 24 * time.Hour
)

// Type identifies one mutually exclusive primary trigger mechanism.
type Type string

const (
	// AfterStart waits for an offset from the admitted campaign or run start.
	AfterStart Type = "AfterStart"
	// AfterDependency waits for one prior stage or execution transition.
	AfterDependency Type = "AfterDependency"
	// AtBurnHeight waits for a trusted burnchain-height observation.
	AtBurnHeight Type = "BurnHeight"
	// AtStacksHeight waits for a trusted Stacks-height observation.
	AtStacksHeight Type = "StacksHeight"
	// OnObservation waits for a bounded trusted named observation.
	OnObservation Type = "Observation"
)

// DependencyState is a durable stage or execution transition usable as a barrier.
type DependencyState string

const (
	// DependencyInjected means all intended mutations were observed injected.
	DependencyInjected DependencyState = "Injected"
	// DependencyEffective means the requested effect was independently proven.
	DependencyEffective DependencyState = "Effective"
	// DependencyRecovered means recovery was independently proven.
	DependencyRecovered DependencyState = "Recovered"
	// DependencyTerminal means the dependency reached any durable terminal phase.
	DependencyTerminal DependencyState = "Terminal"
)

// Spec is the normalized trigger and dependency contract for one subject.
// Exactly one primary trigger field must be non-nil. Dependencies are additional
// barriers and are evaluated in stable ID order.
type Spec struct {
	Subject         string
	AfterStart      *time.Duration
	AfterDependency *DependencyRequirement
	BurnHeight      *int64
	StacksHeight    *int64
	Observation     *ObservationRequirement
	Dependencies    []DependencyRequirement
}

// DependencyRequirement waits for a named dependency transition and delay.
type DependencyRequirement struct {
	ID    string
	State DependencyState
	Delay time.Duration
}

// ObservationRequirement selects one bounded trusted observation.
type ObservationRequirement struct {
	Type     string
	Actor    string
	Expected string
	Timeout  time.Duration
}

// Source identifies the trusted object or service that produced evidence.
type Source struct {
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
	Trusted         bool   `json:"trusted"`
}

// HeightObservation is one source-bound chain-height reading.
type HeightObservation struct {
	Height     int64
	ObservedAt time.Time
	Source     Source
}

// Observation is one source-bound invariant or event observation.
type Observation struct {
	ID         string
	Type       string
	Actor      string
	Value      string
	ObservedAt time.Time
	Source     Source
}

// DependencyTransition records when a named durable state was first reached.
type DependencyTransition struct {
	State     DependencyState
	ReachedAt time.Time
}

// DependencyObservation is the bounded transition history of one dependency.
type DependencyObservation struct {
	ID          string
	Source      Source
	Transitions []DependencyTransition
}

// Snapshot contains only the trusted observations needed by the pure evaluator.
type Snapshot struct {
	Now          time.Time
	StartedAt    time.Time
	Dependencies []DependencyObservation
	BurnHeight   *HeightObservation
	StacksHeight *HeightObservation
	Observations []Observation
}

// Evidence records the exact source and value that satisfied one barrier.
type Evidence struct {
	Kind            string          `json:"kind"`
	DependencyID    string          `json:"dependencyId,omitempty"`
	DependencyState DependencyState `json:"dependencyState,omitempty"`
	ObservationID   string          `json:"observationId,omitempty"`
	ObservationType string          `json:"observationType,omitempty"`
	Actor           string          `json:"actor,omitempty"`
	Value           string          `json:"value,omitempty"`
	TargetHeight    *int64          `json:"targetHeight,omitempty"`
	ObservedHeight  *int64          `json:"observedHeight,omitempty"`
	StartedAt       *time.Time      `json:"startedAt,omitempty"`
	EligibleAt      *time.Time      `json:"eligibleAt,omitempty"`
	ObservedAt      time.Time       `json:"observedAt"`
	Source          *Source         `json:"source,omitempty"`
}

// Receipt is the deterministic proof that all trigger barriers were satisfied.
type Receipt struct {
	SchemaVersion string     `json:"schemaVersion"`
	Subject       string     `json:"subject"`
	Trigger       Type       `json:"trigger"`
	SatisfiedAt   time.Time  `json:"satisfiedAt"`
	Evidence      []Evidence `json:"evidence"`
}

// Decision reports trigger eligibility, terminal timeout, and the next exact
// wall-clock instant at which a time-dependent result can change.
type Decision struct {
	Eligible  bool
	Expired   bool
	Reason    string
	RequeueAt *time.Time
	Receipt   *Receipt
}

// Evaluate validates and evaluates one normalized trigger against a snapshot.
func Evaluate(spec Spec, snapshot Snapshot) (Decision, error) {
	spec.Dependencies = append([]DependencyRequirement(nil), spec.Dependencies...)
	triggerType, err := validateSpec(&spec)
	if err != nil {
		return Decision{}, err
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Decision{}, err
	}

	primary, err := evaluatePrimary(spec, triggerType, snapshot)
	if err != nil {
		return Decision{}, err
	}
	components := []component{primary}
	for _, requirement := range spec.Dependencies {
		value, err := evaluateDependency(requirement, snapshot)
		if err != nil {
			return Decision{}, err
		}
		components = append(components, value)
	}

	decision := Decision{Reason: "WaitingForTrigger"}
	var satisfiedAt time.Time
	evidence := make([]Evidence, 0, len(components))
	for _, value := range components {
		if value.expired {
			return Decision{Expired: true, Reason: value.reason}, nil
		}
		if !value.ready {
			if decision.Reason == "WaitingForTrigger" && value.reason != "" {
				decision.Reason = value.reason
			}
			decision.RequeueAt = earlier(decision.RequeueAt, value.requeueAt)
			continue
		}
		if value.satisfiedAt.After(satisfiedAt) {
			satisfiedAt = value.satisfiedAt
		}
		evidence = append(evidence, value.evidence)
	}
	if len(evidence) != len(components) {
		return decision, nil
	}
	return Decision{
		Eligible: true,
		Reason:   "TriggerSatisfied",
		Receipt: &Receipt{
			SchemaVersion: "stacks-attacknet-trigger-receipt/v1",
			Subject:       spec.Subject,
			Trigger:       triggerType,
			SatisfiedAt:   canonicalTime(satisfiedAt),
			Evidence:      evidence,
		},
	}, nil
}

type component struct {
	ready       bool
	expired     bool
	reason      string
	requeueAt   *time.Time
	satisfiedAt time.Time
	evidence    Evidence
}

func evaluatePrimary(spec Spec, triggerType Type, snapshot Snapshot) (component, error) {
	switch triggerType {
	case AfterStart:
		eligibleAt := snapshot.StartedAt.Add(*spec.AfterStart)
		if snapshot.Now.Before(eligibleAt) {
			return waiting("WaitingForStartOffset", eligibleAt), nil
		}
		startedAt := canonicalTime(snapshot.StartedAt)
		eligibleAt = canonicalTime(eligibleAt)
		return satisfied(eligibleAt, Evidence{Kind: string(AfterStart), StartedAt: &startedAt, EligibleAt: &eligibleAt, ObservedAt: eligibleAt}), nil
	case AfterDependency:
		return evaluateDependency(*spec.AfterDependency, snapshot)
	case AtBurnHeight:
		return evaluateHeight(string(AtBurnHeight), *spec.BurnHeight, snapshot.BurnHeight, snapshot)
	case AtStacksHeight:
		return evaluateHeight(string(AtStacksHeight), *spec.StacksHeight, snapshot.StacksHeight, snapshot)
	case OnObservation:
		return evaluateObservation(*spec.Observation, snapshot)
	default:
		return component{}, fmt.Errorf("unsupported trigger type %q", triggerType)
	}
}

func evaluateDependency(requirement DependencyRequirement, snapshot Snapshot) (component, error) {
	var observed *DependencyObservation
	for index := range snapshot.Dependencies {
		if snapshot.Dependencies[index].ID == requirement.ID {
			observed = &snapshot.Dependencies[index]
			break
		}
	}
	if observed == nil {
		return component{reason: "WaitingForDependency"}, nil
	}
	if !observed.Source.Trusted {
		return component{reason: "WaitingForTrustedDependency"}, nil
	}
	for _, transition := range observed.Transitions {
		if transition.State != requirement.State {
			continue
		}
		eligibleAt := transition.ReachedAt.Add(requirement.Delay)
		if snapshot.Now.Before(eligibleAt) {
			return waiting("WaitingForDependencyDelay", eligibleAt), nil
		}
		source := observed.Source
		observedAt := canonicalTime(transition.ReachedAt)
		eligibleAt = canonicalTime(eligibleAt)
		return satisfied(eligibleAt, Evidence{
			Kind: string(AfterDependency), DependencyID: requirement.ID,
			DependencyState: requirement.State, EligibleAt: &eligibleAt,
			ObservedAt: observedAt, Source: &source,
		}), nil
	}
	return component{reason: "WaitingForDependencyState"}, nil
}

func evaluateHeight(kind string, target int64, observed *HeightObservation, snapshot Snapshot) (component, error) {
	if observed == nil {
		return component{reason: "WaitingForHeight"}, nil
	}
	if !observed.Source.Trusted {
		return component{reason: "WaitingForTrustedHeight"}, nil
	}
	if observed.ObservedAt.Before(snapshot.StartedAt) {
		return component{reason: "WaitingForFreshHeight"}, nil
	}
	if observed.Height < target {
		return component{reason: "WaitingForHeight"}, nil
	}
	source := observed.Source
	value := observed.Height
	targetCopy := target
	observedAt := canonicalTime(observed.ObservedAt)
	return satisfied(observedAt, Evidence{
		Kind: kind, TargetHeight: &targetCopy, ObservedHeight: &value,
		ObservedAt: observedAt, Source: &source,
	}), nil
}

func evaluateObservation(requirement ObservationRequirement, snapshot Snapshot) (component, error) {
	deadline := snapshot.StartedAt.Add(requirement.Timeout)
	candidates := make([]Observation, 0)
	for _, observed := range snapshot.Observations {
		if !observed.Source.Trusted || observed.ObservedAt.Before(snapshot.StartedAt) || observed.ObservedAt.After(deadline) {
			continue
		}
		if observed.Type != requirement.Type || requirement.Actor != "" && observed.Actor != requirement.Actor ||
			requirement.Expected != "" && observed.Value != requirement.Expected {
			continue
		}
		candidates = append(candidates, observed)
	}
	if len(candidates) == 0 {
		if !snapshot.Now.Before(deadline) {
			return component{expired: true, reason: "ObservationTimedOut"}, nil
		}
		return waiting("WaitingForObservation", deadline), nil
	}
	sort.Slice(candidates, func(left, right int) bool {
		if !candidates[left].ObservedAt.Equal(candidates[right].ObservedAt) {
			return candidates[left].ObservedAt.Before(candidates[right].ObservedAt)
		}
		if candidates[left].ID != candidates[right].ID {
			return candidates[left].ID < candidates[right].ID
		}
		return candidates[left].Source.UID < candidates[right].Source.UID
	})
	selected := candidates[0]
	source := selected.Source
	observedAt := canonicalTime(selected.ObservedAt)
	return satisfied(observedAt, Evidence{
		Kind: string(OnObservation), ObservationID: selected.ID,
		ObservationType: selected.Type, Actor: selected.Actor, Value: selected.Value,
		ObservedAt: observedAt, Source: &source,
	}), nil
}

func validateSpec(spec *Spec) (Type, error) {
	if err := boundedRequired(spec.Subject, "trigger subject"); err != nil {
		return "", err
	}
	variants := []struct {
		present bool
		kind    Type
	}{
		{spec.AfterStart != nil, AfterStart},
		{spec.AfterDependency != nil, AfterDependency},
		{spec.BurnHeight != nil, AtBurnHeight},
		{spec.StacksHeight != nil, AtStacksHeight},
		{spec.Observation != nil, OnObservation},
	}
	var selected Type
	count := 0
	for _, variant := range variants {
		if variant.present {
			count++
			selected = variant.kind
		}
	}
	if count != 1 {
		return "", fmt.Errorf("trigger must define exactly one primary variant, got %d", count)
	}
	if spec.AfterStart != nil && (*spec.AfterStart < 0 || *spec.AfterStart > maximumTriggerDelay) {
		return "", fmt.Errorf("after-start duration must be within 0..%s", maximumTriggerDelay)
	}
	if (spec.BurnHeight != nil && *spec.BurnHeight < 0) || (spec.StacksHeight != nil && *spec.StacksHeight < 0) {
		return "", errors.New("trigger height must not be negative")
	}
	if spec.Observation != nil {
		if err := boundedRequired(spec.Observation.Type, "observation trigger type"); err != nil {
			return "", err
		}
		if err := boundedOptional(spec.Observation.Actor, "observation trigger actor"); err != nil {
			return "", err
		}
		if err := boundedOptional(spec.Observation.Expected, "observation trigger expected value"); err != nil {
			return "", err
		}
		if spec.Observation.Timeout <= 0 || spec.Observation.Timeout > maximumTriggerDelay {
			return "", fmt.Errorf("observation timeout must be within 1ns..%s", maximumTriggerDelay)
		}
	}
	if spec.AfterDependency != nil {
		if err := validateRequirement(*spec.AfterDependency, spec.Subject); err != nil {
			return "", err
		}
	}
	seen := map[string]struct{}{}
	for _, requirement := range spec.Dependencies {
		if err := validateRequirement(requirement, spec.Subject); err != nil {
			return "", err
		}
		if _, duplicate := seen[requirement.ID]; duplicate {
			return "", fmt.Errorf("duplicate dependency %q", requirement.ID)
		}
		if spec.AfterDependency != nil && requirement.ID == spec.AfterDependency.ID {
			return "", fmt.Errorf("dependency %q duplicates the primary dependency trigger", requirement.ID)
		}
		seen[requirement.ID] = struct{}{}
	}
	sort.Slice(spec.Dependencies, func(left, right int) bool {
		if spec.Dependencies[left].ID != spec.Dependencies[right].ID {
			return spec.Dependencies[left].ID < spec.Dependencies[right].ID
		}
		return spec.Dependencies[left].State < spec.Dependencies[right].State
	})
	return selected, nil
}

func validateRequirement(requirement DependencyRequirement, subject string) error {
	if err := boundedRequired(requirement.ID, "dependency ID"); err != nil {
		return err
	}
	if requirement.ID == subject {
		return fmt.Errorf("subject %q cannot depend on itself", subject)
	}
	if !validDependencyState(requirement.State) {
		return fmt.Errorf("dependency %q has unsupported state %q", requirement.ID, requirement.State)
	}
	if requirement.Delay < 0 || requirement.Delay > maximumTriggerDelay {
		return fmt.Errorf("dependency %q delay must be within 0..%s", requirement.ID, maximumTriggerDelay)
	}
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Now.IsZero() || snapshot.StartedAt.IsZero() {
		return errors.New("snapshot now and start time are required")
	}
	if snapshot.Now.Before(snapshot.StartedAt) {
		return errors.New("snapshot time precedes start time")
	}
	if len(snapshot.Dependencies) > maximumInputs || len(snapshot.Observations) > maximumInputs {
		return fmt.Errorf("snapshot inputs must contain at most %d entries", maximumInputs)
	}
	seenDependencies := map[string]struct{}{}
	for _, dependency := range snapshot.Dependencies {
		if err := boundedRequired(dependency.ID, "dependency observation ID"); err != nil {
			return err
		}
		if _, duplicate := seenDependencies[dependency.ID]; duplicate {
			return fmt.Errorf("duplicate dependency observation %q", dependency.ID)
		}
		seenDependencies[dependency.ID] = struct{}{}
		if err := validateSource(dependency.Source, "dependency "+dependency.ID); err != nil {
			return err
		}
		if len(dependency.Transitions) > 16 {
			return fmt.Errorf("dependency %q has more than 16 transitions", dependency.ID)
		}
		seenStates := map[DependencyState]struct{}{}
		for _, transition := range dependency.Transitions {
			if !validDependencyState(transition.State) {
				return fmt.Errorf("dependency %q has unsupported transition %q", dependency.ID, transition.State)
			}
			if _, duplicate := seenStates[transition.State]; duplicate {
				return fmt.Errorf("dependency %q repeats transition %q", dependency.ID, transition.State)
			}
			seenStates[transition.State] = struct{}{}
			if transition.ReachedAt.IsZero() || transition.ReachedAt.After(snapshot.Now) || transition.ReachedAt.Before(snapshot.StartedAt) {
				return fmt.Errorf("dependency %q transition %q is outside the run window", dependency.ID, transition.State)
			}
		}
	}
	seenObservations := map[string]struct{}{}
	for _, observed := range snapshot.Observations {
		if err := boundedRequired(observed.ID, "observation ID"); err != nil {
			return err
		}
		if _, duplicate := seenObservations[observed.ID]; duplicate {
			return fmt.Errorf("duplicate observation %q", observed.ID)
		}
		seenObservations[observed.ID] = struct{}{}
		if err := boundedRequired(observed.Type, "observation type"); err != nil {
			return err
		}
		if err := boundedOptional(observed.Actor, "observation actor"); err != nil {
			return err
		}
		if err := boundedOptional(observed.Value, "observation value"); err != nil {
			return err
		}
		if observed.ObservedAt.IsZero() || observed.ObservedAt.After(snapshot.Now) {
			return fmt.Errorf("observation %q has an invalid observation time", observed.ID)
		}
		if err := validateSource(observed.Source, "observation "+observed.ID); err != nil {
			return err
		}
	}
	if err := validateHeightObservation(snapshot.BurnHeight, snapshot, "burn height"); err != nil {
		return err
	}
	return validateHeightObservation(snapshot.StacksHeight, snapshot, "Stacks height")
}

func validateHeightObservation(observed *HeightObservation, snapshot Snapshot, field string) error {
	if observed == nil {
		return nil
	}
	if observed.Height < 0 {
		return fmt.Errorf("%s observation must not be negative", field)
	}
	if observed.ObservedAt.IsZero() || observed.ObservedAt.After(snapshot.Now) {
		return fmt.Errorf("%s has an invalid observation time", field)
	}
	return validateSource(observed.Source, field)
}

func validateSource(source Source, field string) error {
	for _, item := range []struct{ name, value string }{
		{"kind", source.Kind}, {"name", source.Name}, {"UID", source.UID},
	} {
		if err := boundedRequired(item.value, field+" source "+item.name); err != nil {
			return err
		}
	}
	for _, item := range []struct{ name, value string }{
		{"namespace", source.Namespace}, {"resourceVersion", source.ResourceVersion},
	} {
		if err := boundedOptional(item.value, field+" source "+item.name); err != nil {
			return err
		}
	}
	return nil
}

func boundedRequired(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return boundedOptional(value, field)
}

func boundedOptional(value, field string) error {
	if len(value) > maximumStringBytes {
		return fmt.Errorf("%s must contain at most %d bytes", field, maximumStringBytes)
	}
	return nil
}

func validDependencyState(state DependencyState) bool {
	return state == DependencyInjected || state == DependencyEffective || state == DependencyRecovered || state == DependencyTerminal
}

func waiting(reason string, requeueAt time.Time) component {
	value := canonicalTime(requeueAt)
	return component{reason: reason, requeueAt: &value}
}

func satisfied(at time.Time, evidence Evidence) component {
	return component{ready: true, satisfiedAt: canonicalTime(at), evidence: evidence}
}

func earlier(current, candidate *time.Time) *time.Time {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.Before(*current) {
		value := canonicalTime(*candidate)
		return &value
	}
	return current
}

func canonicalTime(value time.Time) time.Time {
	return value.Round(0).UTC()
}
