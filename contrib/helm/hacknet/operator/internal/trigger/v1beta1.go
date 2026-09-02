package trigger

import (
	"fmt"
	"time"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

// ForStage converts one v1beta1 stage trigger into the normalized evaluator contract.
func ForStage(stage attacknetv1beta1.FaultStageSpec) (Spec, error) {
	spec := Spec{Subject: stage.ID}
	trigger := stage.Trigger
	if trigger.AfterCampaignStart == nil && trigger.AfterStage == nil && trigger.BurnHeight == nil && trigger.StacksHeight == nil && trigger.Observation == nil {
		immediate := time.Duration(0)
		spec.AfterStart = &immediate
	}
	if trigger.AfterCampaignStart != nil {
		value := trigger.AfterCampaignStart.Duration
		spec.AfterStart = &value
	}
	if trigger.AfterStage != nil {
		spec.AfterDependency = &DependencyRequirement{
			ID: trigger.AfterStage.Stage, State: DependencyState(trigger.AfterStage.State),
			Delay: trigger.AfterStage.Delay.Duration,
		}
	}
	spec.BurnHeight = trigger.BurnHeight
	spec.StacksHeight = trigger.StacksHeight
	if trigger.Observation != nil {
		spec.Observation = observationRequirement(trigger.Observation)
	}
	if _, err := validateSpec(&spec); err != nil {
		return Spec{}, fmt.Errorf("stage %q trigger: %w", stage.ID, err)
	}
	return spec, nil
}

// ForRunExecution converts one v1beta1 run execution and its dependency barriers.
func ForRunExecution(execution attacknetv1beta1.RunExecutionSpec) (Spec, error) {
	spec := Spec{Subject: execution.ID}
	trigger := execution.Trigger
	if trigger.AfterRunStart == nil && trigger.BurnHeight == nil && trigger.StacksHeight == nil && trigger.Observation == nil {
		immediate := time.Duration(0)
		spec.AfterStart = &immediate
	}
	if trigger.AfterRunStart != nil {
		value := trigger.AfterRunStart.Duration
		spec.AfterStart = &value
	}
	spec.BurnHeight = trigger.BurnHeight
	spec.StacksHeight = trigger.StacksHeight
	if trigger.Observation != nil {
		spec.Observation = observationRequirement(trigger.Observation)
	}
	for _, dependency := range execution.DependsOn {
		spec.Dependencies = append(spec.Dependencies, DependencyRequirement{
			ID: dependency.Execution, State: DependencyState(dependency.State), Delay: dependency.Delay.Duration,
		})
	}
	if _, err := validateSpec(&spec); err != nil {
		return Spec{}, fmt.Errorf("run execution %q trigger: %w", execution.ID, err)
	}
	return spec, nil
}

func observationRequirement(value *attacknetv1beta1.ObservationTriggerSpec) *ObservationRequirement {
	return &ObservationRequirement{
		Type: value.Type, Actor: value.Actor, Expected: value.Expected,
		Timeout: time.Duration(value.TimeoutSeconds) * time.Second,
	}
}
