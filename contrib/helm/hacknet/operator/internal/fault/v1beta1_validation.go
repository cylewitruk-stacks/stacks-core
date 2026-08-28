package fault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/util/intstr"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

// ValidateV1Beta1Structure validates campaign-local invariants that do not
// require an admitted network inventory. The CLI and compiler share this gate.
func ValidateV1Beta1Structure(campaign *attacknetv1beta1.FaultCampaign) error {
	if campaign == nil {
		return errors.New("campaign is required")
	}
	if !campaign.Spec.Template && campaign.Spec.NetworkRef == "" {
		return errors.New("executable campaign requires networkRef")
	}
	if len(campaign.Spec.Stages) == 0 || len(campaign.Spec.Stages) > maximumCampaignStages {
		return fmt.Errorf("campaign requires between 1 and %d stages", maximumCampaignStages)
	}
	if campaign.Spec.Safety.MaxConcurrentFaults < 1 || campaign.Spec.Safety.MaxConcurrentFaults > 512 {
		return errors.New("safety.maxConcurrentFaults must be within 1..512")
	}
	if campaign.Spec.Safety.MaxUnavailableSignerBasisPoints < 0 || campaign.Spec.Safety.MaxUnavailableSignerBasisPoints > 10_000 ||
		campaign.Spec.Safety.MaxUnavailableMinerBasisPoints < 0 || campaign.Spec.Safety.MaxUnavailableMinerBasisPoints > 10_000 {
		return errors.New("signer and miner safety limits must be within 0..10000 basis points")
	}

	stageIndexes := make(map[string]int, len(campaign.Spec.Stages))
	campaignActionIDs := make(map[string]struct{})
	for stageIndex := range campaign.Spec.Stages {
		stage := &campaign.Spec.Stages[stageIndex]
		if !stageIDPattern.MatchString(stage.ID) {
			return fmt.Errorf("stage %d has invalid DNS-label id %q", stageIndex, stage.ID)
		}
		if _, duplicate := stageIndexes[stage.ID]; duplicate {
			return fmt.Errorf("duplicate stage id %q", stage.ID)
		}
		stageIndexes[stage.ID] = stageIndex
		if len(stage.Faults) == 0 || len(stage.Faults) > 32 {
			return fmt.Errorf("stage %q requires between 1 and 32 faults", stage.ID)
		}
		if stage.CompletionPolicy != "" && stage.CompletionPolicy != "all" {
			return fmt.Errorf("stage %q completionPolicy must be all when specified", stage.ID)
		}
		if err := validateStageTrigger(stage.Trigger); err != nil {
			return fmt.Errorf("stage %q trigger: %w", stage.ID, err)
		}

		actionIDs := make(map[string]struct{}, len(stage.Faults))
		for actionIndex := range stage.Faults {
			action := &stage.Faults[actionIndex]
			if !stageIDPattern.MatchString(action.ID) {
				return fmt.Errorf("stage %q action %d has invalid DNS-label id %q", stage.ID, actionIndex, action.ID)
			}
			if _, duplicate := actionIDs[action.ID]; duplicate {
				return fmt.Errorf("stage %q has duplicate action id %q", stage.ID, action.ID)
			}
			actionIDs[action.ID] = struct{}{}
			campaignActionIDs[action.ID] = struct{}{}
			if err := validateV1Beta1Action(action, campaign.Spec.Safety); err != nil {
				return fmt.Errorf("stage %q action %q: %w", stage.ID, action.ID, err)
			}
			assertions := append(append([]attacknetv1beta1.CampaignAssertion{}, action.EffectAssertions...), action.RecoveryAssertions...)
			if err := validateAssertionScope("stage "+stage.ID+" action "+action.ID, assertions, map[string]struct{}{action.ID: {}}, false); err != nil {
				return err
			}
		}
		assertions := append(append([]attacknetv1beta1.CampaignAssertion{}, stage.EffectAssertions...), stage.RecoveryAssertions...)
		if err := validateAssertionScope("stage "+stage.ID, assertions, actionIDs, len(stage.Faults) > 1); err != nil {
			return err
		}
	}
	assertions := append(append([]attacknetv1beta1.CampaignAssertion{}, campaign.Spec.EffectAssertions...), campaign.Spec.RecoveryAssertions...)
	if err := validateAssertionScope("campaign", assertions, campaignActionIDs, campaignActionCount(campaign.Spec.Stages) > 1); err != nil {
		return err
	}
	return validateStageDependencies(campaign.Spec.Stages, stageIndexes)
}

func validateV1Beta1Action(action *attacknetv1beta1.FaultActionSpec, safety attacknetv1beta1.FaultSafety) error {
	if len(action.Target.Actors) == 0 && len(action.Target.Roles) == 0 {
		return errors.New("target requires actors or roles")
	}
	if len(action.Target.Actors) > 64 || len(action.Target.Roles) > 16 {
		return errors.New("target accepts at most 64 actors and 16 roles")
	}
	for _, value := range append(append([]string(nil), action.Target.Actors...), action.Target.Roles...) {
		if !stageIDPattern.MatchString(value) {
			return fmt.Errorf("target value %q must be a DNS label", value)
		}
	}
	if err := validateV1Beta1Mode("fault", action.Fault.Mode, action.Fault.Value); err != nil {
		return err
	}
	if action.Fault.Type == "burnchain-reorg" {
		return validateBurnchainReorgAction(action, safety)
	}
	if action.Fault.BurnchainReorg != nil {
		return errors.New("burnchainReorg is valid only for burnchain-reorg faults")
	}
	definition, err := mechanismForType(action.Fault.Type)
	if err != nil {
		return err
	}
	if len(definition.AllowedActions) > 0 && !definition.AllowedActions[action.Fault.Action] {
		return fmt.Errorf("unsupported %s action %q", action.Fault.Type, action.Fault.Action)
	}
	if len(definition.AllowedActions) == 0 && action.Fault.Action != "" {
		return fmt.Errorf("%s faults must not specify action", action.Fault.Type)
	}
	duration := action.Fault.Duration.Duration
	if duration <= 0 || duration > 24*time.Hour {
		return errors.New("fault.duration must be within 1ns..24h")
	}
	if duration > 10*time.Minute && !safety.AllowExtendedDuration {
		return errors.New("faults longer than 10m require safety.allowExtendedDuration=true")
	}
	if duration > time.Hour && !safety.AllowExtremeSeverity {
		return errors.New("faults longer than 1h require safety.allowExtremeSeverity=true")
	}
	for _, role := range action.Target.Roles {
		if role == "burnchain" && !safety.AllowBurnchain {
			return errors.New("burnchain faults require safety.allowBurnchain=true")
		}
	}
	parameters := map[string]any{}
	if len(action.Fault.Parameters.Raw) > 0 {
		if err := json.Unmarshal(action.Fault.Parameters.Raw, &parameters); err != nil {
			return fmt.Errorf("decode fault parameters: %w", err)
		}
	}
	return validateV1Beta1ParameterPresence(action, parameters, safety)
}

func validateBurnchainReorgAction(action *attacknetv1beta1.FaultActionSpec, safety attacknetv1beta1.FaultSafety) error {
	request := action.Fault.BurnchainReorg
	if request == nil {
		return errors.New("burnchain-reorg requires fault.burnchainReorg")
	}
	if action.Fault.Action != "" || len(action.Fault.Parameters.Raw) != 0 {
		return errors.New("burnchain-reorg does not accept action or raw parameters")
	}
	if action.Fault.Mode != "one" || action.Fault.Value != nil {
		return errors.New("burnchain-reorg requires mode one without value")
	}
	if len(action.Target.Actors) != 1 || len(action.Target.Roles) != 0 || action.Target.Mode != "one" || action.Target.Value != nil {
		return errors.New("burnchain-reorg must name exactly one Bitcoin actor with target mode one and no value")
	}
	if !safety.AllowBurnchain {
		return errors.New("burnchain-reorg requires safety.allowBurnchain=true")
	}
	duration := action.Fault.Duration.Duration
	if duration <= 0 || duration > 24*time.Hour {
		return errors.New("fault.duration must be within 1ns..24h")
	}
	if duration > 10*time.Minute && !safety.AllowExtendedDuration {
		return errors.New("faults longer than 10m require safety.allowExtendedDuration=true")
	}
	if duration > time.Hour && !safety.AllowExtremeSeverity {
		return errors.New("faults longer than 1h require safety.allowExtremeSeverity=true")
	}
	if request.Depth < 1 || request.Depth > 144 {
		return errors.New("burnchainReorg.depth must be within 1..144")
	}
	if request.ReplacementBlocks <= request.Depth || request.ReplacementBlocks > 288 {
		return errors.New("burnchainReorg.replacementBlocks must exceed depth and not exceed 288")
	}
	if request.ReplacementInterval.Duration < 0 || request.ReplacementInterval.Duration > time.Hour {
		return errors.New("burnchainReorg.replacementInterval must be within 0..1h")
	}
	if time.Duration(request.ReplacementBlocks-1)*request.ReplacementInterval.Duration > duration {
		return errors.New("burnchainReorg replacement schedule exceeds fault.duration")
	}
	if request.DestinationIndex < 0 || request.DestinationIndex > 63 {
		return errors.New("burnchainReorg.destinationIndex must be within 0..63")
	}
	if safety.MaxBurnchainReorgDepth < request.Depth {
		return fmt.Errorf("burnchain reorg depth %d exceeds safety maximum %d", request.Depth, safety.MaxBurnchainReorgDepth)
	}
	if safety.MaxBurnchainReplacementBlocks < request.ReplacementBlocks {
		return fmt.Errorf("burnchain replacement blocks %d exceed safety maximum %d", request.ReplacementBlocks, safety.MaxBurnchainReplacementBlocks)
	}
	return nil
}

func validateV1Beta1Mode(field, mode string, value *intstr.IntOrString) error {
	switch mode {
	case "one", "all":
		if value != nil {
			return fmt.Errorf("%s.value is forbidden when mode is %s", field, mode)
		}
	case "fixed", "fixed-percent", "random-max-percent":
		if value == nil {
			return fmt.Errorf("%s.value is required when mode is %s", field, mode)
		}
		number, err := strconv.Atoi(value.String())
		if err != nil || number < 1 {
			return fmt.Errorf("%s.value must be a positive integer for mode %s", field, mode)
		}
		if mode != "fixed" && number > 100 {
			return fmt.Errorf("%s.value must not exceed 100 for mode %s", field, mode)
		}
	default:
		return fmt.Errorf("unsupported %s mode %q", field, mode)
	}
	return nil
}

func validateV1Beta1ParameterPresence(action *attacknetv1beta1.FaultActionSpec, values map[string]any, safety attacknetv1beta1.FaultSafety) error {
	has := func(name string) bool {
		_, present := values[name]
		return present
	}
	require := func(name string) error {
		if !has(name) {
			return fmt.Errorf("%s fault action %s requires parameters.%s", action.Fault.Type, action.Fault.Action, name)
		}
		return nil
	}
	switch action.Fault.Type {
	case "network":
		switch action.Fault.Action {
		case "loss", "duplicate", "corrupt", "bandwidth":
			if err := require(action.Fault.Action); err != nil {
				return err
			}
		case "partition":
			if !has("target") && !has("peerTarget") && !has("harnessTarget") && !has("externalTargets") {
				return errors.New("network fault action partition requires one target parameter")
			}
		}
		forms := 0
		for _, field := range []string{"target", "peerTarget", "harnessTarget", "externalTargets"} {
			if has(field) {
				forms++
			}
		}
		if forms > 1 {
			return errors.New("network faults may use only one target form")
		}
		if (has("target") || has("externalTargets")) && !safety.AllowUnenrolledTargets {
			return errors.New("raw target or externalTargets require safety.allowUnenrolledNetworkTargets=true")
		}
	case "dns":
		return require("patterns")
	case "io":
		if err := require("volumePath"); err != nil {
			return err
		}
		required := map[string]string{"fault": "errno", "mistake": "mistake", "attrOverride": "attr"}
		if field := required[action.Fault.Action]; field != "" {
			return require(field)
		}
	case "io-pressure":
		if len(action.Target.Actors) != 1 || len(action.Target.Roles) != 0 {
			return errors.New("disk-pressure must name exactly one actor target")
		}
		for _, field := range []string{"severity", "workers", "bytesMiB", "writeSizeKiB", "minimumLatencyMultiplier", "minimumAddedLatencyMs"} {
			if err := require(field); err != nil {
				return err
			}
		}
	case "time", "clock-skew":
		return require("timeOffset")
	}
	return nil
}
