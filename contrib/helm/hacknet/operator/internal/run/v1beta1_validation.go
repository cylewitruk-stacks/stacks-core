package run

import (
	"errors"
	"fmt"
	"regexp"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolassertion"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

var fuzzDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateV1Beta1Structure validates run-local invariants without reading
// campaign templates, admitted identities, or prior run state.
func ValidateV1Beta1Structure(run *attacknetv1beta1.AttacknetRun) error {
	if run == nil {
		return errors.New("run is required")
	}
	if run.Spec.NetworkRef == "" || run.Spec.Seed == "" {
		return errors.New("networkRef and seed are required")
	}
	if run.Spec.DecisionAlgorithm != "" && run.Spec.DecisionAlgorithm != betaDecisionAlgorithm {
		return fmt.Errorf("unsupported decision algorithm %q", run.Spec.DecisionAlgorithm)
	}
	if err := validateFuzzProvenance(
		run.Spec.FuzzProvenance,
		run.Labels["testing.stacks.org/fuzz-session"],
	); err != nil {
		return err
	}
	if err := validateBetaRunBudgets(run.Spec.Budgets); err != nil {
		return err
	}
	if run.Spec.Budgets.MaxCumulativeFaultSeconds > run.Spec.Budgets.MaxWallTimeSeconds {
		return errors.New("maxCumulativeFaultSeconds cannot exceed maxWallTimeSeconds")
	}
	if err := ValidatePolicies(run.Spec.StopPolicy, run.Spec.AttributionPolicy); err != nil {
		return err
	}
	for _, gate := range []struct {
		name string
		set  *attacknetv1beta1.ProtocolAssertionSetSpec
	}{
		{name: "baseline", set: run.Spec.BaselineAssertions},
		{name: "during", set: run.Spec.DuringAssertions},
		{name: "recovery", set: run.Spec.RecoveryAssertions},
	} {
		if err := protocolassertion.ValidateStructure(gate.set); err != nil {
			return fmt.Errorf("%s protocol assertions: %w", gate.name, err)
		}
	}
	if len(run.Spec.CampaignCatalog) > 256 || len(run.Spec.UpgradeCatalog) > 64 || len(run.Spec.CampaignCatalog)+len(run.Spec.UpgradeCatalog) == 0 {
		return errors.New("run requires a bounded fault or upgrade catalog")
	}
	catalog := make(map[string]struct{}, len(run.Spec.CampaignCatalog)+len(run.Spec.UpgradeCatalog))
	upgradeAliases := make(map[string]struct{}, len(run.Spec.UpgradeCatalog))
	for _, entry := range run.Spec.UpgradeCatalog {
		if entry.Name == "" || entry.UpgradeRef == "" {
			return errors.New("upgrade catalog names and references must be non-empty")
		}
		if _, duplicate := catalog[entry.Name]; duplicate {
			return fmt.Errorf("duplicate catalog alias %q", entry.Name)
		}
		catalog[entry.Name] = struct{}{}
		upgradeAliases[entry.Name] = struct{}{}
	}
	for _, entry := range run.Spec.CampaignCatalog {
		if entry.Name == "" || entry.CampaignRef == "" {
			return errors.New("campaign catalog names and references must be non-empty")
		}
		if _, duplicate := catalog[entry.Name]; duplicate {
			return fmt.Errorf("duplicate campaign alias %q", entry.Name)
		}
		catalog[entry.Name] = struct{}{}
	}
	if len(run.Spec.Executions) == 0 || len(run.Spec.Executions) > 1024 {
		return errors.New("executions requires between 1 and 1024 entries")
	}
	executions := make(map[string]int, len(run.Spec.Executions))
	enabled := make(map[string]bool, len(run.Spec.Executions))
	enabledCount := int32(0)
	enabledUpgradeCount := 0
	for index, execution := range run.Spec.Executions {
		alias := execution.Campaign
		if execution.Upgrade != "" {
			alias = execution.Upgrade
		}
		if execution.ID == "" || alias == "" || (execution.Campaign != "" && execution.Upgrade != "") {
			return errors.New("execution IDs and campaign aliases must be non-empty")
		}
		if _, duplicate := executions[execution.ID]; duplicate {
			return fmt.Errorf("duplicate execution ID %q", execution.ID)
		}
		if _, found := catalog[alias]; !found {
			return fmt.Errorf("execution %q references unknown campaign alias %q (or upgrade alias)", execution.ID, alias)
		}
		executions[execution.ID] = index
		enabled[execution.ID] = execution.Enabled == nil || *execution.Enabled
		if enabled[execution.ID] {
			enabledCount++
			if execution.Upgrade != "" {
				enabledUpgradeCount++
			}
		}
		if _, err := trigger.ForRunExecution(execution); err != nil {
			return err
		}
	}
	if enabledCount == 0 {
		return errors.New("run resolves to no enabled executions")
	}
	if enabledUpgradeCount > 1 {
		return errors.New("a run supports one UpgradeCampaign execution; express rollout batches as stages in that campaign")
	}
	if enabledCount > run.Spec.Budgets.MaxCampaigns {
		return fmt.Errorf("enabled execution count %d exceeds maxCampaigns budget %d", enabledCount, run.Spec.Budgets.MaxCampaigns)
	}
	for index, execution := range run.Spec.Executions {
		for _, dependency := range execution.DependsOn {
			dependencyIndex, found := executions[dependency.Execution]
			if !found {
				return fmt.Errorf("execution %q depends on unknown execution %q", execution.ID, dependency.Execution)
			}
			if dependencyIndex >= index {
				return fmt.Errorf("execution %q must depend on an earlier execution, got %q", execution.ID, dependency.Execution)
			}
			if !enabled[dependency.Execution] {
				return fmt.Errorf("execution %q depends on disabled execution %q", execution.ID, dependency.Execution)
			}
			dependencyExecution := run.Spec.Executions[dependencyIndex]
			if _, isUpgrade := upgradeAliases[dependencyExecution.Upgrade]; isUpgrade && dependency.State != "Terminal" {
				return fmt.Errorf("execution %q must wait for upgrade execution %q at Terminal", execution.ID, dependency.Execution)
			}
		}
	}
	return validateV1Beta1ReplayModes(run.Spec)
}

func validateFuzzProvenance(value *attacknetv1beta1.FuzzProvenance, sessionID string) error {
	if value == nil {
		return nil
	}
	if !fuzzDigestPattern.MatchString(value.SessionDigest) ||
		!fuzzDigestPattern.MatchString(value.PlanDigest) ||
		!fuzzDigestPattern.MatchString(value.DecisionDigest) ||
		value.TrialOrdinal < 1 || value.TrialOrdinal > 256 ||
		len(kubevalidation.IsDNS1123Label(sessionID)) != 0 ||
		len(kubevalidation.IsDNS1123Label(value.AttemptID)) != 0 ||
		value.AttemptKind != "Source" &&
			value.AttemptKind != "Confirmation" &&
			value.AttemptKind != "Reduction" {
		return errors.New("fuzzProvenance contains invalid or incomplete immutable identity")
	}
	return nil
}

func validateV1Beta1ReplayModes(spec attacknetv1beta1.AttacknetRunSpec) error {
	enabled := 0
	for _, value := range []bool{spec.Replay.Enabled, spec.Resume.Enabled, spec.Minimization.Enabled} {
		if value {
			enabled++
		}
	}
	if enabled > 1 {
		return errors.New("replay, resume, and minimization are mutually exclusive")
	}
	if spec.Replay.Enabled {
		if spec.Replay.SourceRunRef == "" || spec.Replay.DescriptorURI == "" || spec.Replay.DescriptorDigest == "" || spec.Replay.AttemptID == "" {
			return errors.New("enabled replay requires sourceRunRef, descriptorURI, descriptorDigest, and attemptId")
		}
		if spec.Replay.VerifyExpectedFailure && (spec.Replay.ExpectedAssertion == "" || spec.Replay.ExpectedStatus == "") {
			return errors.New("expected-failure replay requires expectedAssertion and expectedStatus")
		}
	}
	if spec.Resume.Enabled && (spec.Resume.SourceRunRef == "" || spec.Resume.AfterExecutionID == "") {
		return errors.New("enabled resume requires sourceRunRef and afterExecutionId")
	}
	if !spec.Minimization.Enabled {
		if spec.Minimization.MaxAttempts != 0 {
			return errors.New("disabled minimization requires maxAttempts=0")
		}
		return nil
	}
	if spec.Minimization.Strategy != "DeltaDebug" || spec.Minimization.MaxAttempts != 1 || !spec.Minimization.RequireFreshNetwork {
		return errors.New("minimization must be one bounded fresh-network DeltaDebug attempt")
	}
	if spec.Minimization.SourceRunRef == "" || spec.Minimization.SourceScheduleDigest == "" || spec.Minimization.AttemptID == "" || spec.Minimization.CandidateDigest == "" || spec.Minimization.ExpectedAssertion == "" || spec.Minimization.ExpectedStatus == "" {
		return errors.New("enabled minimization requires source run, schedule, candidate, attempt, and expected outcome")
	}
	if len(spec.Minimization.Retained) == 0 {
		return errors.New("enabled minimization requires at least one retained execution")
	}
	if err := validateReductionCandidateDigest(spec.Minimization.Retained, spec.Minimization.CandidateDigest); err != nil {
		return err
	}
	return nil
}
