package fuzzplan

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	runcontroller "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/run"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidatePlan rejects unbounded or ambiguous fuzz inputs before resolution.
func ValidatePlan(plan Plan) error {
	if plan.SchemaVersion != PlanSchema {
		return fmt.Errorf("schemaVersion must be %s", PlanSchema)
	}
	if problems := kubevalidation.IsDNS1123Label(plan.SessionID); len(problems) != 0 {
		return fmt.Errorf("sessionId is invalid: %s", strings.Join(problems, "; "))
	}
	if plan.Seed == "" || len(plan.Seed) > 256 {
		return errors.New("seed length must be within 1..256 bytes")
	}
	if plan.MaxTrials < 1 || plan.MaxTrials > 256 {
		return errors.New("maxTrials must be within 1..256")
	}
	if plan.MaxDuration.Duration < time.Minute || plan.MaxDuration.Duration > 7*24*time.Hour {
		return errors.New("maxDuration must be within 1m..168h")
	}
	if plan.Network.TemplateFile == "" {
		return errors.New("network.templateFile is required")
	}
	if plan.Network.ExpectedDigest != "" && !digestPattern.MatchString(plan.Network.ExpectedDigest) {
		return errors.New("network.expectedDigest must be a SHA-256 digest")
	}
	if len(plan.Templates) == 0 || len(plan.Templates) > 256 {
		return errors.New("templates count must be within 1..256")
	}
	if err := validateTemplatePlans(plan.Templates); err != nil {
		return err
	}
	if plan.Generation.MinExecutions < 1 ||
		plan.Generation.MaxExecutions < plan.Generation.MinExecutions ||
		plan.Generation.MaxExecutions > 64 {
		return errors.New("generation executions must satisfy 1 <= min <= max <= 64")
	}
	if int(plan.Generation.MaxExecutions) > len(plan.Templates) {
		return errors.New("generation.maxExecutions exceeds selectable templates")
	}
	if len(plan.Generation.Triggers) == 0 || len(plan.Generation.Triggers) > 64 {
		return errors.New("generation.triggers count must be within 1..64")
	}
	for index, candidate := range plan.Generation.Triggers {
		execution := attacknetv1beta1.RunExecutionSpec{
			ID: "candidate", Campaign: "candidate", Trigger: candidate,
		}
		if _, err := trigger.ForRunExecution(execution); err != nil {
			return fmt.Errorf("generation trigger %d: %w", index, err)
		}
	}
	if err := validateRunBudgets(plan); err != nil {
		return err
	}
	if err := runcontroller.ValidatePolicies(plan.Run.StopPolicy, plan.Run.AttributionPolicy); err != nil {
		return fmt.Errorf("run policy: %w", err)
	}
	if plan.Confirmation.RequiredMatches < 1 ||
		plan.Confirmation.RequiredMatches > 5 ||
		plan.Confirmation.MaxAttempts < plan.Confirmation.RequiredMatches ||
		plan.Confirmation.MaxAttempts > 10 {
		return errors.New("confirmation must satisfy 1 <= requiredMatches <= 5 and requiredMatches <= maxAttempts <= 10")
	}
	if plan.Reduction.Enabled {
		if plan.Reduction.MaxAttempts < 1 ||
			plan.Reduction.MaxAttempts > 1024 ||
			plan.Reduction.MaxDuration.Duration < time.Minute ||
			plan.Reduction.MaxDuration.Duration > 7*24*time.Hour ||
			plan.Reduction.MaxEvidenceBytes < MinimumReductionEvidenceBytes ||
			plan.Reduction.MaxEvidenceBytes > 64<<30 {
			return errors.New("enabled reduction requires bounded attempts, duration, and evidence bytes")
		}
	} else if plan.Reduction.MaxAttempts != 0 ||
		plan.Reduction.MaxDuration.Duration != 0 ||
		plan.Reduction.MaxEvidenceBytes != 0 {
		return errors.New("disabled reduction must have zero bounds")
	}
	for name, value := range map[string]int64{
		"minimumNodeBytes":    plan.Capacity.MinimumNodeBytes,
		"minimumImageBytes":   plan.Capacity.MinimumImageBytes,
		"minimumCorpusBytes":  plan.Capacity.MinimumCorpusBytes,
		"storageEscrowBytes":  plan.Capacity.StorageEscrowBytes,
		"evidenceEscrowBytes": plan.Capacity.EvidenceEscrowBytes,
	} {
		if value < 0 || value > 1<<50 {
			return fmt.Errorf("capacity.%s must be within 0..1PiB", name)
		}
	}
	if plan.Capacity.RequirePhysicalEscrow &&
		(plan.Capacity.StorageEscrowBytes < 1<<20 || plan.Capacity.StorageEscrowBytes > 64<<30 ||
			plan.Capacity.EvidenceEscrowBytes < 1 || plan.Capacity.EvidenceEscrowBytes > 64<<30) {
		return errors.New("physical escrow requires storage within 1MiB..64GiB and evidence within 1B..64GiB")
	}
	if plan.Corpus.Root == "" || plan.Corpus.MaximumBytes < 1 || plan.Corpus.MaximumBytes > 1<<50 {
		return errors.New("corpus root and maximumBytes within 1..1PiB are required")
	}
	seenTrials := map[int32]struct{}{}
	for _, advisory := range plan.Advisories {
		if advisory.TrialOrdinal < 1 || advisory.TrialOrdinal > plan.MaxTrials || advisory.File == "" {
			return errors.New("advisory trialOrdinal and file are required and bounded by maxTrials")
		}
		if _, duplicate := seenTrials[advisory.TrialOrdinal]; duplicate {
			return fmt.Errorf("duplicate advisory for trial %d", advisory.TrialOrdinal)
		}
		seenTrials[advisory.TrialOrdinal] = struct{}{}
	}
	return nil
}

func validateTemplatePlans(templates []TemplatePlan) error {
	byID := make(map[string]TemplatePlan, len(templates))
	for _, template := range templates {
		if problems := kubevalidation.IsDNS1123Label(template.ID); len(problems) != 0 {
			return fmt.Errorf("template ID %q is invalid", template.ID)
		}
		if _, duplicate := byID[template.ID]; duplicate {
			return fmt.Errorf("duplicate template ID %q", template.ID)
		}
		if template.Kind != "FaultCampaign" && template.Kind != "UpgradeCampaign" {
			return fmt.Errorf("template %s kind must be FaultCampaign or UpgradeCampaign", template.ID)
		}
		if problems := kubevalidation.IsDNS1123Subdomain(template.Name); len(problems) != 0 {
			return fmt.Errorf("template %s name is invalid", template.ID)
		}
		if template.Weight < 1 || template.Weight > 1_000_000 ||
			template.MaxUses < 1 || template.MaxUses > 256 {
			return fmt.Errorf("template %s weight and maxUses are out of bounds", template.ID)
		}
		if template.ExpectedUID != "" && len(template.ExpectedUID) > 128 ||
			template.ExpectedGeneration != nil && *template.ExpectedGeneration < 1 ||
			template.ExpectedSpecDigest != "" && !digestPattern.MatchString(template.ExpectedSpecDigest) {
			return fmt.Errorf("template %s expected identity is invalid", template.ID)
		}
		for _, group := range template.ConflictGroups {
			if problems := kubevalidation.IsDNS1123Label(group); len(problems) != 0 {
				return fmt.Errorf("template %s conflict group %q is invalid", template.ID, group)
			}
		}
		byID[template.ID] = template
	}
	for _, template := range templates {
		seen := map[string]struct{}{}
		for _, required := range template.Requires {
			if required == template.ID {
				return fmt.Errorf("template %s cannot require itself", template.ID)
			}
			if _, found := byID[required]; !found {
				return fmt.Errorf("template %s requires unknown template %s", template.ID, required)
			}
			if _, duplicate := seen[required]; duplicate {
				return fmt.Errorf("template %s repeats requirement %s", template.ID, required)
			}
			seen[required] = struct{}{}
		}
	}
	return nil
}

func validateRunBudgets(plan Plan) error {
	budgets := plan.Run.Budgets
	if budgets.MaxCampaigns < plan.Generation.MaxExecutions ||
		budgets.MaxCampaigns > 1024 ||
		budgets.MaxWallTimeSeconds < 1 || budgets.MaxWallTimeSeconds > 604800 ||
		budgets.MaxCumulativeFaultSeconds < 1 ||
		budgets.MaxCumulativeFaultSeconds > budgets.MaxWallTimeSeconds ||
		budgets.MaxActiveFaults < 1 || budgets.MaxActiveFaults > 512 ||
		budgets.MaxSignerImpactPercent < 0 || budgets.MaxSignerImpactPercent > 100 ||
		budgets.MaxBurnchainFaults < 0 || budgets.MaxBurnchainFaults > 10 ||
		budgets.MaxInconclusiveCampaigns < 0 || budgets.MaxInconclusiveCampaigns > 64 {
		return errors.New("run budgets are invalid or cannot hold the generated execution bound")
	}
	return nil
}

// ValidateResolvedInput verifies direct observations before decisions.
func ValidateResolvedInput(input ResolvedInput) error {
	if err := ValidatePlan(input.Plan); err != nil {
		return err
	}
	digest, err := PlanDigest(input.Plan)
	if err != nil {
		return err
	}
	if input.PlanDigest != digest {
		return errors.New("resolved plan digest does not match plan")
	}
	if !digestPattern.MatchString(input.Network.TemplateDigest) ||
		input.Plan.Network.ExpectedDigest != "" &&
			input.Plan.Network.ExpectedDigest != input.Network.TemplateDigest {
		return errors.New("resolved network template digest does not match plan")
	}
	if err := validateNetworkConfigurationBoundary(input.Network.Template); err != nil {
		return err
	}
	if err := validateResolvedPolicies(input.Network); err != nil {
		return err
	}
	if len(input.Templates) != len(input.Plan.Templates) {
		return errors.New("resolved template count does not match plan")
	}
	planned := make(map[string]TemplatePlan, len(input.Plan.Templates))
	for _, template := range input.Plan.Templates {
		planned[template.ID] = template
	}
	seen := map[string]struct{}{}
	for _, resolved := range input.Templates {
		plan, found := planned[resolved.ID]
		if !found {
			return fmt.Errorf("resolved unknown template %s", resolved.ID)
		}
		if _, duplicate := seen[resolved.ID]; duplicate {
			return fmt.Errorf("resolved duplicate template %s", resolved.ID)
		}
		seen[resolved.ID] = struct{}{}
		if resolved.Kind != plan.Kind || resolved.Name != plan.Name ||
			resolved.Namespace == "" || resolved.UID == "" ||
			resolved.Generation < 1 || !digestPattern.MatchString(resolved.SpecDigest) ||
			resolved.Weight != plan.Weight || resolved.MaxUses != plan.MaxUses ||
			!equalStringSets(resolved.ConflictGroups, plan.ConflictGroups) ||
			!equalStringSets(resolved.Requires, plan.Requires) {
			return fmt.Errorf("resolved template %s identity or policy differs from plan", resolved.ID)
		}
		var embeddedDigest string
		switch resolved.Kind {
		case "FaultCampaign":
			if resolved.FaultSpec == nil || resolved.UpgradeSpec != nil {
				return fmt.Errorf("resolved template %s lacks its fault specification", resolved.ID)
			}
			embeddedDigest, err = canonical.ArtifactDigest(*resolved.FaultSpec)
		case "UpgradeCampaign":
			if resolved.UpgradeSpec == nil || resolved.FaultSpec != nil {
				return fmt.Errorf("resolved template %s lacks its upgrade specification", resolved.ID)
			}
			embeddedDigest, err = canonical.ArtifactDigest(*resolved.UpgradeSpec)
		}
		if err != nil || embeddedDigest != resolved.SpecDigest {
			return fmt.Errorf("resolved template %s embedded specification digest mismatch", resolved.ID)
		}
		if plan.ExpectedUID != "" && plan.ExpectedUID != resolved.UID ||
			plan.ExpectedGeneration != nil && *plan.ExpectedGeneration != resolved.Generation ||
			plan.ExpectedSpecDigest != "" && plan.ExpectedSpecDigest != resolved.SpecDigest {
			return fmt.Errorf("resolved template %s violates expected identity", resolved.ID)
		}
	}
	return validateAdvisories(input.Advisories, input.Plan.MaxTrials, planned)
}

func validateNetworkConfigurationBoundary(network attacknetv1beta1.StacksNetwork) error {
	type configBinding struct {
		name   string
		source *attacknetv1beta1.ConfigSource
	}
	type advancedBinding struct {
		name     string
		override *attacknetv1beta1.AdvancedWorkloadOverride
	}
	bindings := make([]configBinding, 0, len(network.Spec.Burnchain.Nodes)+len(network.Spec.Nodes)+2*len(network.Spec.SignerSets))
	advanced := make([]advancedBinding, 0, len(bindings))
	for index := range network.Spec.Burnchain.Nodes {
		node := &network.Spec.Burnchain.Nodes[index]
		bindings = append(bindings, configBinding{"bitcoin node " + node.Name, &node.Config})
		advanced = append(advanced, advancedBinding{"bitcoin node " + node.Name, node.Advanced})
	}
	for index := range network.Spec.Nodes {
		node := &network.Spec.Nodes[index]
		bindings = append(bindings, configBinding{"Stacks node " + node.Name, &node.Config})
		advanced = append(advanced, advancedBinding{"Stacks node " + node.Name, node.Advanced})
	}
	for setIndex := range network.Spec.SignerSets {
		for memberIndex := range network.Spec.SignerSets[setIndex].Members {
			member := &network.Spec.SignerSets[setIndex].Members[memberIndex]
			bindings = append(bindings,
				configBinding{"signer " + member.Name, &member.SignerConfig},
				configBinding{"signer node " + member.NodeName, &member.NodeConfig},
			)
			advanced = append(advanced,
				advancedBinding{"signer " + member.Name, member.SignerAdvanced},
				advancedBinding{"signer node " + member.NodeName, member.NodeAdvanced},
			)
		}
	}
	for index := range network.Spec.RawActors {
		actor := &network.Spec.RawActors[index]
		bindings = append(bindings, configBinding{"raw actor " + actor.Name, actor.Config})
		advanced = append(advanced, advancedBinding{"raw actor " + actor.Name, actor.Advanced})
	}
	if network.Spec.Enrollment != nil {
		advanced = append(advanced, advancedBinding{"enrollment " + network.Spec.Enrollment.Name, network.Spec.Enrollment.Advanced})
	}
	for _, binding := range bindings {
		if binding.source == nil || binding.source.ConfigMapRef == nil && binding.source.SecretRef == nil {
			continue
		}
		if !digestPattern.MatchString(binding.source.ExpectedDigest) {
			return fmt.Errorf("%s external configuration requires expectedDigest for deterministic fuzzing", binding.name)
		}
	}
	for _, binding := range advanced {
		if binding.override == nil {
			continue
		}
		for _, variable := range binding.override.Env {
			if variable.ValueFrom != nil {
				return fmt.Errorf("%s environment variable %s uses an unsealed valueFrom source", binding.name, variable.Name)
			}
		}
	}
	return nil
}

func validateResolvedPolicies(network ResolvedNetwork) error {
	if network.Template.Name == "" || network.Template.Namespace == "" ||
		len(network.Template.Spec.Burnchain.Nodes) == 0 || len(network.Policies) == 0 {
		return errors.New("resolved network must include its referenced burnchain policies")
	}
	referenced := make(map[string]string, len(network.Template.Spec.Burnchain.Nodes))
	for _, node := range network.Template.Spec.Burnchain.Nodes {
		policy := network.Template.Spec.Burnchain.PolicyRef.Name
		if node.PolicyRef != nil {
			policy = node.PolicyRef.Name
		}
		if policy == "" || node.Name == "" {
			return errors.New("resolved network has an incomplete burnchain policy reference")
		}
		if prior, duplicate := referenced[policy]; duplicate && prior != node.Name {
			return fmt.Errorf("burnchain policy %s is shared by Bitcoin nodes %s and %s", policy, prior, node.Name)
		}
		referenced[policy] = node.Name
	}
	if len(referenced) != len(network.Policies) {
		return errors.New("resolved burnchain policy inventory differs from network references")
	}
	seen := make(map[string]struct{}, len(network.Policies))
	for _, policy := range network.Policies {
		node, wanted := referenced[policy.Name]
		if !wanted || policy.Namespace != network.Template.Namespace || policy.UID == "" ||
			policy.Generation < 1 || !digestPattern.MatchString(policy.SpecDigest) ||
			policy.Spec.NetworkRef != network.Template.Name || policy.Spec.BitcoinNodeRef != node ||
			policy.Spec.Flash != nil {
			return fmt.Errorf("resolved burnchain policy %s identity or binding is invalid", policy.Name)
		}
		if _, duplicate := seen[policy.Name]; duplicate {
			return fmt.Errorf("resolved duplicate burnchain policy %s", policy.Name)
		}
		seen[policy.Name] = struct{}{}
		digest, err := canonical.ArtifactDigest(policy.Spec)
		if err != nil || digest != policy.SpecDigest {
			return fmt.Errorf("resolved burnchain policy %s specification digest mismatch", policy.Name)
		}
	}
	return nil
}

func equalStringSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] ||
			index > 0 && left[index] == left[index-1] {
			return false
		}
	}
	return true
}

func validateAdvisories(
	advisories []AdvisoryArtifact, maxTrials int32, templates map[string]TemplatePlan,
) error {
	seenTrials := map[int32]struct{}{}
	for _, artifact := range advisories {
		if artifact.SchemaVersion != "stacks-attacknet-advisory/v1" ||
			artifact.TrialOrdinal < 1 || artifact.TrialOrdinal > maxTrials ||
			!digestPattern.MatchString(artifact.Digest) ||
			len(artifact.Candidates) == 0 || len(artifact.Candidates) > len(templates) {
			return errors.New("invalid advisory artifact envelope")
		}
		if _, duplicate := seenTrials[artifact.TrialOrdinal]; duplicate {
			return fmt.Errorf("duplicate resolved advisory for trial %d", artifact.TrialOrdinal)
		}
		seenTrials[artifact.TrialOrdinal] = struct{}{}
		sealed, err := SealAdvisory(artifact)
		if err != nil || sealed.Digest != artifact.Digest {
			return fmt.Errorf("advisory for trial %d digest mismatch", artifact.TrialOrdinal)
		}
		seenCandidates := map[string]struct{}{}
		for _, candidate := range artifact.Candidates {
			if _, found := templates[candidate.ID]; !found ||
				candidate.Score < -1_000_000 || candidate.Score > 1_000_000 ||
				len(candidate.Rationale) > 512 {
				return fmt.Errorf("advisory for trial %d contains invalid candidate %s", artifact.TrialOrdinal, candidate.ID)
			}
			if _, duplicate := seenCandidates[candidate.ID]; duplicate {
				return fmt.Errorf("advisory for trial %d repeats candidate %s", artifact.TrialOrdinal, candidate.ID)
			}
			seenCandidates[candidate.ID] = struct{}{}
		}
	}
	return nil
}

func sortedResolvedTemplates(value []ResolvedTemplate) []ResolvedTemplate {
	result := append([]ResolvedTemplate(nil), value...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// NormalizePlan returns the semantic ordering used for plan digests and
// deterministic generation. Caller-provided list ordering is not a decision.
func NormalizePlan(plan Plan) Plan {
	result := plan
	result.Templates = append([]TemplatePlan(nil), plan.Templates...)
	for index := range result.Templates {
		result.Templates[index].ConflictGroups = append(
			[]string(nil), result.Templates[index].ConflictGroups...,
		)
		result.Templates[index].Requires = append(
			[]string(nil), result.Templates[index].Requires...,
		)
		sort.Strings(result.Templates[index].ConflictGroups)
		sort.Strings(result.Templates[index].Requires)
	}
	sort.Slice(result.Templates, func(i, j int) bool {
		return result.Templates[i].ID < result.Templates[j].ID
	})
	result.Advisories = append([]AdvisoryFilePlan(nil), plan.Advisories...)
	sort.Slice(result.Advisories, func(i, j int) bool {
		return result.Advisories[i].TrialOrdinal < result.Advisories[j].TrialOrdinal
	})
	return result
}

// PlanDigest hashes normalized plan semantics.
func PlanDigest(plan Plan) (string, error) {
	return canonical.Digest(NormalizePlan(plan))
}

// SealAdvisory canonicalizes and digests one bounded proposal.
func SealAdvisory(value AdvisoryArtifact) (AdvisoryArtifact, error) {
	result := value
	result.Candidates = append([]AdvisoryCandidate(nil), value.Candidates...)
	sort.Slice(result.Candidates, func(i, j int) bool {
		return result.Candidates[i].ID < result.Candidates[j].ID
	})
	result.Digest = ""
	digest, err := canonical.Digest(result)
	if err != nil {
		return AdvisoryArtifact{}, err
	}
	result.Digest = digest
	return result, nil
}

// AdvisoryObjectBytes returns the exact retained replay input whose SHA-256
// identity is AdvisoryArtifact.Digest.
func AdvisoryObjectBytes(value AdvisoryArtifact) ([]byte, error) {
	sealed, err := SealAdvisory(value)
	if err != nil {
		return nil, err
	}
	view := sealed
	view.Digest = ""
	data, err := canonical.Marshal(view)
	if err != nil {
		return nil, err
	}
	digest, err := canonical.Digest(view)
	if err != nil || digest != sealed.Digest {
		return nil, errors.New("advisory object digest mismatch")
	}
	return data, nil
}
