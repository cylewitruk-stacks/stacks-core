package fuzzplan

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

type deterministicSource struct {
	key      []byte
	context  string
	counters map[string]uint64
}

type weightedCandidate struct {
	ID     string `json:"id"`
	Weight uint64 `json:"weight"`
	Score  int32  `json:"score,omitempty"`
}

const maximumCompletionStates = 100_000

// Compile creates every finite trial instruction without side effects.
func Compile(input ResolvedInput) (Descriptor, error) {
	if err := ValidateResolvedInput(input); err != nil {
		return Descriptor{}, err
	}
	plan := NormalizePlan(input.Plan)
	descriptor := Descriptor{
		SchemaVersion: DescriptorSchema, SessionID: plan.SessionID,
		Seed: plan.Seed, DecisionAlgorithm: DecisionAlgorithm,
		MaterializationAlgorithm: MaterializationAlgorithm,
		MaxDuration:              plan.MaxDuration,
		PlanDigest:               input.PlanDigest, Network: input.Network,
		Templates: sortedResolvedTemplates(input.Templates), Generation: plan.Generation,
		Run:          plan.Run,
		Confirmation: plan.Confirmation, Reduction: plan.Reduction,
		Capacity: plan.Capacity, Corpus: plan.Corpus,
		Advisories: append([]AdvisoryArtifact(nil), input.Advisories...),
	}
	sort.Slice(descriptor.Network.Policies, func(i, j int) bool {
		return descriptor.Network.Policies[i].Name < descriptor.Network.Policies[j].Name
	})
	sort.Slice(descriptor.Advisories, func(i, j int) bool {
		return descriptor.Advisories[i].TrialOrdinal < descriptor.Advisories[j].TrialOrdinal
	})
	contextDigest, err := descriptorContextDigest(descriptor)
	if err != nil {
		return Descriptor{}, err
	}
	source := &deterministicSource{
		key: []byte(plan.Seed), context: contextDigest,
		counters: map[string]uint64{},
	}
	uses := map[string]int32{}
	completionBudget := &completionBudget{remainingStates: maximumCompletionStates}
	advisories := map[int32]AdvisoryArtifact{}
	for _, advisory := range input.Advisories {
		advisories[advisory.TrialOrdinal] = advisory
	}
	for ordinal := int32(1); ordinal <= plan.MaxTrials; ordinal++ {
		trial, err := compileTrial(
			source, plan, descriptor.Templates, uses,
			advisories[ordinal], ordinal, completionBudget,
		)
		if err != nil {
			return Descriptor{}, fmt.Errorf("trial %d: %w", ordinal, err)
		}
		descriptor.Trials = append(descriptor.Trials, trial)
	}
	digestView := descriptor
	digestView.Digest = ""
	descriptor.Digest, err = canonical.DigestExactIntegers(digestView)
	return descriptor, err
}

// VerifyDescriptor checks the complete immutable planning artifact.
func VerifyDescriptor(descriptor Descriptor) error {
	if descriptor.SchemaVersion != DescriptorSchema ||
		descriptor.DecisionAlgorithm != DecisionAlgorithm ||
		descriptor.MaterializationAlgorithm != MaterializationAlgorithm ||
		!digestPattern.MatchString(descriptor.Digest) ||
		!digestPattern.MatchString(descriptor.PlanDigest) ||
		len(descriptor.Trials) < 1 || len(descriptor.Trials) > 256 {
		return errors.New("session descriptor envelope is invalid")
	}
	plan, err := descriptorPlan(descriptor)
	if err != nil {
		return err
	}
	planDigest, err := PlanDigest(plan)
	if err != nil {
		return err
	}
	if err := ValidateResolvedInput(ResolvedInput{
		Plan: plan, PlanDigest: planDigest, Network: descriptor.Network,
		Templates: descriptor.Templates, Advisories: descriptor.Advisories,
	}); err != nil {
		return fmt.Errorf("session descriptor resolved inputs are invalid: %w", err)
	}
	networkDigest, err := NetworkTemplateDigest(descriptor.Network.Template)
	if err != nil || networkDigest != descriptor.Network.TemplateDigest {
		return errors.New("session descriptor network template digest mismatch")
	}
	if !reflect.DeepEqual(descriptor.Templates, sortedResolvedTemplates(descriptor.Templates)) ||
		!sort.SliceIsSorted(descriptor.Network.Policies, func(i, j int) bool {
			return descriptor.Network.Policies[i].Name < descriptor.Network.Policies[j].Name
		}) || !sort.SliceIsSorted(descriptor.Advisories, func(i, j int) bool {
		return descriptor.Advisories[i].TrialOrdinal < descriptor.Advisories[j].TrialOrdinal
	}) {
		return errors.New("session descriptor resolved inputs are not canonically ordered")
	}
	view := descriptor
	view.Digest = ""
	digest, err := canonical.DigestExactIntegers(view)
	if err != nil || digest != descriptor.Digest {
		return errors.New("session descriptor digest does not match its contents")
	}
	contextDigest, err := descriptorContextDigest(descriptor)
	if err != nil {
		return err
	}
	source := &deterministicSource{
		key: []byte(descriptor.Seed), context: contextDigest,
		counters: map[string]uint64{},
	}
	uses := map[string]int32{}
	completionBudget := &completionBudget{remainingStates: maximumCompletionStates}
	advisories := map[int32]AdvisoryArtifact{}
	for _, advisory := range descriptor.Advisories {
		advisories[advisory.TrialOrdinal] = advisory
	}
	for index, trial := range descriptor.Trials {
		ordinal := int32(index + 1)
		expected, err := compileTrial(
			source, plan, descriptor.Templates, uses, advisories[ordinal], ordinal,
			completionBudget,
		)
		if err != nil {
			return fmt.Errorf("replay descriptor trial %d: %w", ordinal, err)
		}
		if !reflect.DeepEqual(trial, expected) {
			return fmt.Errorf("descriptor trial %d differs from deterministic replay", ordinal)
		}
	}
	return nil
}

func descriptorPlan(descriptor Descriptor) (Plan, error) {
	templates := make([]TemplatePlan, len(descriptor.Templates))
	for index, resolved := range descriptor.Templates {
		templates[index] = TemplatePlan{
			ID: resolved.ID, Kind: resolved.Kind, Name: resolved.Name,
			Weight: resolved.Weight, MaxUses: resolved.MaxUses,
			ConflictGroups: append([]string(nil), resolved.ConflictGroups...),
			Requires:       append([]string(nil), resolved.Requires...),
		}
	}
	plan := Plan{
		SchemaVersion: PlanSchema, SessionID: descriptor.SessionID, Seed: descriptor.Seed,
		MaxTrials: int32(len(descriptor.Trials)), MaxDuration: descriptor.MaxDuration,
		Network:   NetworkPlan{TemplateFile: "sealed-session-descriptor"},
		Templates: templates, Generation: descriptor.Generation, Run: descriptor.Run,
		Confirmation: descriptor.Confirmation, Reduction: descriptor.Reduction,
		Capacity: descriptor.Capacity, Corpus: descriptor.Corpus,
	}
	if err := ValidatePlan(plan); err != nil {
		return Plan{}, fmt.Errorf("session descriptor bounds are invalid: %w", err)
	}
	return NormalizePlan(plan), nil
}

func descriptorContextDigest(descriptor Descriptor) (string, error) {
	view := descriptor
	view.Advisories = nil
	view.Trials = nil
	view.Digest = ""
	return canonical.DigestExactIntegers(view)
}

// NetworkTemplateDigest seals a typed StacksNetwork without narrowing valid
// int64 API fields such as genesis balances to JavaScript's safe range.
func NetworkTemplateDigest(template attacknetv1beta1.StacksNetwork) (string, error) {
	return canonical.DigestExactIntegers(template)
}

func compileTrial(
	source *deterministicSource,
	plan Plan,
	templates []ResolvedTemplate,
	uses map[string]int32,
	advisory AdvisoryArtifact,
	ordinal int32,
	budget *completionBudget,
) (Trial, error) {
	countCandidates := make([]weightedCandidate, 0, plan.Generation.MaxExecutions-plan.Generation.MinExecutions+1)
	for count := plan.Generation.MinExecutions; count <= plan.Generation.MaxExecutions; count++ {
		countCandidates = append(countCandidates, weightedCandidate{ID: strconv.Itoa(int(count)), Weight: 1})
	}
	countReceipt, err := source.choose(ordinal, "execution-count", countCandidates, advisory.Digest)
	if err != nil {
		return Trial{}, err
	}
	count64, err := strconv.ParseInt(countReceipt.Selected, 10, 32)
	if err != nil {
		return Trial{}, err
	}
	count := int32(count64)
	trial := Trial{
		Ordinal: ordinal, AdvisoryDigest: advisory.Digest,
		Receipts: []DecisionReceipt{countReceipt},
	}
	selected := map[string]bool{}
	conflicts := map[string]bool{}
	scores := advisoryScores(advisory)
	search := completionSearch{budget: budget, memo: map[string]bool{}}
	for index := int32(0); index < count; index++ {
		eligibleTemplates := selectableTemplates(
			templates, uses, selected, conflicts, scores, advisory.Digest != "",
		)
		eligible := make([]weightedCandidate, 0, len(eligibleTemplates))
		for _, candidate := range eligibleTemplates {
			nextUses, nextSelected, nextConflicts := selectedState(uses, selected, conflicts, candidate)
			possible, err := search.canComplete(
				templates, nextUses, nextSelected, nextConflicts, scores,
				advisory.Digest != "", count-index-1,
			)
			if err != nil {
				return Trial{}, err
			}
			if possible {
				eligible = append(eligible, weightedCandidate{
					ID: candidate.ID, Weight: uint64(candidate.Weight),
					Score: decisionScore(candidate.ID, scores),
				})
			}
		}
		if len(eligible) == 0 {
			return Trial{}, errors.New("template constraints cannot satisfy generated execution count")
		}
		templateReceipt, err := source.choose(
			ordinal, fmt.Sprintf("template-%d", index+1), eligible, advisory.Digest,
		)
		if err != nil {
			return Trial{}, err
		}
		selectedTemplate, err := findTemplate(templates, templateReceipt.Selected)
		if err != nil {
			return Trial{}, err
		}
		selected[selectedTemplate.ID] = true
		uses[selectedTemplate.ID]++
		for _, group := range selectedTemplate.ConflictGroups {
			conflicts[group] = true
		}
		triggerCandidates := make([]weightedCandidate, len(plan.Generation.Triggers))
		for triggerIndex := range plan.Generation.Triggers {
			triggerCandidates[triggerIndex] = weightedCandidate{
				ID: strconv.Itoa(triggerIndex), Weight: 1,
			}
		}
		triggerReceipt, err := source.choose(
			ordinal, fmt.Sprintf("trigger-%d", index+1),
			triggerCandidates, advisory.Digest,
		)
		if err != nil {
			return Trial{}, err
		}
		triggerIndex, err := strconv.Atoi(triggerReceipt.Selected)
		if err != nil {
			return Trial{}, err
		}
		trial.Executions = append(trial.Executions, TrialExecution{
			ID:       fmt.Sprintf("trial-%03d-execution-%03d", ordinal, index+1),
			Template: selectedTemplate.ID, Kind: selectedTemplate.Kind,
			Trigger: *plan.Generation.Triggers[triggerIndex].DeepCopy(),
		})
		trial.Receipts = append(trial.Receipts, templateReceipt, triggerReceipt)
	}
	seedDigest := hmac.New(sha256.New, []byte(plan.Seed))
	seedDigest.Write([]byte("trial-seed\x00" + strconv.Itoa(int(ordinal))))
	trial.Seed = hex.EncodeToString(seedDigest.Sum(nil))
	trial.DecisionDigest, err = canonical.Digest(trial.Receipts)
	return trial, err
}

type completionSearch struct {
	budget *completionBudget
	memo   map[string]bool
}

type completionBudget struct {
	remainingStates int
}

func (search *completionSearch) canComplete(
	templates []ResolvedTemplate,
	uses map[string]int32,
	selected, conflicts map[string]bool,
	scores map[string]int32,
	advisory bool,
	remaining int32,
) (bool, error) {
	if remaining == 0 {
		return true, nil
	}
	key := completionStateKey(selected, remaining)
	if possible, found := search.memo[key]; found {
		return possible, nil
	}
	if search.budget == nil || search.budget.remainingStates == 0 {
		return false, errors.New("template completion search exceeded deterministic state bound")
	}
	search.budget.remainingStates--
	candidates := selectableTemplates(templates, uses, selected, conflicts, scores, advisory)
	for _, candidate := range candidates {
		nextUses, nextSelected, nextConflicts := selectedState(uses, selected, conflicts, candidate)
		possible, err := search.canComplete(
			templates, nextUses, nextSelected, nextConflicts, scores, advisory, remaining-1,
		)
		if err != nil {
			return false, err
		}
		if possible {
			search.memo[key] = true
			return true, nil
		}
	}
	search.memo[key] = false
	return false, nil
}

func selectableTemplates(
	templates []ResolvedTemplate,
	uses map[string]int32,
	selected, conflicts map[string]bool,
	scores map[string]int32,
	advisory bool,
) []ResolvedTemplate {
	result := make([]ResolvedTemplate, 0, len(templates))
	maximumScore := int32(-1_000_001)
	for _, template := range templates {
		if selected[template.ID] || uses[template.ID] >= template.MaxUses ||
			hasConflict(template.ConflictGroups, conflicts) ||
			!requirementsSelected(template.Requires, selected) {
			continue
		}
		score := decisionScore(template.ID, scores)
		if advisory && score > maximumScore {
			maximumScore = score
		}
		result = append(result, template)
	}
	if !advisory {
		return result
	}
	filtered := result[:0]
	for _, template := range result {
		score := decisionScore(template.ID, scores)
		if score == maximumScore {
			filtered = append(filtered, template)
		}
	}
	return filtered
}

func decisionScore(id string, scores map[string]int32) int32 {
	if value, ranked := scores[id]; ranked {
		return value
	}
	return -1_000_001
}

func selectedState(
	uses map[string]int32,
	selected, conflicts map[string]bool,
	template ResolvedTemplate,
) (map[string]int32, map[string]bool, map[string]bool) {
	nextUses := make(map[string]int32, len(uses)+1)
	for id, count := range uses {
		nextUses[id] = count
	}
	nextUses[template.ID]++
	nextSelected := make(map[string]bool, len(selected)+1)
	for id, value := range selected {
		nextSelected[id] = value
	}
	nextSelected[template.ID] = true
	nextConflicts := make(map[string]bool, len(conflicts)+len(template.ConflictGroups))
	for group, value := range conflicts {
		nextConflicts[group] = value
	}
	for _, group := range template.ConflictGroups {
		nextConflicts[group] = true
	}
	return nextUses, nextSelected, nextConflicts
}

func completionStateKey(selected map[string]bool, remaining int32) string {
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strconv.Itoa(int(remaining)) + "\x00" + strings.Join(ids, "\x00")
}

func (source *deterministicSource) choose(
	trial int32,
	domain string,
	candidates []weightedCandidate,
	advisoryDigest string,
) (DecisionReceipt, error) {
	if len(candidates) == 0 {
		return DecisionReceipt{}, errors.New("decision candidate set is empty")
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ID < candidates[j].ID
	})
	candidateDigest, err := canonical.Digest(candidates)
	if err != nil {
		return DecisionReceipt{}, err
	}
	var total uint64
	for _, candidate := range candidates {
		if candidate.Weight == 0 || total > ^uint64(0)-candidate.Weight {
			return DecisionReceipt{}, errors.New("invalid decision weight total")
		}
		total += candidate.Weight
	}
	value, counter, err := source.uniform(trial, domain, candidateDigest, total)
	if err != nil {
		return DecisionReceipt{}, err
	}
	var upper uint64
	selected := ""
	for _, candidate := range candidates {
		upper += candidate.Weight
		if value < upper {
			selected = candidate.ID
			break
		}
	}
	receipt := DecisionReceipt{
		Algorithm: DecisionAlgorithm, TrialOrdinal: trial, Domain: domain,
		ContextDigest: source.context,
		Counter:       counter, CandidateSetDigest: candidateDigest,
		Selected: selected, AdvisoryDigest: advisoryDigest,
	}
	if err := sealReceipt(&receipt); err != nil {
		return DecisionReceipt{}, err
	}
	return receipt, nil
}

func (source *deterministicSource) uniform(
	trial int32, domain, candidateDigest string, maximum uint64,
) (uint64, uint64, error) {
	if maximum == 0 {
		return 0, 0, errors.New("decision range must be non-zero")
	}
	key := fmt.Sprintf("%d/%s", trial, domain)
	counter := source.counters[key]
	threshold := -maximum % maximum
	for attempts := 0; attempts < 1024; attempts++ {
		mac := hmac.New(sha256.New, source.key)
		fmt.Fprintf(
			mac, "%s\x00%d\x00%s\x00%s\x00%d",
			source.context, trial, domain, candidateDigest, counter,
		)
		value := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
		used := counter
		counter++
		source.counters[key] = counter
		if value >= threshold {
			return value % maximum, used, nil
		}
	}
	return 0, 0, errors.New("decision rejection sampling exceeded bound")
}

func sealReceipt(receipt *DecisionReceipt) error {
	view := *receipt
	view.Digest = ""
	digest, err := canonical.Digest(view)
	if err != nil {
		return err
	}
	receipt.Digest = digest
	return nil
}

func advisoryScores(value AdvisoryArtifact) map[string]int32 {
	result := map[string]int32{}
	for _, candidate := range value.Candidates {
		result[candidate.ID] = candidate.Score
	}
	return result
}

func findTemplate(templates []ResolvedTemplate, id string) (ResolvedTemplate, error) {
	for _, template := range templates {
		if template.ID == id {
			return template, nil
		}
	}
	return ResolvedTemplate{}, fmt.Errorf("selected fuzz template is absent: %s", id)
}

func hasConflict(groups []string, active map[string]bool) bool {
	for _, group := range groups {
		if active[group] {
			return true
		}
	}
	return false
}

func requirementsSelected(requirements []string, selected map[string]bool) bool {
	for _, requirement := range requirements {
		if !selected[requirement] {
			return false
		}
	}
	return true
}
