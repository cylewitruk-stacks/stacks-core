// Package run owns immutable AttacknetRun scheduling and execution.
package run

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
)

const (
	scheduleSchema    = "stacks-attacknet-schedule/v1"
	decisionAlgorithm = "hmac-sha256-decisions/v1"
)

type imageConstraint struct {
	Scope          string `json:"scope"`
	RequestedRef   string `json:"requestedRef"`
	ResolvedRef    string `json:"resolvedRef"`
	ResolvedDigest string `json:"resolvedDigest"`
}
type sourceIdentity struct {
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	SpecDigest string `json:"specDigest"`
}
type resolvedAction struct {
	Targets            []string                            `json:"targets"`
	Parameters         map[string]any                      `json:"parameters"`
	CampaignSpec       attacknetv1alpha1.FaultCampaignSpec `json:"campaignSpec"`
	CampaignSpecDigest string                              `json:"campaignSpecDigest"`
}
type budgetCharge struct {
	Campaigns           int32   `json:"campaigns"`
	FaultSeconds        float64 `json:"faultSeconds"`
	SignerImpactPercent float64 `json:"signerImpactPercent"`
	BurnchainFaults     int32   `json:"burnchainFaults"`
}
type action struct {
	Order                  int32             `json:"order"`
	Kind                   string            `json:"kind"`
	InstructionID          string            `json:"instructionId"`
	NotBeforeOffsetSeconds float64           `json:"notBeforeOffsetSeconds"`
	DelayAfterSeconds      int32             `json:"delayAfterSeconds"`
	CampaignAlias          string            `json:"campaignAlias"`
	Source                 sourceIdentity    `json:"source"`
	ImageConstraints       []imageConstraint `json:"imageConstraints"`
	Resolved               resolvedAction    `json:"resolved"`
	BudgetCharge           budgetCharge      `json:"budgetCharge"`
}
type scheduleNetwork struct {
	Name           string `json:"name"`
	UID            string `json:"uid"`
	Generation     int64  `json:"generation"`
	ManifestDigest string `json:"manifestDigest"`
}
type scheduleIntegrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}
type resolvedSchedule struct {
	SchemaVersion    string            `json:"schemaVersion"`
	Run              map[string]any    `json:"run"`
	Network          scheduleNetwork   `json:"network"`
	CatalogDigest    string            `json:"catalogDigest"`
	SequenceDigest   string            `json:"sequenceDigest"`
	ImageConstraints []imageConstraint `json:"imageConstraints"`
	Actions          []action          `json:"actions"`
	Budgets          scheduleBudgets   `json:"budgets"`
	Replay           map[string]any    `json:"replay"`
	Integrity        scheduleIntegrity `json:"integrity,omitempty"`
}

type budgetUsage struct {
	Campaigns                  int32   `json:"campaigns"`
	CumulativeFaultSeconds     float64 `json:"cumulativeFaultSeconds"`
	MaximumSignerImpactPercent float64 `json:"maximumSignerImpactPercent"`
	BurnchainFaults            int32   `json:"burnchainFaults"`
	MaximumActiveFaults        int32   `json:"maximumActiveFaults"`
	PlannedWallTimeSeconds     float64 `json:"plannedWallTimeSeconds"`
}

type budgetHeadroom struct {
	Campaigns              int32   `json:"campaigns"`
	CumulativeFaultSeconds float64 `json:"cumulativeFaultSeconds"`
	SignerImpactPercent    float64 `json:"signerImpactPercent"`
	BurnchainFaults        int32   `json:"burnchainFaults"`
	WallTimeSeconds        float64 `json:"wallTimeSeconds"`
}

type scheduleBudgets struct {
	Limits   attacknetv1alpha1.RunBudgets `json:"limits"`
	Usage    budgetUsage                  `json:"usage"`
	Headroom budgetHeadroom               `json:"headroom"`
}

func buildSchedule(run *attacknetv1alpha1.AttacknetRun, network *attacknetv1alpha1.StacksNetwork, inventory attacknetv1alpha1.NetworkInventory, templates map[string]*attacknetv1alpha1.FaultCampaign, manifest fault.Manifest) (resolvedSchedule, error) {
	algorithm := run.Spec.DecisionAlgorithm
	if algorithm == "" {
		algorithm = decisionAlgorithm
	}
	if algorithm != decisionAlgorithm {
		return resolvedSchedule{}, fmt.Errorf("unsupported decision algorithm %s", algorithm)
	}
	manifestDigest, err := canonical.ArtifactDigest(manifest)
	if err != nil {
		return resolvedSchedule{}, err
	}
	images := make([]imageConstraint, len(inventory.Actors))
	for index, actor := range inventory.Actors {
		images[index] = imageConstraint{Scope: actor.Name, RequestedRef: actor.RequestedImage, ResolvedRef: actor.RuntimeImageID, ResolvedDigest: digestIn(actor.RuntimeImageID)}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Scope < images[j].Scope })
	catalog := map[string]attacknetv1alpha1.CampaignCatalogEntry{}
	catalogRefs := map[string]bool{}
	for _, entry := range run.Spec.CampaignCatalog {
		if entry.Name == "" || entry.CampaignRef == "" {
			return resolvedSchedule{}, errors.New("campaign catalog names and references must be non-empty")
		}
		if _, duplicate := catalog[entry.Name]; duplicate {
			return resolvedSchedule{}, fmt.Errorf("duplicate campaign alias %s", entry.Name)
		}
		if catalogRefs[entry.CampaignRef] {
			return resolvedSchedule{}, fmt.Errorf("duplicate campaign reference %s", entry.CampaignRef)
		}
		catalog[entry.Name] = entry
		catalogRefs[entry.CampaignRef] = true
	}
	if len(catalog) == 0 {
		return resolvedSchedule{}, errors.New("campaign catalog must not be empty")
	}
	actions := []action{}
	instructionIDs := map[string]bool{}
	offset := float64(0)
	for _, instruction := range run.Spec.Sequence {
		if instruction.ID == "" || instruction.Campaign == "" {
			return resolvedSchedule{}, errors.New("sequence IDs and campaign aliases must be non-empty")
		}
		if instructionIDs[instruction.ID] {
			return resolvedSchedule{}, fmt.Errorf("duplicate instruction ID %s", instruction.ID)
		}
		instructionIDs[instruction.ID] = true
		if instruction.Enabled != nil && !*instruction.Enabled {
			continue
		}
		entry, ok := catalog[instruction.Campaign]
		if !ok {
			return resolvedSchedule{}, fmt.Errorf("instruction %s references unknown campaign %s", instruction.ID, instruction.Campaign)
		}
		source := templates[entry.CampaignRef]
		if source == nil || !source.Spec.Template {
			return resolvedSchedule{}, fmt.Errorf("campaign source %s is absent or not a template", entry.CampaignRef)
		}
		if source.Spec.NetworkRef != run.Spec.NetworkRef {
			return resolvedSchedule{}, fmt.Errorf("campaign source %s targets another network", source.Name)
		}
		specDigest, err := canonical.ArtifactDigest(source.Spec)
		if err != nil {
			return resolvedSchedule{}, err
		}
		if entry.ExpectedUID != "" && entry.ExpectedUID != string(source.UID) {
			return resolvedSchedule{}, fmt.Errorf("campaign %s UID constraint does not match", entry.Name)
		}
		if entry.ExpectedGeneration != nil && *entry.ExpectedGeneration != source.Generation {
			return resolvedSchedule{}, fmt.Errorf("campaign %s generation constraint does not match", entry.Name)
		}
		if entry.ExpectedSpecDigest != "" && entry.ExpectedSpecDigest != specDigest {
			return resolvedSchedule{}, fmt.Errorf("campaign %s digest constraint does not match", entry.Name)
		}
		compiled, err := fault.Compile(source, manifest)
		if err != nil {
			return resolvedSchedule{}, err
		}
		duration, err := time.ParseDuration(source.Spec.Fault.Duration)
		if err != nil || duration <= 0 {
			return resolvedSchedule{}, fmt.Errorf("campaign %s has invalid duration", source.Name)
		}
		campaignSpec := source.Spec
		campaignSpec.Template = false
		campaignDigest, err := canonical.ArtifactDigest(campaignSpec)
		if err != nil {
			return resolvedSchedule{}, err
		}
		burn := int32(0)
		selectedRoles := map[string]string{}
		for _, actor := range manifest.Actors {
			selectedRoles[actor.Name] = actor.Role
		}
		for _, target := range compiled.Evidence.SelectedActors {
			if selectedRoles[target] == "burnchain" {
				burn = 1
			}
		}
		parameters := map[string]any{}
		if len(source.Spec.Fault.Parameters.Raw) > 0 {
			if err := json.Unmarshal(source.Spec.Fault.Parameters.Raw, &parameters); err != nil {
				return resolvedSchedule{}, fmt.Errorf("campaign %s parameters: %w", source.Name, err)
			}
		}
		actions = append(actions, action{Order: int32(len(actions) + 1), Kind: "fault-campaign", InstructionID: instruction.ID, NotBeforeOffsetSeconds: offset, DelayAfterSeconds: instruction.DelayAfterSeconds, CampaignAlias: instruction.Campaign, Source: sourceIdentity{Name: source.Name, UID: string(source.UID), Generation: source.Generation, SpecDigest: specDigest}, ImageConstraints: images, Resolved: resolvedAction{Targets: compiled.Evidence.SelectedActors, Parameters: parameters, CampaignSpec: campaignSpec, CampaignSpecDigest: campaignDigest}, BudgetCharge: budgetCharge{Campaigns: 1, FaultSeconds: duration.Seconds(), SignerImpactPercent: compiled.Evidence.SignerImpact.Percent, BurnchainFaults: burn}})
		offset += duration.Seconds() + float64(instruction.DelayAfterSeconds)
	}
	if len(actions) == 0 {
		return resolvedSchedule{}, errors.New("run resolves to no enabled actions")
	}
	budgets, err := resolvedBudgets(actions, run.Spec.Budgets)
	if err != nil {
		return resolvedSchedule{}, err
	}
	normalizedCatalog := append([]attacknetv1alpha1.CampaignCatalogEntry(nil), run.Spec.CampaignCatalog...)
	sort.Slice(normalizedCatalog, func(i, j int) bool { return normalizedCatalog[i].Name < normalizedCatalog[j].Name })
	catalogDigest, err := canonical.ArtifactDigest(normalizedCatalog)
	if err != nil {
		return resolvedSchedule{}, err
	}
	normalizedSequence := append([]attacknetv1alpha1.RunInstruction(nil), run.Spec.Sequence...)
	for i := range normalizedSequence {
		if normalizedSequence[i].Enabled == nil {
			normalizedSequence[i].Enabled = ptr(true)
		}
	}
	sequenceDigest, err := canonical.ArtifactDigest(normalizedSequence)
	if err != nil {
		return resolvedSchedule{}, err
	}
	schedule := resolvedSchedule{SchemaVersion: scheduleSchema, Run: map[string]any{"name": run.Name, "seed": run.Spec.Seed, "decisionAlgorithm": algorithm}, Network: scheduleNetwork{Name: network.Name, UID: string(network.UID), Generation: network.Generation, ManifestDigest: manifestDigest}, CatalogDigest: catalogDigest, SequenceDigest: sequenceDigest, ImageConstraints: images, Actions: actions, Budgets: budgets, Replay: map[string]any{"enabled": false}}
	if run.Spec.Resume.Enabled {
		schedule.Replay = map[string]any{"enabled": true, "strategy": "resume/v1", "sourceRunRef": run.Spec.Resume.SourceRunRef, "afterInstructionId": run.Spec.Resume.AfterInstructionID}
		found := false
		filtered := []action{}
		for _, item := range schedule.Actions {
			if found {
				filtered = append(filtered, item)
			}
			if item.InstructionID == run.Spec.Resume.AfterInstructionID {
				found = true
			}
		}
		if !found {
			return resolvedSchedule{}, errors.New("resume boundary is absent from schedule")
		}
		schedule.Actions = filtered
		reorder(schedule.Actions)
		budgets, err := resolvedBudgets(schedule.Actions, run.Spec.Budgets)
		if err != nil {
			return resolvedSchedule{}, err
		}
		schedule.Budgets = budgets
	}
	return sealAndValidate(schedule)
}

func applyReplay(source resolvedSchedule, run *attacknetv1alpha1.AttacknetRun, network *attacknetv1alpha1.StacksNetwork, inventory attacknetv1alpha1.NetworkInventory, manifest fault.Manifest, templates map[string]*attacknetv1alpha1.FaultCampaign, minimization bool) (resolvedSchedule, error) {
	if err := validateSchedule(source); err != nil {
		return resolvedSchedule{}, fmt.Errorf("source schedule: %w", err)
	}
	algorithm := run.Spec.DecisionAlgorithm
	if algorithm == "" {
		algorithm = decisionAlgorithm
	}
	if algorithm != decisionAlgorithm {
		return resolvedSchedule{}, fmt.Errorf("unsupported decision algorithm %s", algorithm)
	}
	manifestDigest, err := canonical.ArtifactDigest(manifest)
	if err != nil {
		return resolvedSchedule{}, err
	}
	if source.Network.Name != run.Spec.NetworkRef || source.Network.ManifestDigest != manifestDigest {
		return resolvedSchedule{}, errors.New("current network manifest differs from source schedule")
	}
	if source.Network.UID == string(network.UID) {
		return resolvedSchedule{}, errors.New("replay and minimization require a fresh network UID")
	}
	images := make([]imageConstraint, len(inventory.Actors))
	for i, a := range inventory.Actors {
		images[i] = imageConstraint{Scope: a.Name, RequestedRef: a.RequestedImage, ResolvedRef: a.RuntimeImageID, ResolvedDigest: digestIn(a.RuntimeImageID)}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Scope < images[j].Scope })
	if !reflectDeepEqual(source.ImageConstraints, images) {
		return resolvedSchedule{}, errors.New("resolved images differ from source schedule")
	}
	for _, item := range source.Actions {
		if item.Kind != "fault-campaign" {
			return resolvedSchedule{}, fmt.Errorf("unsupported source action kind %s", item.Kind)
		}
		template := templates[item.Source.Name]
		if template == nil || string(template.UID) != item.Source.UID || template.Generation != item.Source.Generation {
			return resolvedSchedule{}, fmt.Errorf("campaign source %s no longer satisfies immutable identity constraints", item.Source.Name)
		}
		digest, digestErr := canonical.ArtifactDigest(template.Spec)
		if digestErr != nil || digest != item.Source.SpecDigest {
			return resolvedSchedule{}, fmt.Errorf("campaign source %s no longer satisfies immutable content constraints", item.Source.Name)
		}
	}
	if !reflectDeepEqual(source.Budgets.Limits, run.Spec.Budgets) {
		return resolvedSchedule{}, errors.New("replay and minimization budgets must equal immutable source budgets")
	}
	originalNetwork := source.Network
	sourceDigest := source.Integrity.Digest
	replayMetadata := map[string]any{"enabled": true, "strategy": "resolved-schedule/v1", "sourceRunRef": run.Spec.Replay.SourceRunRef, "sourceScheduleDigest": sourceDigest, "sourceNetwork": originalNetwork, "disclosure": "The immutable instructions and images are replayed on a separately identified network; execution interleavings remain nondeterministic."}
	if minimization {
		if run.Spec.Minimization.SourceScheduleDigest != sourceDigest {
			return resolvedSchedule{}, errors.New("minimization sourceScheduleDigest does not match source schedule")
		}
		if run.Spec.Minimization.Strategy != "DeltaDebug" || run.Spec.Minimization.MaxAttempts != 1 || !run.Spec.Minimization.RequireFreshNetwork {
			return resolvedSchedule{}, errors.New("minimization must be one bounded fresh-network DeltaDebug attempt")
		}
		retained := map[string]attacknetv1alpha1.RetainedInstruction{}
		priorOrder := -1
		sourceOrder := map[string]int{}
		for index, item := range source.Actions {
			sourceOrder[item.InstructionID] = index
		}
		for _, item := range run.Spec.Minimization.Retained {
			if _, duplicate := retained[item.InstructionID]; duplicate {
				return resolvedSchedule{}, fmt.Errorf("duplicate retained instruction %s", item.InstructionID)
			}
			order, exists := sourceOrder[item.InstructionID]
			if !exists {
				return resolvedSchedule{}, fmt.Errorf("minimization references unknown instruction %s", item.InstructionID)
			}
			if order <= priorOrder {
				return resolvedSchedule{}, errors.New("minimization may not reorder source actions")
			}
			priorOrder = order
			retained[item.InstructionID] = item
		}
		actions := []action{}
		materialRemoval := len(retained) < len(source.Actions)
		for _, item := range source.Actions {
			rule, keep := retained[item.InstructionID]
			if !keep {
				continue
			}
			removedTargets, err := checkedSubset(rule.RemovedTargets, item.Resolved.Targets, "target", item.InstructionID)
			if err != nil {
				return resolvedSchedule{}, err
			}
			materialRemoval = materialRemoval || len(removedTargets) > 0
			targets := []string{}
			for _, target := range item.Resolved.Targets {
				if !removedTargets[target] {
					targets = append(targets, target)
				}
			}
			if len(targets) == 0 {
				return resolvedSchedule{}, fmt.Errorf("minimization removes every target from %s", item.InstructionID)
			}
			if len(removedTargets) > 0 {
				item.Resolved.Targets = targets
				item.Resolved.CampaignSpec.Target = attacknetv1alpha1.FaultTarget{Actors: targets}
			}
			parameterKeys := make([]string, 0, len(item.Resolved.Parameters))
			for key := range item.Resolved.Parameters {
				parameterKeys = append(parameterKeys, key)
			}
			removedParameters, err := checkedSubset(rule.RemovedParameters, parameterKeys, "parameter", item.InstructionID)
			if err != nil {
				return resolvedSchedule{}, err
			}
			materialRemoval = materialRemoval || len(removedParameters) > 0
			for key := range removedParameters {
				delete(item.Resolved.Parameters, key)
			}
			if len(removedParameters) > 0 {
				encoded, _ := json.Marshal(item.Resolved.Parameters)
				item.Resolved.CampaignSpec.Fault.Parameters.Raw = encoded
			}
			item.Resolved.CampaignSpecDigest, _ = canonical.ArtifactDigest(item.Resolved.CampaignSpec)
			actions = append(actions, item)
		}
		if len(actions) == 0 {
			return resolvedSchedule{}, errors.New("minimization retains no actions")
		}
		if !materialRemoval {
			return resolvedSchedule{}, errors.New("minimization must remove at least one campaign, target, or parameter")
		}
		source.Actions = actions
		reorder(source.Actions)
		for _, item := range source.Actions {
			candidate := &attacknetv1alpha1.FaultCampaign{Spec: item.Resolved.CampaignSpec}
			if _, err := fault.Compile(candidate, manifest); err != nil {
				return resolvedSchedule{}, fmt.Errorf("minimized instruction %s is invalid: %w", item.InstructionID, err)
			}
		}
		budgets, err := resolvedBudgets(source.Actions, run.Spec.Budgets)
		if err != nil {
			return resolvedSchedule{}, err
		}
		source.Budgets = budgets
		candidate, err := sealAndValidate(source)
		if err != nil {
			return resolvedSchedule{}, err
		}
		if candidate.Integrity.Digest != run.Spec.Minimization.CandidateScheduleDigest {
			return resolvedSchedule{}, fmt.Errorf("minimization candidateScheduleDigest %s does not match permitted source removals %s", run.Spec.Minimization.CandidateScheduleDigest, candidate.Integrity.Digest)
		}
		source = candidate
		replayMetadata = map[string]any{"enabled": true, "strategy": "deterministic-hierarchical-ddmin/v1", "sourceScheduleDigest": run.Spec.Minimization.SourceScheduleDigest, "candidateScheduleDigest": run.Spec.Minimization.CandidateScheduleDigest, "attemptId": run.Spec.Minimization.AttemptID, "sourceNetwork": originalNetwork, "disclosure": "This is a permitted removal-only counterfactual on a fresh network; it does not establish causal minimality."}
	}
	source.Network.UID = string(network.UID)
	source.Network.Generation = network.Generation
	source.Run = map[string]any{"name": run.Name, "seed": run.Spec.Seed, "decisionAlgorithm": algorithm}
	source.Replay = replayMetadata
	return sealAndValidate(source)
}

func seal(schedule resolvedSchedule) (resolvedSchedule, error) {
	schedule.Integrity = scheduleIntegrity{}
	encoded, err := json.Marshal(schedule)
	if err != nil {
		return schedule, err
	}
	unsigned := map[string]any{}
	if err := json.Unmarshal(encoded, &unsigned); err != nil {
		return schedule, err
	}
	delete(unsigned, "integrity")
	digest, err := canonical.ArtifactDigest(unsigned)
	if err != nil {
		return schedule, err
	}
	schedule.Integrity = scheduleIntegrity{Algorithm: "sha256", Digest: digest}
	return schedule, nil
}
func encodeSchedule(schedule resolvedSchedule) ([]byte, error) {
	encoded, err := json.Marshal(schedule)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(encoded); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > 900_000 {
		return nil, errors.New("compressed resolved schedule exceeds 900 KiB")
	}
	return buffer.Bytes(), nil
}
func decodeSchedule(data []byte) (resolvedSchedule, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return resolvedSchedule{}, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, 8<<20))
	if err != nil {
		return resolvedSchedule{}, err
	}
	var schedule resolvedSchedule
	if err := json.Unmarshal(encoded, &schedule); err != nil {
		return schedule, err
	}
	expected := schedule.Integrity.Digest
	sealed, err := seal(schedule)
	if err != nil {
		return schedule, err
	}
	if sealed.Integrity.Digest != expected {
		return schedule, errors.New("resolved schedule digest mismatch")
	}
	if err := validateSchedule(schedule); err != nil {
		return schedule, err
	}
	return schedule, nil
}
func resolvedBudgets(actions []action, limits attacknetv1alpha1.RunBudgets) (scheduleBudgets, error) {
	usage := budgetUsage{Campaigns: int32(len(actions))}
	if len(actions) > 0 {
		usage.MaximumActiveFaults = 1
	}
	for _, a := range actions {
		usage.CumulativeFaultSeconds += a.BudgetCharge.FaultSeconds
		usage.MaximumSignerImpactPercent = max(usage.MaximumSignerImpactPercent, a.BudgetCharge.SignerImpactPercent)
		usage.BurnchainFaults += a.BudgetCharge.BurnchainFaults
		usage.PlannedWallTimeSeconds = max(usage.PlannedWallTimeSeconds, a.NotBeforeOffsetSeconds+a.BudgetCharge.FaultSeconds+float64(a.DelayAfterSeconds))
	}
	switch {
	case limits.MaxActiveFaults != 1:
		return scheduleBudgets{}, errors.New("maxActiveFaults must equal one")
	case usage.Campaigns > limits.MaxCampaigns:
		return scheduleBudgets{}, errors.New("resolved schedule exceeds campaign budget")
	case usage.CumulativeFaultSeconds > float64(limits.MaxCumulativeFaultSeconds):
		return scheduleBudgets{}, errors.New("resolved schedule exceeds cumulative fault budget")
	case usage.MaximumSignerImpactPercent > float64(limits.MaxSignerImpactPercent):
		return scheduleBudgets{}, errors.New("resolved schedule exceeds signer impact budget")
	case usage.BurnchainFaults > limits.MaxBurnchainFaults:
		return scheduleBudgets{}, errors.New("resolved schedule exceeds burnchain budget")
	case usage.PlannedWallTimeSeconds > float64(limits.MaxWallTimeSeconds):
		return scheduleBudgets{}, errors.New("resolved schedule exceeds wall-time budget")
	}
	return scheduleBudgets{Limits: limits, Usage: usage, Headroom: budgetHeadroom{Campaigns: limits.MaxCampaigns - usage.Campaigns, CumulativeFaultSeconds: float64(limits.MaxCumulativeFaultSeconds) - usage.CumulativeFaultSeconds, SignerImpactPercent: float64(limits.MaxSignerImpactPercent) - usage.MaximumSignerImpactPercent, BurnchainFaults: limits.MaxBurnchainFaults - usage.BurnchainFaults, WallTimeSeconds: float64(limits.MaxWallTimeSeconds) - usage.PlannedWallTimeSeconds}}, nil
}

func sealAndValidate(schedule resolvedSchedule) (resolvedSchedule, error) {
	sealed, err := seal(schedule)
	if err != nil {
		return sealed, err
	}
	if err := validateSchedule(sealed); err != nil {
		return sealed, err
	}
	return sealed, nil
}

func validateSchedule(schedule resolvedSchedule) error {
	if schedule.SchemaVersion != scheduleSchema {
		return errors.New("unsupported schedule schema")
	}
	algorithm, _ := schedule.Run["decisionAlgorithm"].(string)
	if algorithm != decisionAlgorithm {
		return errors.New("unsupported schedule decision algorithm")
	}
	if schedule.Network.Name == "" || schedule.Network.UID == "" || schedule.Network.Generation < 1 {
		return errors.New("schedule network identity is incomplete")
	}
	if !isDigest(schedule.Network.ManifestDigest) || !isDigest(schedule.CatalogDigest) || !isDigest(schedule.SequenceDigest) {
		return errors.New("schedule input digest is invalid")
	}
	seen := map[string]bool{}
	priorOffset := -1.0
	for index, item := range schedule.Actions {
		if item.Order != int32(index+1) || item.Kind != "fault-campaign" || item.InstructionID == "" || seen[item.InstructionID] {
			return errors.New("schedule action identity or order is invalid")
		}
		seen[item.InstructionID] = true
		if item.NotBeforeOffsetSeconds < priorOffset {
			return errors.New("schedule action offsets must be nondecreasing")
		}
		priorOffset = item.NotBeforeOffsetSeconds
		if !reflectDeepEqual(item.ImageConstraints, schedule.ImageConstraints) {
			return fmt.Errorf("action %s image constraints differ from schedule", item.InstructionID)
		}
		digest, err := canonical.ArtifactDigest(item.Resolved.CampaignSpec)
		if err != nil || digest != item.Resolved.CampaignSpecDigest {
			return fmt.Errorf("action %s campaign spec digest mismatch", item.InstructionID)
		}
	}
	expected, err := resolvedBudgets(schedule.Actions, schedule.Budgets.Limits)
	if err != nil {
		return err
	}
	if !reflectDeepEqual(expected, schedule.Budgets) {
		return errors.New("schedule budget usage or headroom mismatch")
	}
	if schedule.Integrity.Algorithm != "sha256" || !isDigest(schedule.Integrity.Digest) {
		return errors.New("schedule integrity metadata is invalid")
	}
	return nil
}
func reorder(actions []action) {
	for i := range actions {
		actions[i].Order = int32(i + 1)
	}
}
func digestIn(value string) string {
	for i := 0; i+71 <= len(value); i++ {
		part := value[i : i+71]
		if len(part) == 71 && part[:7] == "sha256:" {
			return part
		}
	}
	return ""
}
func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, v := range values {
		result[v] = true
	}
	return result
}

func checkedSubset(values, source []string, kind, instruction string) (map[string]bool, error) {
	available := stringSet(source)
	result := map[string]bool{}
	for _, value := range values {
		if result[value] {
			return nil, fmt.Errorf("minimization %s %s lists %s twice", instruction, kind, value)
		}
		if !available[value] {
			return nil, fmt.Errorf("minimization %s removes unknown %s %s", instruction, kind, value)
		}
		result[value] = true
	}
	return result, nil
}

func isDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
func reflectDeepEqual(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}
