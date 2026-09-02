// Package upgrade owns bounded actor-version transitions. It never writes
// workloads; topology reconciliation consumes its admitted assignment overlay.
package upgrade

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/instrumentationprofile"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolassertion"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateStructure checks fields that do not require a live StacksNetwork.
func ValidateStructure(campaign *attacknetv1beta1.UpgradeCampaign) error {
	if campaign.Spec.NetworkRef == "" || len(campaign.Spec.Profiles) == 0 || len(campaign.Spec.Stages) == 0 {
		return errors.New("UpgradeCampaign requires networkRef, profiles, and stages")
	}
	profiles := map[string]struct{}{}
	for _, profile := range campaign.Spec.Profiles {
		if profile.Name == "" || profile.Image == "" || !digestPattern.MatchString(profile.ImageID) || !digestPattern.MatchString(profile.ProvenanceDigest) || !digestPattern.MatchString(profile.ConfigDigest) {
			return fmt.Errorf("upgrade profile %q is incomplete", profile.Name)
		}
		if profile.SourceKind != "remoteGit" && profile.SourceKind != "localGit" && profile.SourceKind != "prebuilt" {
			return fmt.Errorf("upgrade profile %q has unsupported source kind %q", profile.Name, profile.SourceKind)
		}
		if !instrumentationprofile.Validate(profile.Capabilities) || !validExpectation(profile.Expectation) {
			return fmt.Errorf("upgrade profile %q has invalid capabilities or expectation", profile.Name)
		}
		if _, duplicate := profiles[profile.Name]; duplicate {
			return fmt.Errorf("duplicate upgrade profile %q", profile.Name)
		}
		profiles[profile.Name] = struct{}{}
	}
	for _, stage := range campaign.Spec.Stages {
		if stage.Name == "" || len(stage.Assignments) == 0 || stage.Deadline.Duration <= 0 || stage.StableFor.Duration < 0 || stage.StableFor.Duration >= stage.Deadline.Duration {
			return fmt.Errorf("upgrade stage %q has invalid timing or assignments", stage.Name)
		}
		if int32(len(stage.Assignments)) > campaign.Spec.Safety.MaxParallelActors {
			return fmt.Errorf("upgrade stage %q exceeds maxParallelActors", stage.Name)
		}
		if err := protocolassertion.ValidateStructure(stage.Assertions); err != nil {
			return fmt.Errorf("upgrade stage %q assertions: %w", stage.Name, err)
		}
		seen := map[string]struct{}{}
		for _, assignment := range stage.Assignments {
			if _, ok := profiles[assignment.Profile]; !ok {
				return fmt.Errorf("actor %q references unknown profile %q", assignment.Actor, assignment.Profile)
			}
			if _, duplicate := seen[assignment.Actor]; duplicate {
				return fmt.Errorf("actor %q is assigned twice in stage %q", assignment.Actor, stage.Name)
			}
			seen[assignment.Actor] = struct{}{}
		}
	}
	return nil
}

func validExpectation(value string) bool {
	return value == "" || value == "compatible" || value == "incompatible" || value == "unknown" || value == "intentionally-incompatible"
}

// Validate checks campaign structure and protocol-role safety against a network.
func Validate(campaign *attacknetv1beta1.UpgradeCampaign, network *attacknetv1beta1.StacksNetwork) error {
	if err := ValidateStructure(campaign); err != nil {
		return err
	}
	if campaign.Spec.NetworkRef == "" || campaign.Spec.NetworkRef != network.Name {
		return errors.New("upgrade campaign must reference its StacksNetwork")
	}
	actors := actorKinds(network)
	actorRoles := make(map[string]string, len(actors))
	for name, kind := range actors {
		actorRoles[name] = kind.role
	}
	totalSignerWeight, totalMiners := networkTotals(network)
	for _, stage := range campaign.Spec.Stages {
		if err := protocolassertion.ValidateSet(stage.Assertions, actorRoles); err != nil {
			return fmt.Errorf("upgrade stage %q assertions: %w", stage.Name, err)
		}
		var signerWeight int64
		miners := int32(0)
		for _, assignment := range stage.Assignments {
			kind, found := actors[assignment.Actor]
			if !found {
				return fmt.Errorf("upgrade stage %q references unknown actor %q", stage.Name, assignment.Actor)
			}
			if !kind.upgradeable {
				return fmt.Errorf("actor %q role %q is not upgradeable", assignment.Actor, kind.role)
			}
			signerWeight += kind.signerWeight
			miners += kind.miner
		}
		if totalSignerWeight > 0 && signerWeight*100 > totalSignerWeight*int64(campaign.Spec.Safety.MaxSignerWeightPercent) {
			return fmt.Errorf("upgrade stage %q exceeds signer-weight safety limit", stage.Name)
		}
		if totalMiners > 0 && miners*100 > totalMiners*campaign.Spec.Safety.MaxMinerPercent {
			return fmt.Errorf("upgrade stage %q exceeds miner safety limit", stage.Name)
		}
	}
	return nil
}

type actorKind struct {
	role         string
	upgradeable  bool
	signerWeight int64
	miner        int32
}

func actorKinds(network *attacknetv1beta1.StacksNetwork) map[string]actorKind {
	result := map[string]actorKind{}
	for _, node := range network.Spec.Nodes {
		kind := actorKind{role: string(node.Role), upgradeable: true}
		if node.Role == attacknetv1beta1.StacksNodeMiner {
			kind.miner = 1
		}
		result[node.Name] = kind
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			result[member.Name] = actorKind{role: "signer", upgradeable: true, signerWeight: member.Weight}
			if _, declared := result[member.NodeName]; !declared {
				result[member.NodeName] = actorKind{role: string(attacknetv1beta1.StacksNodeFollower), upgradeable: true}
			}
		}
	}
	return result
}

func networkTotals(network *attacknetv1beta1.StacksNetwork) (int64, int32) {
	var weight int64
	var miners int32
	for _, node := range network.Spec.Nodes {
		if node.Role == attacknetv1beta1.StacksNodeMiner {
			miners++
		}
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			weight += member.Weight
		}
	}
	return weight, miners
}

// EffectiveAssignments returns the cumulative, actor-sorted overlay.
func EffectiveAssignments(campaign *attacknetv1beta1.UpgradeCampaign) []attacknetv1beta1.UpgradeAssignment {
	if campaign == nil || campaign.Status.BaselineInventory == nil || campaign.Status.Phase == "RollingBack" || campaign.Status.Phase == "" || campaign.Status.Phase == "Pending" || campaign.Status.RollbackComplete {
		return nil
	}
	last := int(campaign.Status.CurrentStage)
	if last >= len(campaign.Spec.Stages) {
		last = len(campaign.Spec.Stages) - 1
	}
	resolved := map[string]attacknetv1beta1.UpgradeAssignment{}
	for index := 0; index <= last && index < len(campaign.Spec.Stages); index++ {
		for _, assignment := range campaign.Spec.Stages[index].Assignments {
			resolved[assignment.Actor] = *assignment.DeepCopy()
		}
	}
	result := make([]attacknetv1beta1.UpgradeAssignment, 0, len(resolved))
	for _, assignment := range resolved {
		result = append(result, assignment)
	}
	sort.Slice(result, func(i, j int) bool { return strings.Compare(result[i].Actor, result[j].Actor) < 0 })
	return result
}

// ApplyOverlay copies a network and applies one campaign's cumulative desired state.
func ApplyOverlay(network *attacknetv1beta1.StacksNetwork, campaign *attacknetv1beta1.UpgradeCampaign) (*attacknetv1beta1.StacksNetwork, error) {
	if campaign == nil {
		return network.DeepCopy(), nil
	}
	if err := Validate(campaign, network); err != nil {
		return nil, err
	}
	return ApplyAssignments(network, campaign.Spec.Profiles, EffectiveAssignments(campaign))
}

// ApplyAssignments copies a network and applies explicit resolved profiles.
func ApplyAssignments(network *attacknetv1beta1.StacksNetwork, profiles []attacknetv1beta1.UpgradeProfileSpec, assignments []attacknetv1beta1.UpgradeAssignment) (*attacknetv1beta1.StacksNetwork, error) {
	result := network.DeepCopy()
	byName := map[string]attacknetv1beta1.UpgradeProfileSpec{}
	for _, profile := range profiles {
		byName[profile.Name] = profile
	}
	for _, assignment := range assignments {
		profile, ok := byName[assignment.Profile]
		if !ok {
			return nil, fmt.Errorf("upgrade actor %q references unknown profile %q", assignment.Actor, assignment.Profile)
		}
		if !applyActor(result, assignment, profile.Image) {
			return nil, fmt.Errorf("upgrade actor %q disappeared from network", assignment.Actor)
		}
	}
	return result, nil
}

func applyActor(network *attacknetv1beta1.StacksNetwork, assignment attacknetv1beta1.UpgradeAssignment, image string) bool {
	for index := range network.Spec.Nodes {
		if network.Spec.Nodes[index].Name == assignment.Actor {
			network.Spec.Nodes[index].Image = image
			if assignment.Config != nil {
				network.Spec.Nodes[index].Config = *assignment.Config.DeepCopy()
			}
			return true
		}
	}
	for setIndex := range network.Spec.SignerSets {
		for memberIndex := range network.Spec.SignerSets[setIndex].Members {
			member := &network.Spec.SignerSets[setIndex].Members[memberIndex]
			switch assignment.Actor {
			case member.Name:
				member.SignerImage = image
				if assignment.Config != nil {
					member.SignerConfig = *assignment.Config.DeepCopy()
				}
				return true
			case member.NodeName:
				member.NodeImage = image
				if assignment.Config != nil {
					member.NodeConfig = *assignment.Config.DeepCopy()
				}
				return true
			}
		}
	}
	return false
}
