package versionmatrix

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/upgrade"
)

// RenderStaticNetwork applies the descriptor's explicit mapping before the
// network is submitted, preserving topology ownership from the first Pod.
func RenderStaticNetwork(descriptor Descriptor, network *attacknetv1beta1.StacksNetwork) (*attacknetv1beta1.StacksNetwork, error) {
	declaredActors := make(map[string]string, len(descriptor.Assignment.Actors))
	for _, actor := range descriptor.Assignment.Actors {
		declaredActors[actor.Name] = actor.Role
	}
	actualActors := networkActorRoles(network)
	if len(declaredActors) != len(actualActors) {
		return nil, fmt.Errorf("version descriptor covers %d actors, StacksNetwork has %d upgradeable actors", len(declaredActors), len(actualActors))
	}
	for actor, role := range actualActors {
		if declaredActors[actor] != role {
			return nil, fmt.Errorf("version descriptor actor %s role is %q, want %q", actor, declaredActors[actor], role)
		}
	}
	profiles := make([]attacknetv1beta1.UpgradeProfileSpec, 0, len(descriptor.Profiles))
	resolved := map[string]ResolvedProfile{}
	for _, profile := range descriptor.Profiles {
		resolved[profile.Name] = profile
		profiles = append(profiles, apiUpgradeProfile(profile))
	}
	assignments := make([]attacknetv1beta1.UpgradeAssignment, 0, len(descriptor.Assignments))
	for _, assignment := range descriptor.Assignments {
		profile, ok := resolved[assignment.Profile]
		if !ok {
			return nil, fmt.Errorf("static actor %s references unknown profile %s", assignment.Actor, assignment.Profile)
		}
		config, _ := resolvedConfiguration(descriptor, assignment.Actor, assignment.Profile, profile)
		assignments = append(assignments, attacknetv1beta1.UpgradeAssignment{Actor: assignment.Actor, Profile: assignment.Profile, Config: config})
	}
	result, err := upgrade.ApplyAssignments(network, profiles, assignments)
	if err != nil {
		return nil, err
	}
	if result.Annotations == nil {
		result.Annotations = map[string]string{}
	}
	result.Annotations["testing.stacks.org/version-descriptor-digest"] = descriptor.Digest
	manifest, err := json.Marshal(runtimeManifest(descriptor))
	if err != nil {
		return nil, err
	}
	result.Annotations[RuntimeManifestAnnotation] = string(manifest)
	return result, nil
}

func networkActorRoles(network *attacknetv1beta1.StacksNetwork) map[string]string {
	result := make(map[string]string, len(network.Spec.Nodes)+2*len(network.Spec.SignerSets))
	for _, node := range network.Spec.Nodes {
		role := "follower"
		if node.Role == attacknetv1beta1.StacksNodeMiner {
			role = "miner"
		}
		result[node.Name] = role
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			result[member.Name] = "signer"
			result[member.NodeName] = "signer-node"
		}
	}
	return result
}

// RenderUpgradeCampaign creates the typed runtime request sealed by a descriptor.
func RenderUpgradeCampaign(descriptor Descriptor, namespace string) (*attacknetv1beta1.UpgradeCampaign, error) {
	if descriptor.Upgrade == nil {
		return nil, errors.New("version descriptor has no upgrade plan")
	}
	plan := descriptor.Upgrade
	profiles := make(map[string]ResolvedProfile, len(descriptor.Profiles))
	apiProfiles := make([]attacknetv1beta1.UpgradeProfileSpec, 0, len(descriptor.Profiles))
	for _, profile := range descriptor.Profiles {
		profiles[profile.Name] = profile
		apiProfiles = append(apiProfiles, apiUpgradeProfile(profile))
	}
	stages := make([]attacknetv1beta1.UpgradeStageSpec, 0, len(plan.Stages))
	for _, stage := range plan.Stages {
		stable, err := time.ParseDuration(stage.StableFor)
		if err != nil {
			return nil, fmt.Errorf("stage %s stableFor: %w", stage.Name, err)
		}
		deadline, err := time.ParseDuration(stage.Deadline)
		if err != nil {
			return nil, fmt.Errorf("stage %s deadline: %w", stage.Name, err)
		}
		assignments := make([]attacknetv1beta1.UpgradeAssignment, 0, len(stage.Actors))
		for _, assignment := range stage.Actors {
			if _, ok := profiles[assignment.Profile]; !ok {
				return nil, fmt.Errorf("stage %s references unknown profile %s", stage.Name, assignment.Profile)
			}
			resolved := profiles[assignment.Profile]
			config, _ := resolvedConfiguration(descriptor, assignment.Actor, assignment.Profile, resolved)
			assignments = append(assignments, attacknetv1beta1.UpgradeAssignment{Actor: assignment.Actor, Profile: assignment.Profile, Config: config})
		}
		stages = append(stages, attacknetv1beta1.UpgradeStageSpec{
			Name: stage.Name, Assignments: assignments,
			StableFor: metav1.Duration{Duration: stable}, Deadline: metav1.Duration{Duration: deadline},
			Assertions: stage.Assertions.DeepCopy(),
		})
	}
	return &attacknetv1beta1.UpgradeCampaign{
		TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "UpgradeCampaign"},
		ObjectMeta: metav1.ObjectMeta{Name: plan.Name, Namespace: namespace, Annotations: map[string]string{
			"testing.stacks.org/version-descriptor-digest": descriptor.Digest,
		}},
		Spec: attacknetv1beta1.UpgradeCampaignSpec{
			NetworkRef: plan.NetworkRef, Profiles: apiProfiles, Stages: stages,
			Safety: plan.Safety, RollbackOnFailure: plan.RollbackOnFailure,
		},
	}, nil
}

func resolvedConfiguration(descriptor Descriptor, actor, profileName string, profile ResolvedProfile) (*attacknetv1beta1.ConfigSource, string) {
	for index := range descriptor.Configurations {
		configuration := &descriptor.Configurations[index]
		if configuration.Actor == actor && configuration.Profile == profileName {
			return configuration.ConfigSource.DeepCopy(), configuration.ConfigDigest
		}
	}
	if profile.ConfigSource != nil {
		return profile.ConfigSource.DeepCopy(), profile.ConfigDigest
	}
	return nil, ""
}

func apiUpgradeProfile(profile ResolvedProfile) attacknetv1beta1.UpgradeProfileSpec {
	return attacknetv1beta1.UpgradeProfileSpec{
		Name: profile.Name, Image: profile.Image, ImageID: profile.ImageID,
		ProvenanceDigest: profile.ProvenanceDigest, ConfigDigest: profile.ConfigDigest,
		SourceKind: profile.SourceKind, Revision: profile.Revision,
		Capabilities: append([]string(nil), profile.Capabilities...), Expectation: profile.Expectation,
	}
}
