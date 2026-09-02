// Package versionmatrix prepares immutable mixed-version actor assignments
// outside Kubernetes. Controllers consume only its sealed results.
package versionmatrix

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/instrumentationprofile"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolassertion"
)

const (
	// PlanSchema identifies the human-authored preparation plan.
	PlanSchema = "stacks-attacknet-version-plan/v1"
	// DescriptorSchema identifies the immutable preparation result.
	DescriptorSchema = "stacks-attacknet-version-descriptor/v1"
	// AssignmentAlgorithm identifies the deterministic seeded bucketing rule.
	AssignmentAlgorithm   = "sha256-actor-bucket/v1"
	buildCacheKeyArgument = "ATTACKNET_BUILD_CACHE_KEY"
)

var (
	profileNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Plan is one bounded human-authored version-matrix request.
type Plan struct {
	SchemaVersion  string                   `json:"schemaVersion" yaml:"schemaVersion"`
	MatrixID       string                   `json:"matrixId" yaml:"matrixId"`
	Platform       string                   `json:"platform" yaml:"platform"`
	Profiles       []ProfilePlan            `json:"profiles" yaml:"profiles"`
	Actors         []ActorPlan              `json:"actors" yaml:"actors"`
	Configurations []ActorConfigurationPlan `json:"configurations,omitempty" yaml:"configurations,omitempty"`
	Assignment     AssignmentPlan           `json:"assignment" yaml:"assignment"`
	Upgrade        *UpgradePlan             `json:"upgrade,omitempty" yaml:"upgrade,omitempty"`
}

// ProfilePlan describes one remote, local, or prebuilt input.
type ProfilePlan struct {
	Name          string      `json:"name" yaml:"name"`
	Source        SourcePlan  `json:"source" yaml:"source"`
	Image         string      `json:"image" yaml:"image"`
	Build         *BuildPlan  `json:"build,omitempty" yaml:"build,omitempty"`
	Configuration *ConfigPlan `json:"configuration,omitempty" yaml:"configuration,omitempty"`
	Capabilities  []string    `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Expectation   string      `json:"expectation,omitempty" yaml:"expectation,omitempty"`
}

// SourcePlan selects exactly one source acquisition path.
type SourcePlan struct {
	// +kubebuilder:validation:Enum=remoteGit;localGit;prebuilt
	Kind             string `json:"kind" yaml:"kind"`
	Repository       string `json:"repository,omitempty" yaml:"repository,omitempty"`
	Ref              string `json:"ref,omitempty" yaml:"ref,omitempty"`
	ExpectedRevision string `json:"expectedRevision,omitempty" yaml:"expectedRevision,omitempty"`
}

// BuildPlan defines an explicit Docker build boundary.
type BuildPlan struct {
	Dockerfile string `json:"dockerfile" yaml:"dockerfile"`
	// DockerfileScope selects the selected source tree or the trusted host-side
	// recipe root supplied to version preparation.
	// +kubebuilder:validation:Enum=source;host
	DockerfileScope string            `json:"dockerfileScope,omitempty" yaml:"dockerfileScope,omitempty"`
	Context         string            `json:"context,omitempty" yaml:"context,omitempty"`
	Arguments       map[string]string `json:"arguments,omitempty" yaml:"arguments,omitempty"`
}

// ConfigPlan binds optional raw config and a target-specific smoke command.
type ConfigPlan struct {
	File string `json:"file,omitempty" yaml:"file,omitempty"`
	// ExpectedDigest is required for a runtime ConfigMap or Secret when no
	// local file is available to hash during preparation.
	ExpectedDigest  string   `json:"expectedDigest,omitempty" yaml:"expectedDigest,omitempty"`
	Secret          bool     `json:"secret,omitempty" yaml:"secret,omitempty"`
	SmokeCommand    []string `json:"smokeCommand,omitempty" yaml:"smokeCommand,omitempty"`
	AllowUnverified bool     `json:"allowUnverified,omitempty" yaml:"allowUnverified,omitempty"`
	// Source is the raw runtime ConfigMap/Secret reference rendered into an
	// UpgradeCampaign assignment. It may accompany a local smoke-test file.
	Source *attacknetv1beta1.ConfigSource `json:"source,omitempty" yaml:"source,omitempty"`
}

// ActorPlan identifies one topology actor and its role.
type ActorPlan struct {
	Name string `json:"name" yaml:"name"`
	Role string `json:"role" yaml:"role"`
}

// ActorConfigurationPlan selects a profile-specific raw config for one actor.
type ActorConfigurationPlan struct {
	Actor         string     `json:"actor" yaml:"actor"`
	Profile       string     `json:"profile" yaml:"profile"`
	Configuration ConfigPlan `json:"configuration" yaml:"configuration"`
}

// AssignmentPlan defines explicit overrides or deterministic weighted cohorts.
type AssignmentPlan struct {
	DefaultProfile string            `json:"defaultProfile" yaml:"defaultProfile"`
	Seed           string            `json:"seed,omitempty" yaml:"seed,omitempty"`
	Overrides      []Assignment      `json:"overrides,omitempty" yaml:"overrides,omitempty"`
	Weighted       []WeightedProfile `json:"weighted,omitempty" yaml:"weighted,omitempty"`
}

// Assignment binds an actor to one profile.
type Assignment struct {
	Actor   string `json:"actor" yaml:"actor"`
	Profile string `json:"profile" yaml:"profile"`
}

// WeightedProfile allocates integer basis points for selected roles.
type WeightedProfile struct {
	Profile     string   `json:"profile" yaml:"profile"`
	BasisPoints int32    `json:"basisPoints" yaml:"basisPoints"`
	Roles       []string `json:"roles,omitempty" yaml:"roles,omitempty"`
}

// UpgradePlan declares ordered batches for the rendered UpgradeCampaign.
type UpgradePlan struct {
	Name              string                             `json:"name" yaml:"name"`
	NetworkRef        string                             `json:"networkRef" yaml:"networkRef"`
	Stages            []UpgradeStagePlan                 `json:"stages" yaml:"stages"`
	Safety            attacknetv1beta1.UpgradeSafetySpec `json:"safety" yaml:"safety"`
	RollbackOnFailure bool                               `json:"rollbackOnFailure" yaml:"rollbackOnFailure"`
}

// UpgradeStagePlan is one profile assignment batch.
type UpgradeStagePlan struct {
	Name       string                                     `json:"name" yaml:"name"`
	Actors     []Assignment                               `json:"actors" yaml:"actors"`
	StableFor  string                                     `json:"stableFor" yaml:"stableFor"`
	Deadline   string                                     `json:"deadline" yaml:"deadline"`
	Assertions *attacknetv1beta1.ProtocolAssertionSetSpec `json:"assertions,omitempty" yaml:"assertions,omitempty"`
}

// Descriptor is the canonical immutable result consumed by rendering and replay.
type Descriptor struct {
	SchemaVersion  string                       `json:"schemaVersion"`
	MatrixID       string                       `json:"matrixId"`
	Platform       string                       `json:"platform"`
	PlanDigest     string                       `json:"planDigest"`
	Profiles       []ResolvedProfile            `json:"profiles"`
	Configurations []ResolvedActorConfiguration `json:"configurations,omitempty"`
	Assignments    []Assignment                 `json:"assignments"`
	Assignment     AssignmentReceipt            `json:"assignment"`
	Upgrade        *UpgradePlan                 `json:"upgrade,omitempty"`
	Digest         string                       `json:"digest"`
}

// ResolvedActorConfiguration binds one actor/profile pair to smoke-tested
// config bytes and its runtime ConfigMap or Secret source.
type ResolvedActorConfiguration struct {
	Actor           string                         `json:"actor"`
	Profile         string                         `json:"profile"`
	ConfigDigest    string                         `json:"configDigest"`
	ConfigSmoke     string                         `json:"configSmoke"`
	ConfigSensitive bool                           `json:"configSensitive,omitempty"`
	ConfigSource    *attacknetv1beta1.ConfigSource `json:"configSource"`
}

// AssignmentReceipt preserves every finite input to actor cohort selection.
type AssignmentReceipt struct {
	Algorithm string            `json:"algorithm"`
	Seed      string            `json:"seed,omitempty"`
	Actors    []ActorPlan       `json:"actors"`
	Overrides []Assignment      `json:"overrides,omitempty"`
	Weighted  []WeightedProfile `json:"weighted,omitempty"`
}

// ResolvedProfile records exact source, build, image, and configuration facts.
type ResolvedProfile struct {
	Name             string                         `json:"name"`
	SourceKind       string                         `json:"sourceKind"`
	Repository       string                         `json:"repository,omitempty"`
	RequestedRef     string                         `json:"requestedRef,omitempty"`
	Revision         string                         `json:"revision,omitempty"`
	Tree             string                         `json:"tree,omitempty"`
	Submodules       map[string]string              `json:"submodules,omitempty"`
	DirtyPatchDigest string                         `json:"dirtyPatchDigest,omitempty"`
	UntrackedDigest  string                         `json:"untrackedDigest,omitempty"`
	Image            string                         `json:"image"`
	ImageID          string                         `json:"imageID"`
	BuildDigest      string                         `json:"buildDigest,omitempty"`
	BuildInputDigest string                         `json:"buildInputDigest,omitempty"`
	DockerfileDigest string                         `json:"dockerfileDigest,omitempty"`
	ConfigDigest     string                         `json:"configDigest"`
	ConfigSmoke      string                         `json:"configSmoke"`
	ConfigSensitive  bool                           `json:"configSensitive,omitempty"`
	ConfigSource     *attacknetv1beta1.ConfigSource `json:"configSource,omitempty"`
	Capabilities     []string                       `json:"capabilities,omitempty"`
	Expectation      string                         `json:"expectation,omitempty"`
	ProvenanceDigest string                         `json:"provenanceDigest"`
}

// ValidatePlan rejects ambiguous or unbounded preparation inputs.
func ValidatePlan(plan Plan) error {
	if plan.SchemaVersion != PlanSchema {
		return fmt.Errorf("unsupported version plan schema %q", plan.SchemaVersion)
	}
	if !profileNamePattern.MatchString(plan.MatrixID) || plan.Platform == "" {
		return fmt.Errorf("matrixId and platform are required")
	}
	if len(plan.Profiles) == 0 || len(plan.Profiles) > 32 || len(plan.Actors) == 0 || len(plan.Actors) > 100 {
		return fmt.Errorf("version plan requires 1..32 profiles and 1..100 actors")
	}
	profiles := map[string]struct{}{}
	for _, profile := range plan.Profiles {
		if !profileNamePattern.MatchString(profile.Name) || profile.Image == "" {
			return fmt.Errorf("profile name and image are required")
		}
		if _, duplicate := profiles[profile.Name]; duplicate {
			return fmt.Errorf("duplicate profile %q", profile.Name)
		}
		profiles[profile.Name] = struct{}{}
		switch profile.Source.Kind {
		case "remoteGit":
			if profile.Source.Repository == "" || profile.Source.Ref == "" || profile.Build == nil {
				return fmt.Errorf("remoteGit profile %q requires repository, ref, and build", profile.Name)
			}
		case "localGit":
			if profile.Source.Repository == "" || profile.Build == nil {
				return fmt.Errorf("localGit profile %q requires repository and build", profile.Name)
			}
		case "prebuilt":
			if profile.Build != nil || !stringsContainDigest(profile.Image) {
				return fmt.Errorf("prebuilt profile %q requires an immutable image and no build", profile.Name)
			}
		default:
			return fmt.Errorf("profile %q has unsupported source kind %q", profile.Name, profile.Source.Kind)
		}
		if profile.Build != nil {
			if !safeRelativePath(profile.Build.Dockerfile) || profile.Build.Context != "" && !safeRelativePath(profile.Build.Context) {
				return fmt.Errorf("profile %q build paths must be safe relative paths", profile.Name)
			}
			if profile.Build.DockerfileScope != "" && profile.Build.DockerfileScope != "source" && profile.Build.DockerfileScope != "host" {
				return fmt.Errorf("profile %q dockerfileScope must be source or host", profile.Name)
			}
			if _, reserved := profile.Build.Arguments[buildCacheKeyArgument]; reserved {
				return fmt.Errorf("profile %q build argument %s is reserved", profile.Name, buildCacheKeyArgument)
			}
		}
		if profile.Source.ExpectedRevision != "" && !revisionPattern.MatchString(profile.Source.ExpectedRevision) {
			return fmt.Errorf("profile %q expectedRevision must be a 40-character SHA", profile.Name)
		}
		if !instrumentationprofile.Validate(profile.Capabilities) || !validExpectation(profile.Expectation) {
			return fmt.Errorf("profile %q has invalid capabilities or expectation", profile.Name)
		}
		if profile.Configuration != nil {
			if err := validateConfigPlan("profile "+profile.Name, profile.Configuration, false); err != nil {
				return err
			}
		}
	}
	if _, ok := profiles[plan.Assignment.DefaultProfile]; !ok {
		return fmt.Errorf("default profile %q is not declared", plan.Assignment.DefaultProfile)
	}
	actors := map[string]struct{}{}
	for _, actor := range plan.Actors {
		if !profileNamePattern.MatchString(actor.Name) || !validActorRole(actor.Role) {
			return fmt.Errorf("actor name and role must identify a Stacks node or signer")
		}
		if _, duplicate := actors[actor.Name]; duplicate {
			return fmt.Errorf("duplicate actor %q", actor.Name)
		}
		actors[actor.Name] = struct{}{}
	}
	if len(plan.Configurations) > 200 {
		return fmt.Errorf("version plan supports at most 200 actor configuration overrides")
	}
	configurations := map[string]struct{}{}
	for index := range plan.Configurations {
		configuration := &plan.Configurations[index]
		if _, ok := actors[configuration.Actor]; !ok {
			return fmt.Errorf("configuration references unknown actor %q", configuration.Actor)
		}
		if _, ok := profiles[configuration.Profile]; !ok {
			return fmt.Errorf("configuration for actor %q references unknown profile %q", configuration.Actor, configuration.Profile)
		}
		key := configuration.Actor + "\x00" + configuration.Profile
		if _, duplicate := configurations[key]; duplicate {
			return fmt.Errorf("duplicate configuration for actor %q and profile %q", configuration.Actor, configuration.Profile)
		}
		configurations[key] = struct{}{}
		if err := validateConfigPlan("configuration for "+configuration.Actor+"/"+configuration.Profile, &configuration.Configuration, true); err != nil {
			return err
		}
	}
	for _, override := range plan.Assignment.Overrides {
		if _, ok := actors[override.Actor]; !ok {
			return fmt.Errorf("override references unknown actor %q", override.Actor)
		}
		if _, ok := profiles[override.Profile]; !ok {
			return fmt.Errorf("override references unknown profile %q", override.Profile)
		}
	}
	if len(plan.Assignment.Weighted) > 0 {
		if plan.Assignment.Seed == "" {
			return fmt.Errorf("weighted assignment requires a seed")
		}
		seenWeighted := map[string]struct{}{}
		for _, weighted := range plan.Assignment.Weighted {
			if _, ok := profiles[weighted.Profile]; !ok || weighted.BasisPoints <= 0 {
				return fmt.Errorf("weighted assignment references an invalid profile")
			}
			key, err := canonicalRoleKey(weighted)
			if err != nil {
				return err
			}
			if _, duplicate := seenWeighted[key]; duplicate {
				return fmt.Errorf("duplicate weighted assignment for profile %q and roles", weighted.Profile)
			}
			seenWeighted[key] = struct{}{}
		}
		for _, actor := range plan.Actors {
			var total int32
			for _, weighted := range plan.Assignment.Weighted {
				if matchesRole(weighted.Roles, actor.Role) {
					total += weighted.BasisPoints
				}
			}
			if total > 10000 {
				return fmt.Errorf("weighted assignment exceeds 10000 basis points for role %q", actor.Role)
			}
		}
	}
	if plan.Upgrade != nil {
		if !profileNamePattern.MatchString(plan.Upgrade.Name) || plan.Upgrade.NetworkRef == "" || len(plan.Upgrade.Stages) == 0 || len(plan.Upgrade.Stages) > 64 {
			return fmt.Errorf("upgrade requires a name, networkRef, and 1..64 stages")
		}
		if plan.Upgrade.Safety.MaxParallelActors < 1 || plan.Upgrade.Safety.MaxParallelActors > 100 || plan.Upgrade.Safety.MaxSignerWeightPercent < 0 || plan.Upgrade.Safety.MaxSignerWeightPercent > 100 || plan.Upgrade.Safety.MaxMinerPercent < 0 || plan.Upgrade.Safety.MaxMinerPercent > 100 {
			return fmt.Errorf("upgrade safety bounds are invalid")
		}
		seenStages := map[string]struct{}{}
		for _, stage := range plan.Upgrade.Stages {
			stable, stableErr := time.ParseDuration(stage.StableFor)
			deadline, deadlineErr := time.ParseDuration(stage.Deadline)
			if !profileNamePattern.MatchString(stage.Name) || stableErr != nil || deadlineErr != nil || stable < 0 || deadline <= stable || len(stage.Actors) == 0 || int32(len(stage.Actors)) > plan.Upgrade.Safety.MaxParallelActors {
				return fmt.Errorf("upgrade stage %q has invalid timing or assignments", stage.Name)
			}
			if _, duplicate := seenStages[stage.Name]; duplicate {
				return fmt.Errorf("duplicate upgrade stage %q", stage.Name)
			}
			seenStages[stage.Name] = struct{}{}
			seenActors := map[string]struct{}{}
			for _, assignment := range stage.Actors {
				if _, ok := actors[assignment.Actor]; !ok {
					return fmt.Errorf("upgrade stage %q references unknown actor %q", stage.Name, assignment.Actor)
				}
				if _, ok := profiles[assignment.Profile]; !ok {
					return fmt.Errorf("upgrade stage %q references unknown profile %q", stage.Name, assignment.Profile)
				}
				if _, duplicate := seenActors[assignment.Actor]; duplicate {
					return fmt.Errorf("upgrade stage %q assigns actor %q twice", stage.Name, assignment.Actor)
				}
				seenActors[assignment.Actor] = struct{}{}
			}
			if err := protocolassertion.ValidateStructure(stage.Assertions); err != nil {
				return fmt.Errorf("upgrade stage %q assertions: %w", stage.Name, err)
			}
		}
	}
	return nil
}

func validateConfigPlan(label string, configuration *ConfigPlan, requireRuntimeSource bool) error {
	if configuration == nil {
		return fmt.Errorf("%s is absent", label)
	}
	if requireRuntimeSource && configuration.Source == nil {
		return fmt.Errorf("%s requires a runtime ConfigMap or Secret source", label)
	}
	if configuration.Source != nil && configuration.File == "" && !digestPattern.MatchString(configuration.ExpectedDigest) {
		return fmt.Errorf("%s requires expectedDigest when no local file is supplied", label)
	}
	if configuration.Source == nil {
		return nil
	}
	source := configuration.Source
	if source.Generated != nil || source.ConfigMapRef == nil && source.SecretRef == nil {
		return fmt.Errorf("%s must reference a ConfigMap or Secret", label)
	}
	ref := source.ConfigMapRef
	if ref == nil {
		ref = source.SecretRef
	}
	if ref.Name == "" || ref.Key == "" {
		return fmt.Errorf("%s requires an explicit object name and key", label)
	}
	if source.ExpectedDigest != "" && source.ExpectedDigest != configuration.ExpectedDigest {
		return fmt.Errorf("%s declares conflicting configuration digests", label)
	}
	return nil
}

func validExpectation(value string) bool {
	return value == "" || value == "compatible" || value == "incompatible" || value == "unknown" || value == "intentionally-incompatible"
}

func validActorRole(value string) bool {
	return value == "miner" || value == "follower" || value == "signer-node" || value == "signer"
}

func canonicalRoleKey(weighted WeightedProfile) (string, error) {
	roles := append([]string(nil), weighted.Roles...)
	sort.Strings(roles)
	for index, role := range roles {
		if role == "" || index > 0 && roles[index-1] == role {
			return "", fmt.Errorf("weighted assignment roles must be non-empty and unique")
		}
	}
	return weighted.Profile + "\x00" + strings.Join(roles, "\x00"), nil
}

func safeRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(value)
	return clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func stringsContainDigest(value string) bool {
	for index := 0; index+71 <= len(value); index++ {
		if value[index] == '@' && digestPattern.MatchString(value[index+1:]) {
			return true
		}
	}
	return false
}

func sortedCapabilities(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
