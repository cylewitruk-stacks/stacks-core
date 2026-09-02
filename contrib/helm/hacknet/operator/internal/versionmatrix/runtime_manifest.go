package versionmatrix

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/instrumentationprofile"
)

const (
	// RuntimeManifestAnnotation binds a static StacksNetwork to its finite
	// actor/profile provenance without copying source credentials or configs.
	RuntimeManifestAnnotation = "testing.stacks.org/version-runtime-manifest"
	runtimeManifestSchema     = "stacks-attacknet-runtime-version-manifest/v1"
)

// RuntimeManifest is the bounded, non-secret profile metadata admitted with a
// static mixed-version network.
type RuntimeManifest struct {
	SchemaVersion    string              `json:"schemaVersion"`
	DescriptorDigest string              `json:"descriptorDigest"`
	Profiles         []RuntimeProfile    `json:"profiles"`
	Assignments      []RuntimeAssignment `json:"assignments"`
}

// RuntimeAssignment joins one actor profile to its exact effective config.
type RuntimeAssignment struct {
	Actor        string `json:"actor"`
	Profile      string `json:"profile"`
	ConfigDigest string `json:"configDigest,omitempty"`
}

// RuntimeProfile contains only operator-safe provenance labels.
type RuntimeProfile struct {
	Name             string   `json:"name"`
	SourceKind       string   `json:"sourceKind"`
	Revision         string   `json:"revision,omitempty"`
	Image            string   `json:"image"`
	ImageID          string   `json:"imageID"`
	ProvenanceDigest string   `json:"provenanceDigest"`
	ConfigDigest     string   `json:"configDigest"`
	Capabilities     []string `json:"capabilities,omitempty"`
	Expectation      string   `json:"expectation,omitempty"`
}

func runtimeManifest(descriptor Descriptor) RuntimeManifest {
	manifest := RuntimeManifest{
		SchemaVersion: runtimeManifestSchema, DescriptorDigest: descriptor.Digest,
	}
	profiles := make(map[string]ResolvedProfile, len(descriptor.Profiles))
	for _, profile := range descriptor.Profiles {
		profiles[profile.Name] = profile
		manifest.Profiles = append(manifest.Profiles, RuntimeProfile{
			Name: profile.Name, SourceKind: profile.SourceKind, Revision: profile.Revision,
			Image: profile.Image, ImageID: profile.ImageID,
			ProvenanceDigest: profile.ProvenanceDigest, ConfigDigest: profile.ConfigDigest,
			Capabilities: append([]string(nil), profile.Capabilities...), Expectation: profile.Expectation,
		})
	}
	for _, assignment := range descriptor.Assignments {
		profile := profiles[assignment.Profile]
		_, configDigest := resolvedConfiguration(descriptor, assignment.Actor, assignment.Profile, profile)
		manifest.Assignments = append(manifest.Assignments, RuntimeAssignment{Actor: assignment.Actor, Profile: assignment.Profile, ConfigDigest: configDigest})
	}
	return manifest
}

// ParseRuntimeManifest verifies one annotation before metrics or evidence use.
func ParseRuntimeManifest(value string) (RuntimeManifest, error) {
	var manifest RuntimeManifest
	if err := json.Unmarshal([]byte(value), &manifest); err != nil {
		return RuntimeManifest{}, err
	}
	if manifest.SchemaVersion != runtimeManifestSchema || !digestPattern.MatchString(manifest.DescriptorDigest) || len(manifest.Profiles) == 0 || len(manifest.Profiles) > 32 || len(manifest.Assignments) == 0 || len(manifest.Assignments) > 100 {
		return RuntimeManifest{}, errors.New("invalid runtime version manifest")
	}
	profiles := make(map[string]struct{}, len(manifest.Profiles))
	for _, profile := range manifest.Profiles {
		if !profileNamePattern.MatchString(profile.Name) || profile.Image == "" || !digestPattern.MatchString(profile.ImageID) || !digestPattern.MatchString(profile.ProvenanceDigest) || !digestPattern.MatchString(profile.ConfigDigest) || !instrumentationprofile.Validate(profile.Capabilities) || !validExpectation(profile.Expectation) {
			return RuntimeManifest{}, fmt.Errorf("invalid runtime profile %q", profile.Name)
		}
		if profile.SourceKind != "remoteGit" && profile.SourceKind != "localGit" && profile.SourceKind != "prebuilt" || profile.Revision != "" && !revisionPattern.MatchString(profile.Revision) {
			return RuntimeManifest{}, fmt.Errorf("invalid runtime profile source %q", profile.Name)
		}
		if _, duplicate := profiles[profile.Name]; duplicate {
			return RuntimeManifest{}, fmt.Errorf("duplicate runtime profile %q", profile.Name)
		}
		profiles[profile.Name] = struct{}{}
	}
	actors := make(map[string]struct{}, len(manifest.Assignments))
	for _, assignment := range manifest.Assignments {
		if !profileNamePattern.MatchString(assignment.Actor) || assignment.ConfigDigest != "" && !digestPattern.MatchString(assignment.ConfigDigest) {
			return RuntimeManifest{}, fmt.Errorf("invalid runtime actor %q", assignment.Actor)
		}
		if _, ok := profiles[assignment.Profile]; !ok {
			return RuntimeManifest{}, fmt.Errorf("runtime actor %q references unknown profile %q", assignment.Actor, assignment.Profile)
		}
		if _, duplicate := actors[assignment.Actor]; duplicate {
			return RuntimeManifest{}, fmt.Errorf("duplicate runtime actor %q", assignment.Actor)
		}
		actors[assignment.Actor] = struct{}{}
	}
	return manifest, nil
}
