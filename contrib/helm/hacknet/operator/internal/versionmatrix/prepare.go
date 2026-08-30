package versionmatrix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/imagearchive"
)

// Invocation is one shell-free external process request.
type Invocation struct {
	Directory string
	Program   string
	Args      []string
	Stdin     []byte
}

// Executor runs explicit argv without shell interpretation.
type Executor interface {
	Execute(context.Context, Invocation) (stdout, stderr string, err error)
}

// PrepareOptions controls source materialization and image building.
type PrepareOptions struct {
	Workspace string
	// RecipeRoot contains explicitly selected host-scoped Dockerfiles. It is
	// never used as the build context for untrusted source.
	RecipeRoot string
	Git        string
	Docker     string
}

// Preparer resolves and builds one immutable descriptor.
type Preparer struct {
	Executor Executor
}

// Prepare resolves every profile and deterministic actor assignment.
func (preparer Preparer) Prepare(ctx context.Context, plan Plan, options PrepareOptions) (Descriptor, error) {
	if preparer.Executor == nil {
		return Descriptor{}, errors.New("version preparation executor is required")
	}
	if err := ValidatePlan(plan); err != nil {
		return Descriptor{}, err
	}
	if options.Workspace == "" {
		return Descriptor{}, errors.New("version preparation workspace is required")
	}
	if options.RecipeRoot == "" {
		options.RecipeRoot = "."
	}
	recipeRoot, err := filepath.Abs(options.RecipeRoot)
	if err != nil {
		return Descriptor{}, fmt.Errorf("resolve recipe root: %w", err)
	}
	options.RecipeRoot = recipeRoot
	if err := os.MkdirAll(options.Workspace, 0o750); err != nil {
		return Descriptor{}, fmt.Errorf("create preparation workspace: %w", err)
	}
	if options.Git == "" {
		options.Git = "git"
	}
	if options.Docker == "" {
		options.Docker = "docker"
	}
	planDigest, err := canonical.ArtifactDigest(plan)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		SchemaVersion: DescriptorSchema, MatrixID: plan.MatrixID, Platform: plan.Platform,
		PlanDigest: planDigest, Upgrade: plan.Upgrade,
		Assignment: AssignmentReceipt{
			Algorithm: AssignmentAlgorithm, Seed: plan.Assignment.Seed,
			Actors: append([]ActorPlan(nil), plan.Actors...), Overrides: append([]Assignment(nil), plan.Assignment.Overrides...),
			Weighted: append([]WeightedProfile(nil), plan.Assignment.Weighted...),
		},
	}
	sort.Slice(descriptor.Assignment.Actors, func(i, j int) bool {
		return descriptor.Assignment.Actors[i].Name < descriptor.Assignment.Actors[j].Name
	})
	for _, profile := range plan.Profiles {
		resolved, err := preparer.prepareProfile(ctx, plan, profile, options)
		if err != nil {
			return Descriptor{}, fmt.Errorf("prepare profile %s: %w", profile.Name, err)
		}
		descriptor.Profiles = append(descriptor.Profiles, resolved)
	}
	sort.Slice(descriptor.Profiles, func(i, j int) bool { return descriptor.Profiles[i].Name < descriptor.Profiles[j].Name })
	descriptor.Configurations, err = preparer.prepareActorConfigurations(ctx, plan.Configurations, descriptor.Profiles, options.Docker)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor.Assignments, err = ResolveAssignments(plan)
	if err != nil {
		return Descriptor{}, err
	}
	digestView := descriptor
	digestView.Digest = ""
	descriptor.Digest, err = canonical.ArtifactDigest(digestView)
	return descriptor, err
}

func (preparer Preparer) prepareProfile(ctx context.Context, plan Plan, profile ProfilePlan, options PrepareOptions) (ResolvedProfile, error) {
	resolved := ResolvedProfile{Name: profile.Name, SourceKind: profile.Source.Kind, Repository: sanitizeRepository(profile.Source.Repository), RequestedRef: profile.Source.Ref, Image: profile.Image, Capabilities: sortedCapabilities(profile.Capabilities), Expectation: profile.Expectation}
	if profile.Configuration != nil {
		resolved.ConfigSensitive = profile.Configuration.Secret || profile.Configuration.Source != nil && profile.Configuration.Source.SecretRef != nil
	}
	if profile.Configuration != nil && profile.Configuration.Source != nil {
		resolved.ConfigSource = profile.Configuration.Source.DeepCopy()
		resolved.ConfigSource.ExpectedDigest = profile.Configuration.ExpectedDigest
	}
	sourceRoot := ""
	switch profile.Source.Kind {
	case "remoteGit":
		resolvedObject, err := preparer.resolveRemote(ctx, profile.Source, options)
		if err != nil {
			return ResolvedProfile{}, err
		}
		sourceRoot = sealedSourceRoot(options.Workspace, profile.Name, resolvedObject)
		if err := os.MkdirAll(filepath.Dir(sourceRoot), 0o750); err != nil {
			return ResolvedProfile{}, err
		}
		if _, err := os.Stat(sourceRoot); errors.Is(err, os.ErrNotExist) {
			if _, _, err := preparer.Executor.Execute(ctx, Invocation{Program: options.Git, Args: []string{"clone", "--filter=blob:none", "--no-checkout", profile.Source.Repository, sourceRoot}}); err != nil {
				return ResolvedProfile{}, fmt.Errorf("clone sealed source: %w", err)
			}
		} else if err != nil {
			return ResolvedProfile{}, err
		} else if err := preparer.requireReusableCheckout(ctx, options.Git, sourceRoot, resolvedObject); err != nil {
			return ResolvedProfile{}, fmt.Errorf("reuse sealed source: %w", err)
		}
		if _, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: sourceRoot, Program: options.Git, Args: []string{"checkout", "--detach", resolvedObject}}); err != nil {
			return ResolvedProfile{}, fmt.Errorf("checkout sealed revision: %w", err)
		}
		confirmedObject, err := preparer.resolveRemote(ctx, profile.Source, options)
		if err != nil {
			return ResolvedProfile{}, err
		}
		if confirmedObject != resolvedObject {
			return ResolvedProfile{}, fmt.Errorf("Git ref moved during preparation: resolved %s, now %s", resolvedObject, confirmedObject)
		}
		resolved.Revision, err = preparer.gitOutput(ctx, options.Git, sourceRoot, "rev-parse", "--verify", resolvedObject+"^{commit}")
		if err != nil || !revisionPattern.MatchString(resolved.Revision) {
			return ResolvedProfile{}, errors.New("resolved Git object is not a commit")
		}
		if _, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: sourceRoot, Program: options.Git, Args: []string{"submodule", "update", "--init", "--recursive"}}); err != nil {
			return ResolvedProfile{}, fmt.Errorf("materialize sealed submodules: %w", err)
		}
	case "localGit":
		root, err := filepath.Abs(profile.Source.Repository)
		if err != nil {
			return ResolvedProfile{}, err
		}
		ref := profile.Source.Ref
		if ref == "" {
			ref = "HEAD"
		}
		resolved.RequestedRef = ref
		resolved.Revision, err = preparer.gitOutput(ctx, options.Git, root, "rev-parse", "--verify", ref+"^{commit}")
		if err != nil {
			return ResolvedProfile{}, err
		}
		head, err := preparer.gitOutput(ctx, options.Git, root, "rev-parse", "--verify", "HEAD^{commit}")
		if err != nil {
			return ResolvedProfile{}, err
		}
		resolved.DirtyPatchDigest, resolved.UntrackedDigest, err = preparer.localChanges(ctx, options.Git, root)
		if err != nil {
			return ResolvedProfile{}, err
		}
		sourceRoot = root
		if resolved.Revision != head {
			if resolved.DirtyPatchDigest != sum(nil) || resolved.UntrackedDigest != sum(nil) {
				return ResolvedProfile{}, errors.New("localGit ref differs from HEAD while the checkout has uncommitted content")
			}
			sourceRoot = sealedSourceRoot(options.Workspace, profile.Name, resolved.Revision)
			if err := os.MkdirAll(filepath.Dir(sourceRoot), 0o750); err != nil {
				return ResolvedProfile{}, err
			}
			if _, err := os.Stat(sourceRoot); errors.Is(err, os.ErrNotExist) {
				if _, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: root, Program: options.Git, Args: []string{"worktree", "add", "--detach", sourceRoot, resolved.Revision}}); err != nil {
					return ResolvedProfile{}, fmt.Errorf("materialize local Git ref: %w", err)
				}
			} else if err != nil {
				return ResolvedProfile{}, err
			} else if err := preparer.requireReusableCheckout(ctx, options.Git, sourceRoot, resolved.Revision); err != nil {
				return ResolvedProfile{}, fmt.Errorf("reuse local Git ref: %w", err)
			}
			if _, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: sourceRoot, Program: options.Git, Args: []string{"submodule", "update", "--init", "--recursive"}}); err != nil {
				return ResolvedProfile{}, fmt.Errorf("materialize local submodules: %w", err)
			}
			resolved.DirtyPatchDigest, resolved.UntrackedDigest = "", ""
		}
	case "prebuilt":
		if _, _, err := preparer.Executor.Execute(ctx, Invocation{Program: options.Docker, Args: []string{"pull", "--platform", plan.Platform, profile.Image}}); err != nil {
			return ResolvedProfile{}, fmt.Errorf("pull immutable prebuilt image: %w", err)
		}
	}
	if profile.Source.ExpectedRevision != "" && resolved.Revision != profile.Source.ExpectedRevision {
		return ResolvedProfile{}, fmt.Errorf("resolved revision %s does not match expected %s", resolved.Revision, profile.Source.ExpectedRevision)
	}
	if sourceRoot != "" {
		var err error
		resolved.Tree, err = preparer.gitOutput(ctx, options.Git, sourceRoot, "rev-parse", resolved.Revision+"^{tree}")
		if err != nil {
			return ResolvedProfile{}, err
		}
		resolved.Submodules, err = preparer.submodules(ctx, options.Git, sourceRoot)
		if err != nil {
			return ResolvedProfile{}, err
		}
	}
	if profile.Build != nil {
		dockerfilePath := filepath.Join(sourceRoot, filepath.Clean(profile.Build.Dockerfile))
		if profile.Build.DockerfileScope == "host" {
			dockerfilePath = filepath.Join(options.RecipeRoot, filepath.Clean(profile.Build.Dockerfile))
		}
		dockerfile, err := os.ReadFile(dockerfilePath)
		if err != nil {
			return ResolvedProfile{}, err
		}
		resolved.DockerfileDigest = sum(dockerfile)
		resolved.BuildInputDigest, err = canonical.ArtifactDigest(struct {
			Platform       string            `json:"platform"`
			Plan           BuildPlan         `json:"plan"`
			Revision       string            `json:"revision"`
			Tree           string            `json:"tree"`
			Submodules     map[string]string `json:"submodules,omitempty"`
			Patch          string            `json:"dirtyPatchDigest,omitempty"`
			Untracked      string            `json:"untrackedDigest,omitempty"`
			DockerfileHash string            `json:"dockerfileDigest"`
		}{plan.Platform, *profile.Build, resolved.Revision, resolved.Tree, resolved.Submodules, resolved.DirtyPatchDigest, resolved.UntrackedDigest, resolved.DockerfileDigest})
		if err != nil {
			return ResolvedProfile{}, err
		}
		if err := preparer.build(ctx, profile, sourceRoot, dockerfilePath, plan.Platform, resolved.BuildInputDigest, options.Docker); err != nil {
			return ResolvedProfile{}, fmt.Errorf("BuildFailed: %w", err)
		}
	}
	imageID, err := preparer.platformImageID(ctx, options.Docker, options.Workspace, plan.Platform, profile.Image)
	if err != nil || !digestPattern.MatchString(imageID) {
		return ResolvedProfile{}, fmt.Errorf("resolve immutable image identity for %s", profile.Image)
	}
	resolved.ImageID = imageID
	if profile.Build != nil {
		resolved.BuildDigest, err = canonical.ArtifactDigest(struct {
			Input   string `json:"buildInputDigest"`
			Image   string `json:"image"`
			ImageID string `json:"imageID"`
		}{resolved.BuildInputDigest, resolved.Image, resolved.ImageID})
		if err != nil {
			return ResolvedProfile{}, err
		}
	}
	resolved.ConfigDigest, resolved.ConfigSmoke, err = preparer.smokeConfiguration(ctx, profile.Image, profile.Configuration, options.Docker)
	if err != nil {
		return ResolvedProfile{}, fmt.Errorf("ConfigurationUnsupported: %w", err)
	}
	if resolved.ConfigSource != nil {
		resolved.ConfigSource.ExpectedDigest = resolved.ConfigDigest
	}
	provenance := resolved
	provenance.ProvenanceDigest = ""
	resolved.ProvenanceDigest, err = canonical.ArtifactDigest(provenance)
	return resolved, err
}

func sealedSourceRoot(workspace, profile, revision string) string {
	return filepath.Join(workspace, "sources", profile+"-"+revision[:12])
}

func (preparer Preparer) platformImageID(ctx context.Context, docker, workspace, platform, image string) (string, error) {
	archive, err := os.CreateTemp(workspace, ".platform-image-*.tar")
	if err != nil {
		return "", err
	}
	path := archive.Name()
	if err := archive.Close(); err != nil {
		return "", err
	}
	defer os.Remove(path)
	if _, _, err := preparer.Executor.Execute(ctx, Invocation{Program: docker, Args: []string{
		"save", "--platform", platform, "--output", path, image,
	}}); err != nil {
		return "", fmt.Errorf("export platform image: %w", err)
	}
	identities, err := imagearchive.PlatformConfigIDs(path, []string{image}, nil)
	if err != nil {
		return "", err
	}
	return identities[image], nil
}

func (preparer Preparer) prepareActorConfigurations(ctx context.Context, plans []ActorConfigurationPlan, profiles []ResolvedProfile, docker string) ([]ResolvedActorConfiguration, error) {
	byName := make(map[string]ResolvedProfile, len(profiles))
	for _, profile := range profiles {
		byName[profile.Name] = profile
	}
	result := make([]ResolvedActorConfiguration, 0, len(plans))
	for index := range plans {
		plan := &plans[index]
		profile, ok := byName[plan.Profile]
		if !ok {
			return nil, fmt.Errorf("prepare configuration for %s/%s: profile is absent", plan.Actor, plan.Profile)
		}
		digest, smoke, err := preparer.smokeConfiguration(ctx, profile.Image, &plan.Configuration, docker)
		if err != nil {
			return nil, fmt.Errorf("prepare configuration for %s/%s: ConfigurationUnsupported: %w", plan.Actor, plan.Profile, err)
		}
		source := plan.Configuration.Source.DeepCopy()
		source.ExpectedDigest = digest
		result = append(result, ResolvedActorConfiguration{
			Actor: plan.Actor, Profile: plan.Profile, ConfigDigest: digest, ConfigSmoke: smoke,
			ConfigSensitive: plan.Configuration.Secret || source.SecretRef != nil, ConfigSource: source,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Actor != result[j].Actor {
			return result[i].Actor < result[j].Actor
		}
		return result[i].Profile < result[j].Profile
	})
	return result, nil
}

func (preparer Preparer) requireReusableCheckout(ctx context.Context, git, root, revision string) error {
	head, err := preparer.gitOutput(ctx, git, root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || head != revision {
		return fmt.Errorf("workspace contains revision %q, expected %q", head, revision)
	}
	status, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: root, Program: git, Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}})
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "" {
		return errors.New("workspace checkout has unsealed changes")
	}
	return nil
}

func (preparer Preparer) resolveRemote(ctx context.Context, source SourcePlan, options PrepareOptions) (string, error) {
	if revisionPattern.MatchString(source.Ref) {
		return source.Ref, nil
	}
	stdout, _, err := preparer.Executor.Execute(ctx, Invocation{Program: options.Git, Args: []string{"ls-remote", "--exit-code", source.Repository, source.Ref, source.Ref + "^{}"}})
	if err != nil {
		return "", fmt.Errorf("resolve Git ref: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	refs := map[string]map[bool]string{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || !revisionPattern.MatchString(fields[0]) {
			return "", errors.New("Git ref did not resolve to one commit")
		}
		name := strings.TrimSuffix(fields[1], "^{}")
		peeled := strings.HasSuffix(fields[1], "^{}")
		if refs[name] == nil {
			refs[name] = map[bool]string{}
		}
		if existing := refs[name][peeled]; existing != "" && existing != fields[0] {
			return "", errors.New("Git ref resolved inconsistently")
		}
		refs[name][peeled] = fields[0]
	}
	if len(refs) != 1 {
		return "", errors.New("Git ref resolved ambiguously")
	}
	for _, candidates := range refs {
		if peeled := candidates[true]; peeled != "" {
			return peeled, nil
		}
		if object := candidates[false]; object != "" {
			return object, nil
		}
	}
	if len(lines) == 0 {
		return "", errors.New("Git ref did not resolve to one commit")
	}
	return "", errors.New("Git ref did not resolve to one commit")
}

func (preparer Preparer) submodules(ctx context.Context, git, root string) (map[string]string, error) {
	stdout, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: root, Program: git, Args: []string{"submodule", "status", "--recursive"}})
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed submodule status %q", line)
		}
		if strings.HasPrefix(fields[0], "-") || strings.HasPrefix(fields[0], "+") || strings.HasPrefix(fields[0], "U") {
			return nil, fmt.Errorf("submodule %s is not materialized at its sealed commit", fields[1])
		}
		revision := fields[0]
		if !revisionPattern.MatchString(revision) {
			return nil, fmt.Errorf("submodule %s lacks an exact commit", fields[1])
		}
		dirty, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: filepath.Join(root, filepath.Clean(fields[1])), Program: git, Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}})
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(dirty) != "" {
			return nil, fmt.Errorf("submodule %s has unsealed working-tree content", fields[1])
		}
		result[fields[1]] = revision
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func (preparer Preparer) localChanges(ctx context.Context, git, root string) (string, string, error) {
	patch, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: root, Program: git, Args: []string{"diff", "--binary", "HEAD"}})
	if err != nil {
		return "", "", err
	}
	patchDigest := sum([]byte(patch))
	untracked, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: root, Program: git, Args: []string{"ls-files", "--others", "--exclude-standard", "-z"}})
	if err != nil {
		return "", "", err
	}
	paths := strings.Split(strings.TrimSuffix(untracked, "\x00"), "\x00")
	if len(paths) == 1 && paths[0] == "" {
		paths = nil
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		clean := filepath.Clean(path)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", "", fmt.Errorf("unsafe untracked path %q", path)
		}
		content, err := os.ReadFile(filepath.Join(root, clean))
		if err != nil {
			return "", "", err
		}
		hash.Write([]byte(strconv.Itoa(len(clean))))
		hash.Write([]byte{0})
		hash.Write([]byte(clean))
		hash.Write([]byte{0})
		hash.Write(content)
	}
	return patchDigest, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (preparer Preparer) build(ctx context.Context, profile ProfilePlan, root, dockerfile, platform, buildInputDigest, docker string) error {
	build := profile.Build
	contextDir := root
	if build.Context != "" {
		contextDir = filepath.Join(root, filepath.Clean(build.Context))
	}
	args := []string{"build", "--platform", platform, "--file", dockerfile, "--tag", profile.Image}
	keys := make([]string, 0, len(build.Arguments))
	for key := range build.Arguments {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--build-arg", key+"="+build.Arguments[key])
	}
	cacheKey := strings.TrimPrefix(buildInputDigest, "sha256:")
	if len(cacheKey) != 64 {
		return errors.New("build input digest cannot scope the Cargo target cache")
	}
	args = append(args, "--build-arg", buildCacheKeyArgument+"="+cacheKey)
	args = append(args, contextDir)
	_, _, err := preparer.Executor.Execute(ctx, Invocation{Program: docker, Args: args})
	return err
}

func (preparer Preparer) smokeConfiguration(ctx context.Context, image string, configuration *ConfigPlan, docker string) (string, string, error) {
	if configuration == nil || configuration.File == "" {
		if configuration != nil && configuration.Source != nil {
			return configuration.ExpectedDigest, "externally-digest-bound", nil
		}
		return sum(nil), "not-provided", nil
	}
	path, err := filepath.Abs(configuration.File)
	if err != nil {
		return "", "", err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	digest := sum(content)
	if expected := configuration.ExpectedDigest; expected != "" && expected != digest {
		return "", "", fmt.Errorf("configuration digest %s does not match expected %s", digest, expected)
	}
	if len(configuration.SmokeCommand) == 0 {
		if configuration.AllowUnverified {
			return digest, "unverified-explicit", nil
		}
		return "", "", errors.New("raw configuration requires smokeCommand or allowUnverified")
	}
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--cpus", "0.5", "--memory", "512m", "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--mount", "type=bind,src=" + path + ",dst=/attacknet/config,readonly", image}
	args = append(args, configuration.SmokeCommand...)
	if _, _, err := preparer.Executor.Execute(ctx, Invocation{Program: docker, Args: args}); err != nil {
		return "", "", err
	}
	return digest, "passed", nil
}

func (preparer Preparer) gitOutput(ctx context.Context, git, root string, args ...string) (string, error) {
	stdout, _, err := preparer.Executor.Execute(ctx, Invocation{Directory: root, Program: git, Args: args})
	return strings.TrimSpace(stdout), err
}

func (preparer Preparer) dockerOutput(ctx context.Context, docker string, args ...string) (string, error) {
	stdout, _, err := preparer.Executor.Execute(ctx, Invocation{Program: docker, Args: args})
	return strings.TrimSpace(stdout), err
}

func sanitizeRepository(value string) string {
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	// SCP-like SSH locators may contain a username but no URL scheme. Preserve
	// the host/path identity while dropping anything before the final '@'.
	if at := strings.LastIndex(value, "@"); at >= 0 && !strings.Contains(value[:at], string(filepath.Separator)) {
		return value[at+1:]
	}
	return value
}

func sum(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// Marshal returns stable pretty JSON with a trailing newline.
func Marshal(descriptor Descriptor) ([]byte, error) {
	encoded, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// UnmarshalDescriptor validates a sealed descriptor before rendering it.
func UnmarshalDescriptor(value []byte) (Descriptor, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var descriptor Descriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return Descriptor{}, err
	}
	if descriptor.SchemaVersion != DescriptorSchema || !digestPattern.MatchString(descriptor.Digest) {
		return Descriptor{}, errors.New("invalid version descriptor")
	}
	view := descriptor
	view.Digest = ""
	digest, err := canonical.ArtifactDigest(view)
	if err != nil || digest != descriptor.Digest {
		return Descriptor{}, errors.New("version descriptor digest mismatch")
	}
	return descriptor, nil
}
