package versionmatrix

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeExecutor struct{ calls []Invocation }

func (executor *fakeExecutor) Execute(_ context.Context, invocation Invocation) (string, string, error) {
	executor.calls = append(executor.calls, invocation)
	if invocation.Program == "docker" && len(invocation.Args) > 0 && invocation.Args[0] == "save" {
		if err := writeDockerArchive(invocation.Args, "sha256:"+strings.Repeat("b", 64)); err != nil {
			return "", "", err
		}
	}
	return "", "", nil
}

type gitDockerExecutor struct {
	calls       []Invocation
	failRun     bool
	imageDigest string
}

type movingRefExecutor struct {
	gitDockerExecutor
	repository string
	moved      bool
}

func (executor *movingRefExecutor) Execute(ctx context.Context, invocation Invocation) (string, string, error) {
	stdout, stderr, err := executor.gitDockerExecutor.Execute(ctx, invocation)
	if !executor.moved && invocation.Program == "git" && len(invocation.Args) > 0 && invocation.Args[0] == "ls-remote" {
		executor.moved = true
		if moveErr := moveRepositoryHead(executor.repository); moveErr != nil {
			return stdout, stderr, moveErr
		}
	}
	return stdout, stderr, err
}

func moveRepositoryHead(repository string) error {
	if err := os.WriteFile(filepath.Join(repository, "tracked.txt"), []byte("moved\n"), 0o600); err != nil {
		return err
	}
	commands := [][]string{
		{"add", "tracked.txt"},
		{"-c", "commit.gpgsign=false", "-c", "user.name=Attacknet fixture", "-c", "user.email=attacknet-fixture@example.invalid", "commit", "--quiet", "-m", "move ref"},
	}
	for _, args := range commands {
		command := exec.Command("git", args...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, output)
		}
	}
	return nil
}

func (executor *gitDockerExecutor) Execute(ctx context.Context, invocation Invocation) (string, string, error) {
	executor.calls = append(executor.calls, invocation)
	if invocation.Program == "docker" {
		if len(invocation.Args) > 0 && invocation.Args[0] == "run" && executor.failRun {
			return "", "unsupported configuration", errors.New("container exited unsuccessfully")
		}
		if len(invocation.Args) > 0 && invocation.Args[0] == "save" {
			if err := writeDockerArchive(invocation.Args, executor.imageDigest); err != nil {
				return "", "", err
			}
		}
		return "", "", nil
	}
	command := exec.CommandContext(ctx, invocation.Program, invocation.Args...)
	command.Dir = invocation.Directory
	command.Stdin = strings.NewReader(string(invocation.Stdin))
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func writeDockerArchive(arguments []string, imageID string) error {
	var target string
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == "--output" {
			target = arguments[index+1]
		}
	}
	if target == "" || len(arguments) == 0 {
		return errors.New("docker save fixture lacks output or image")
	}
	ref := arguments[len(arguments)-1]
	tags := []string{ref}
	if strings.Contains(ref, "@sha256:") {
		tags = nil
	}
	manifest, err := json.Marshal([]map[string]any{{
		"Config": "blobs/sha256/" + strings.TrimPrefix(imageID, "sha256:"), "RepoTags": tags,
	}})
	if err != nil {
		return err
	}
	file, err := os.Create(target)
	if err != nil {
		return err
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		file.Close()
		return err
	}
	if _, err := writer.Write(manifest); err != nil {
		file.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func TestResolveAssignmentsIsSeededStableAndExplicitWins(t *testing.T) {
	plan := prebuiltPlan()
	plan.Actors = []ActorPlan{{Name: "signer-2", Role: "signer"}, {Name: "miner-1", Role: "miner"}, {Name: "signer-1", Role: "signer"}}
	plan.Assignment = AssignmentPlan{
		DefaultProfile: "stable", Seed: "fixed",
		Overrides: []Assignment{{Actor: "miner-1", Profile: "candidate"}},
		Weighted:  []WeightedProfile{{Profile: "candidate", BasisPoints: 5000, Roles: []string{"signer"}}},
	}
	first, err := ResolveAssignments(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveAssignments(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || first[0].Actor != "miner-1" || first[0].Profile != "candidate" || strings.TrimSpace(first[1].Actor) == "" {
		t.Fatalf("unexpected assignment: %#v", first)
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("same seed produced drift: %#v vs %#v", first, second)
		}
	}
}

func TestPreparePrebuiltSealsDescriptorAndRendersRawConfig(t *testing.T) {
	plan := prebuiltPlan()
	plan.Upgrade = &UpgradePlan{
		Name: "roll", NetworkRef: "network", RollbackOnFailure: true,
		Safety: attacknetv1beta1.UpgradeSafetySpec{MaxParallelActors: 1, MaxSignerWeightPercent: 40, MaxMinerPercent: 50},
		Stages: []UpgradeStagePlan{{Name: "one", StableFor: "1s", Deadline: "1m", Actors: []Assignment{{Actor: "miner-1", Profile: "candidate"}}}},
	}
	ref := &attacknetv1beta1.ConfigSource{ConfigMapRef: &attacknetv1beta1.ConfigObjectRef{Name: "candidate-miner", Key: "config.toml"}}
	plan.Configurations = []ActorConfigurationPlan{{
		Actor: "miner-1", Profile: "candidate",
		Configuration: ConfigPlan{Source: ref, ExpectedDigest: testDigest, AllowUnverified: true},
	}}
	executor := &fakeExecutor{}
	descriptor, err := (Preparer{Executor: executor}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Digest == "" || descriptor.Profiles[1].ImageID != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("descriptor was not sealed: %#v", descriptor)
	}
	if len(descriptor.Configurations) != 1 || descriptor.Configurations[0].ConfigDigest != testDigest {
		t.Fatalf("actor/profile configuration was not sealed independently: %#v", descriptor.Configurations)
	}
	encoded, err := Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalDescriptor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	campaign, err := RenderUpgradeCampaign(decoded, "test")
	if err != nil {
		t.Fatal(err)
	}
	if campaign.Spec.Stages[0].Assignments[0].Config == nil || campaign.Spec.Stages[0].Assignments[0].Config.ConfigMapRef.Name != "candidate-miner" {
		t.Fatalf("raw config source was not rendered: %#v", campaign.Spec.Stages[0].Assignments[0])
	}
	if campaign.Spec.Stages[0].Assignments[0].Config.ExpectedDigest != testDigest {
		t.Fatalf("raw config digest was not bound to the mounted source: %#v", campaign.Spec.Stages[0].Assignments[0].Config)
	}
}

func TestRenderStaticNetworkUsesTheSameSealedProfiles(t *testing.T) {
	descriptor := Descriptor{
		SchemaVersion: DescriptorSchema, Digest: testDigest,
		Profiles:    []ResolvedProfile{{Name: "candidate", SourceKind: "prebuilt", Image: "stacks:candidate", ImageID: testDigest, ProvenanceDigest: testDigest, ConfigDigest: testDigest}},
		Assignments: []Assignment{{Actor: "miner-1", Profile: "candidate"}},
		Assignment:  AssignmentReceipt{Actors: []ActorPlan{{Name: "miner-1", Role: "miner"}}},
	}
	network := &attacknetv1beta1.StacksNetwork{}
	network.Spec.Nodes = []attacknetv1beta1.StacksNodeSpec{{Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner}}
	rendered, err := RenderStaticNetwork(descriptor, network)
	if err != nil {
		t.Fatal(err)
	}
	if rendered.Spec.Nodes[0].Image != "stacks:candidate" || rendered.Annotations["testing.stacks.org/version-descriptor-digest"] != testDigest {
		t.Fatalf("static profile was not applied: %#v", rendered)
	}
	manifest, err := ParseRuntimeManifest(rendered.Annotations[RuntimeManifestAnnotation])
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Assignments[0].ConfigDigest != "" {
		t.Fatalf("inherited topology config was mislabeled as an exactly bound raw config: %#v", manifest.Assignments[0])
	}
	descriptor.Assignment.Actors[0].Role = "follower"
	if _, err := RenderStaticNetwork(descriptor, network); err == nil || !strings.Contains(err.Error(), "want \"miner\"") {
		t.Fatalf("actor-role drift was accepted: %v", err)
	}
}

func TestRuntimeManifestRejectsUnboundedCapabilityLabels(t *testing.T) {
	manifest := runtimeManifest(Descriptor{
		SchemaVersion: DescriptorSchema, Digest: testDigest,
		Profiles:    []ResolvedProfile{{Name: "candidate", SourceKind: "prebuilt", Image: "stacks:candidate", ImageID: testDigest, ProvenanceDigest: testDigest, ConfigDigest: testDigest, Capabilities: []string{"free-form"}}},
		Assignments: []Assignment{{Actor: "miner-1", Profile: "candidate"}},
	})
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRuntimeManifest(string(encoded)); err == nil || !strings.Contains(err.Error(), "invalid runtime profile") {
		t.Fatalf("unbounded capability label was accepted: %v", err)
	}
}

func TestValidatePlanRejectsMutablePrebuiltImageAndDuplicateOverride(t *testing.T) {
	plan := prebuiltPlan()
	plan.Profiles[0].Image = "example/stacks:latest"
	if err := ValidatePlan(plan); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("got %v, want mutable prebuilt rejection", err)
	}
	plan = prebuiltPlan()
	plan.Assignment.Overrides = []Assignment{{Actor: "miner-1", Profile: "stable"}, {Actor: "miner-1", Profile: "candidate"}}
	if _, err := ResolveAssignments(plan); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("got %v, want duplicate assignment rejection", err)
	}
	plan = prebuiltPlan()
	plan.Actors[0].Role = "arbitrary-label"
	if err := ValidatePlan(plan); err == nil || !strings.Contains(err.Error(), "Stacks node or signer") {
		t.Fatalf("got %v, want finite role rejection", err)
	}
}

func TestPrepareLocalGitSealsDirtyTreeBuildAndConfigSmoke(t *testing.T) {
	repository, revision := gitFixture(t)
	if err := os.WriteFile(filepath.Join(repository, "tracked.txt"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "untracked.txt"), []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte("[node]\nworking = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := sourcePlan("localGit", repository, "HEAD")
	plan.Profiles[0].Source.ExpectedRevision = revision
	plan.Profiles[0].Configuration = &ConfigPlan{
		File: config, SmokeCommand: []string{"stacks-node", "start", "--config", "/attacknet/config"},
		Source: &attacknetv1beta1.ConfigSource{SecretRef: &attacknetv1beta1.ConfigObjectRef{Name: "candidate-config", Key: "config.toml"}},
	}
	executor := &gitDockerExecutor{imageDigest: testDigest}
	descriptor, err := (Preparer{Executor: executor}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	profile := descriptor.Profiles[0]
	if profile.Revision != revision || profile.Tree == "" || profile.DirtyPatchDigest == sum(nil) || profile.UntrackedDigest == sum(nil) || profile.BuildDigest == "" {
		t.Fatalf("local source was not completely sealed: %#v", profile)
	}
	if profile.ConfigSmoke != "passed" || profile.ConfigSource == nil || profile.ConfigSource.ExpectedDigest != profile.ConfigDigest {
		t.Fatalf("configuration smoke did not bind the runtime Secret: %#v", profile)
	}
	var smoke Invocation
	var build Invocation
	for _, call := range executor.calls {
		if call.Program == "docker" && len(call.Args) > 0 && call.Args[0] == "build" {
			build = call
		}
		if call.Program == "docker" && len(call.Args) > 0 && call.Args[0] == "run" {
			smoke = call
		}
	}
	if got := strings.Join(build.Args, " "); !strings.Contains(got,
		"--build-arg "+buildCacheKeyArgument+"="+strings.TrimPrefix(profile.BuildInputDigest, "sha256:")) {
		t.Fatalf("build invocation does not scope its target cache: %s", got)
	}
	joined := strings.Join(smoke.Args, " ")
	for _, required := range []string{"--network none", "--read-only", "--pids-limit 128", "readonly"} {
		if !strings.Contains(joined, required) {
			t.Errorf("smoke invocation lacks %q: %s", required, joined)
		}
	}
}

func TestPrepareRemoteGitPinsRefAndRefusesMovedExpectation(t *testing.T) {
	repository, revision := gitFixture(t)
	plan := sourcePlan("remoteGit", repository, "HEAD")
	plan.Profiles[0].Source.ExpectedRevision = revision
	executor := &gitDockerExecutor{imageDigest: testDigest}
	descriptor, err := (Preparer{Executor: executor}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Profiles[0].Revision != revision || descriptor.Profiles[0].DirtyPatchDigest != "" || descriptor.Profiles[0].UntrackedDigest != "" {
		t.Fatalf("remote ref was not materialized as an exact clean commit: %#v", descriptor.Profiles[0])
	}
	plan.Profiles[0].Source.ExpectedRevision = strings.Repeat("f", 40)
	if _, err := (Preparer{Executor: executor}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("moved remote expectation was not rejected: %v", err)
	}
}

func TestPrepareRemoteGitSupportsExactCommitsAndAnnotatedTags(t *testing.T) {
	repository, revision := gitFixture(t)
	command := exec.Command("git", "-c", "user.name=Attacknet fixture", "-c", "user.email=attacknet-fixture@example.invalid", "tag", "-a", "release", "-m", "release")
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create annotated tag: %v: %s", err, output)
	}
	for _, ref := range []string{revision, "release"} {
		plan := sourcePlan("remoteGit", repository, ref)
		plan.Profiles[0].Source.ExpectedRevision = revision
		descriptor, err := (Preparer{Executor: &gitDockerExecutor{imageDigest: testDigest}}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()})
		if err != nil {
			t.Fatalf("prepare remote ref %s: %v", ref, err)
		}
		if descriptor.Profiles[0].Revision != revision {
			t.Fatalf("ref %s resolved to %s, want %s", ref, descriptor.Profiles[0].Revision, revision)
		}
	}
}

func TestPrepareRemoteGitKeepsContentAddressedRevisionsInOneWorkspace(t *testing.T) {
	repository, first := gitFixture(t)
	if err := moveRepositoryHead(repository); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = repository
	encoded, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	second := strings.TrimSpace(string(encoded))
	workspace := t.TempDir()
	for _, revision := range []string{first, second} {
		plan := sourcePlan("remoteGit", repository, revision)
		if _, err := (Preparer{Executor: &gitDockerExecutor{imageDigest: testDigest}}).Prepare(
			context.Background(), plan, PrepareOptions{Workspace: workspace}); err != nil {
			t.Fatalf("prepare revision %s: %v", revision, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(workspace, "sources"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("workspace retained %d sealed revisions, want 2", len(entries))
	}
}

func TestPrepareRemoteGitUsesDigestBoundHostRecipe(t *testing.T) {
	repository, _ := gitFixture(t)
	recipeRoot := t.TempDir()
	recipe := []byte("FROM scratch\nLABEL recipe=host\n")
	if err := os.WriteFile(filepath.Join(recipeRoot, "Dockerfile"), recipe, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := sourcePlan("remoteGit", repository, "HEAD")
	plan.Profiles[0].Build.DockerfileScope = "host"
	descriptor, err := (Preparer{Executor: &gitDockerExecutor{imageDigest: testDigest}}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir(), RecipeRoot: recipeRoot})
	if err != nil {
		t.Fatal(err)
	}
	if got := descriptor.Profiles[0].DockerfileDigest; got != sum(recipe) {
		t.Fatalf("host recipe digest = %s, want %s", got, sum(recipe))
	}
}

func TestPrepareRemoteGitRejectsRefMovementDuringMaterialization(t *testing.T) {
	repository, _ := gitFixture(t)
	plan := sourcePlan("remoteGit", repository, "HEAD")
	executor := &movingRefExecutor{gitDockerExecutor: gitDockerExecutor{imageDigest: testDigest}, repository: repository}
	if _, err := (Preparer{Executor: executor}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "moved during preparation") {
		t.Fatalf("moving ref was not rejected: %v", err)
	}
}

func TestPrepareRejectsConfigurationSmokeFailure(t *testing.T) {
	repository, _ := gitFixture(t)
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte("removed_field = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := sourcePlan("localGit", repository, "HEAD")
	plan.Profiles[0].Configuration = &ConfigPlan{File: config, SmokeCommand: []string{"validate", "/attacknet/config"}}
	executor := &gitDockerExecutor{imageDigest: testDigest, failRun: true}
	if _, err := (Preparer{Executor: executor}).Prepare(context.Background(), plan, PrepareOptions{Workspace: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "ConfigurationUnsupported") {
		t.Fatalf("unsupported version/config pair did not fail closed: %v", err)
	}
}

func sourcePlan(kind, repository, ref string) Plan {
	return Plan{
		SchemaVersion: PlanSchema, MatrixID: "source-matrix", Platform: "linux/arm64",
		Profiles: []ProfilePlan{{
			Name: "candidate", Source: SourcePlan{Kind: kind, Repository: repository, Ref: ref}, Image: "attacknet-source:test",
			Build: &BuildPlan{Dockerfile: "Dockerfile", Context: ".", Arguments: map[string]string{"PROFILE": "candidate"}},
		}},
		Actors: []ActorPlan{{Name: "miner-1", Role: "miner"}}, Assignment: AssignmentPlan{DefaultProfile: "candidate"},
	}
}

func TestValidatePlanRejectsReservedBuildCacheArgument(t *testing.T) {
	plan := sourcePlan("localGit", t.TempDir(), "HEAD")
	plan.Profiles[0].Build.Arguments[buildCacheKeyArgument] = "operator-supplied"
	if err := ValidatePlan(plan); err == nil || !strings.Contains(err.Error(), "is reserved") {
		t.Fatalf("got %v, want reserved build argument rejection", err)
	}
}

func gitFixture(t *testing.T) (string, string) {
	t.Helper()
	repository := t.TempDir()
	if err := os.WriteFile(filepath.Join(repository, "Dockerfile"), []byte("FROM scratch\nARG PROFILE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "tracked.txt"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"init", "--quiet"}, {"add", "Dockerfile", "tracked.txt"},
		{"-c", "commit.gpgsign=false", "-c", "user.name=Attacknet fixture", "-c", "user.email=attacknet-fixture@example.invalid", "commit", "--quiet", "-m", "fixture"},
	}
	for _, args := range commands {
		command := exec.Command("git", args...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
		}
	}
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = repository
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return repository, strings.TrimSpace(string(output))
}

func prebuiltPlan() Plan {
	return Plan{
		SchemaVersion: PlanSchema, MatrixID: "matrix", Platform: "linux/arm64",
		Profiles: []ProfilePlan{
			{Name: "stable", Source: SourcePlan{Kind: "prebuilt"}, Image: "example/stable@" + testDigest},
			{Name: "candidate", Source: SourcePlan{Kind: "prebuilt"}, Image: "example/candidate@" + testDigest},
		},
		Actors:     []ActorPlan{{Name: "miner-1", Role: "miner"}},
		Assignment: AssignmentPlan{DefaultProfile: "stable"},
	}
}
