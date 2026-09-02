package attacknetcli

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var immutableImageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// LocalImage identifies one locally built Attacknet image.
type LocalImage struct {
	Purpose string `json:"purpose"`
	Ref     string `json:"ref"`
	ID      string `json:"id"`
}

// LocalBuildOptions controls the deterministic local image build set.
type LocalBuildOptions struct {
	RepositoryRoot   string
	BuildStacksImage bool
	SkipStackerImage bool
	DockerProgram    string
}

// LocalBuildResult reports every built image and its immutable Docker ID.
type LocalBuildResult struct {
	SchemaVersion string       `json:"schemaVersion"`
	Images        []LocalImage `json:"images"`
}

// LocalImageBuilder builds the supported local image set.
type LocalImageBuilder struct {
	Runner CommandRunner
}

type localBuildSpec struct {
	purpose    string
	ref        string
	contextDir string
	dockerfile string
	buildArgs  []string
}

// Build builds images sequentially and resolves every output to an immutable
// local Docker image ID.
func (builder LocalImageBuilder) Build(ctx context.Context, options LocalBuildOptions) (LocalBuildResult, error) {
	if builder.Runner == nil {
		return LocalBuildResult{}, fmt.Errorf("command runner is required")
	}
	if options.RepositoryRoot == "" {
		return LocalBuildResult{}, fmt.Errorf("repository root is required")
	}
	docker := options.DockerProgram
	if docker == "" {
		docker = "docker"
	}
	operatorRoot := filepath.Join(options.RepositoryRoot, "contrib", "helm", "hacknet", "operator")
	specs := []localBuildSpec{
		{purpose: "topology-operator", ref: "stacks-hacknet-operator:dev", contextDir: operatorRoot, buildArgs: []string{"BINARY=topology-operator"}},
		{purpose: "run-operator", ref: "stacks-hacknet-run-operator:dev", contextDir: operatorRoot, buildArgs: []string{"BINARY=run-operator"}},
		{purpose: "burnchain-clock", ref: "stacks-hacknet-burnchain-clock:dev", contextDir: operatorRoot, buildArgs: []string{"BINARY=burnchain-clock"}},
		{purpose: "probe", ref: "stacks-hacknet-probe:dev", contextDir: filepath.Join(options.RepositoryRoot, "contrib", "attacknet", "images", "probe")},
		{purpose: "io-pressure", ref: "stacks-hacknet-io-pressure:dev", contextDir: options.RepositoryRoot, dockerfile: filepath.Join(options.RepositoryRoot, "contrib", "attacknet", "images", "io-pressure", "Dockerfile")},
	}
	if !options.SkipStackerImage {
		specs = append(specs, localBuildSpec{purpose: "stacker", ref: "stacks-attacknet-stacker:local", contextDir: filepath.Join(options.RepositoryRoot, "contrib", "attacknet", "images", "stacker")})
	}
	if options.BuildStacksImage {
		specs = append(specs, localBuildSpec{purpose: "stacks-core", ref: "stacks-core-attacknet:main", contextDir: options.RepositoryRoot, dockerfile: filepath.Join(options.RepositoryRoot, "contrib", "attacknet", "images", "cli", "Dockerfile")})
	}
	result := LocalBuildResult{SchemaVersion: "stacks-attacknet-local-build/v1"}
	for _, spec := range specs {
		args := []string{"build"}
		for _, argument := range spec.buildArgs {
			args = append(args, "--build-arg", argument)
		}
		args = append(args, "--tag", spec.ref)
		if spec.dockerfile != "" {
			args = append(args, "--file", spec.dockerfile)
		}
		args = append(args, spec.contextDir)
		if _, err := builder.Runner.Run(ctx, Command{Program: docker, Args: args}); err != nil {
			return LocalBuildResult{}, fmt.Errorf("build %s image: %w", spec.purpose, err)
		}
		id, err := inspectImageID(ctx, builder.Runner, docker, spec.ref)
		if err != nil {
			return LocalBuildResult{}, err
		}
		result.Images = append(result.Images, LocalImage{Purpose: spec.purpose, Ref: spec.ref, ID: id})
	}
	return result, nil
}

func inspectImageID(ctx context.Context, runner CommandRunner, docker, ref string) (string, error) {
	result, err := runner.Run(ctx, Command{Program: docker, Args: []string{"image", "inspect", "--format", "{{.Id}}", ref}})
	if err != nil {
		return "", fmt.Errorf("inspect local image %s: %w", ref, err)
	}
	id := strings.TrimSpace(result.Stdout)
	if !immutableImageIDPattern.MatchString(id) {
		return "", fmt.Errorf("could not resolve immutable local image ID for %s", ref)
	}
	return id, nil
}

func immutableLocalRef(ref, id string) (repository, tag, resolved string, err error) {
	if !immutableImageIDPattern.MatchString(id) {
		return "", "", "", fmt.Errorf("invalid immutable image ID for %s", ref)
	}
	if strings.Contains(ref, "@") {
		return "", "", "", fmt.Errorf("image %s must be a locally tagged reference", ref)
	}
	colon := strings.LastIndex(ref, ":")
	if colon <= strings.LastIndex(ref, "/") {
		return "", "", "", fmt.Errorf("image %s must be a locally tagged reference", ref)
	}
	repository = ref[:colon]
	tag = "local-" + strings.TrimPrefix(id, "sha256:")[:16]
	return repository, tag, repository + ":" + tag, nil
}
