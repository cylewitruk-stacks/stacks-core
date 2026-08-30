package attacknetcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/document"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/versionmatrix"
)

func (app *App) runVersion(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet version prepare|load|render-static|render-upgrade [OPTIONS]")
	}
	switch args[0] {
	case "prepare":
		return app.runVersionPrepare(ctx, args[1:])
	case "load":
		return app.runVersionLoad(ctx, args[1:])
	case "render-upgrade":
		return app.runVersionRenderUpgrade(args[1:])
	case "render-static":
		return app.runVersionRenderStatic(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown version command %q", args[0]))
	}
}

func (app *App) runVersionLoad(ctx context.Context, args []string) error {
	flags := newFlagSet("version load", app.Stderr)
	descriptorPath := flags.String("descriptor", "", "sealed descriptor JSON path")
	mode := flags.String("mode", string(KindImageLoadRequire), "auto or require")
	docker := flags.String("docker", "docker", "Docker CLI program")
	kubectl := flags.String("kubectl", "kubectl", "kubectl program")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *descriptorPath == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet version load --descriptor FILE [--mode auto|require]")
	}
	value, err := os.ReadFile(*descriptorPath)
	if err != nil {
		return err
	}
	descriptor, err := versionmatrix.UnmarshalDescriptor(value)
	if err != nil {
		return err
	}
	refs, expectedRuntimeIDs, err := descriptorImageIdentities(descriptor)
	if err != nil {
		return err
	}
	receipt, err := (KindImageLoader{Runner: app.commandRunner()}).Load(ctx, KindImageLoadOptions{
		Mode: KindImageLoadMode(*mode), DockerProgram: *docker, KubectlProgram: *kubectl,
		Now: app.Now, ExpectedRuntimeIDs: expectedRuntimeIDs,
	}, refs)
	if err != nil {
		return err
	}
	if err := verifyDescriptorImports(descriptor, receipt); err != nil {
		return err
	}
	return writeJSON(app.Stdout, struct {
		SchemaVersion    string              `json:"schemaVersion"`
		DescriptorDigest string              `json:"descriptorDigest"`
		Import           KindImageLoadResult `json:"import"`
	}{"stacks-attacknet-version-import/v1", descriptor.Digest, receipt})
}

func verifyDescriptorImports(descriptor versionmatrix.Descriptor, receipt KindImageLoadResult) error {
	if receipt.Outcome != "Loaded" {
		return nil
	}
	_, expected, err := descriptorImageIdentities(descriptor)
	if err != nil {
		return err
	}
	seen := make(map[string]map[string]struct{}, len(expected))
	for _, imported := range receipt.Images {
		identity, ok := expected[imported.RequestedRef]
		if !ok || !imported.Verified || imported.RuntimeImageID != identity {
			return fmt.Errorf("kind import identity for %s is %s, expected %s", imported.RequestedRef, imported.RuntimeImageID, identity)
		}
		if seen[imported.RequestedRef] == nil {
			seen[imported.RequestedRef] = map[string]struct{}{}
		}
		seen[imported.RequestedRef][imported.Node] = struct{}{}
	}
	for image := range expected {
		if len(seen[image]) != len(receipt.Nodes) || len(receipt.Nodes) == 0 {
			return fmt.Errorf("kind import receipt for %s does not cover every target node", image)
		}
	}
	return nil
}

func descriptorImageIdentities(descriptor versionmatrix.Descriptor) ([]string, map[string]string, error) {
	refs := make([]string, 0, len(descriptor.Profiles))
	expected := make(map[string]string, len(descriptor.Profiles))
	for _, profile := range descriptor.Profiles {
		if previous := expected[profile.Image]; previous != "" && previous != profile.ImageID {
			return nil, nil, fmt.Errorf("descriptor binds image %s to multiple runtime identities", profile.Image)
		}
		if expected[profile.Image] == "" {
			refs = append(refs, profile.Image)
		}
		expected[profile.Image] = profile.ImageID
	}
	return refs, expected, nil
}

func (app *App) runVersionRenderStatic(args []string) error {
	flags := newFlagSet("version render-static", app.Stderr)
	descriptorPath := flags.String("descriptor", "", "sealed descriptor JSON path")
	networkPath := flags.String("network", "", "StacksNetwork YAML path")
	output := flags.String("output", "yaml", "yaml or json")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *descriptorPath == "" || *networkPath == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet version render-static --descriptor FILE --network FILE [--output yaml|json]")
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	descriptorBytes, err := os.ReadFile(*descriptorPath)
	if err != nil {
		return err
	}
	descriptor, err := versionmatrix.UnmarshalDescriptor(descriptorBytes)
	if err != nil {
		return err
	}
	networkBytes, err := os.ReadFile(*networkPath)
	if err != nil {
		return err
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := document.DecodeOne(networkBytes, network); err != nil {
		return err
	}
	rendered, err := versionmatrix.RenderStaticNetwork(descriptor, network)
	if err != nil {
		return err
	}
	valueMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(rendered)
	if err != nil {
		return err
	}
	delete(valueMap, "status")
	return writeResource(app.Stdout, &unstructured.Unstructured{Object: valueMap}, *output)
}

func (app *App) runVersionPrepare(ctx context.Context, args []string) error {
	flags := newFlagSet("version prepare", app.Stderr)
	file := flags.String("file", "", "version-plan YAML path")
	output := flags.String("output", "", "descriptor JSON path")
	workspace := flags.String("workspace", "", "persistent source/build workspace")
	recipeRoot := flags.String("recipe-root", ".", "trusted host Dockerfile root")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *file == "" || *output == "" || *workspace == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet version prepare --file PLAN.yaml --workspace DIR --output descriptor.json [--recipe-root DIR]")
	}
	encoded, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	plan, err := decodeVersionPlan(encoded)
	if err != nil {
		return err
	}
	descriptor, err := (versionmatrix.Preparer{Executor: versionExecutor{runner: app.commandRunner()}}).Prepare(ctx, plan, versionmatrix.PrepareOptions{Workspace: *workspace, RecipeRoot: *recipeRoot})
	if err != nil {
		return err
	}
	value, err := versionmatrix.Marshal(descriptor)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*output, value, 0o600); err != nil {
		return fmt.Errorf("write version descriptor: %w", err)
	}
	_, err = app.Stdout.Write(value)
	return err
}

func decodeVersionPlan(encoded []byte) (versionmatrix.Plan, error) {
	jsonValue, err := yaml.YAMLToJSON(encoded)
	if err != nil {
		return versionmatrix.Plan{}, fmt.Errorf("decode version plan YAML: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonValue))
	decoder.DisallowUnknownFields()
	var plan versionmatrix.Plan
	if err := decoder.Decode(&plan); err != nil {
		return versionmatrix.Plan{}, fmt.Errorf("decode version plan: %w", err)
	}
	if err := versionmatrix.ValidatePlan(plan); err != nil {
		return versionmatrix.Plan{}, err
	}
	return plan, nil
}

func (app *App) runVersionRenderUpgrade(args []string) error {
	flags := newFlagSet("version render-upgrade", app.Stderr)
	file := flags.String("descriptor", "", "sealed descriptor JSON path")
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	template := flags.Bool("template", true, "render an inert AttacknetRun catalog template")
	output := flags.String("output", "yaml", "yaml or json")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *file == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet version render-upgrade --descriptor FILE [--namespace NS] [--template=true|false] [--output yaml|json]")
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	value, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	descriptor, err := versionmatrix.UnmarshalDescriptor(value)
	if err != nil {
		return err
	}
	campaign, err := versionmatrix.RenderUpgradeCampaign(descriptor, *namespace)
	if err != nil {
		return err
	}
	campaign.Spec.Template = *template
	valueMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(campaign)
	if err != nil {
		return err
	}
	// A zero-valued struct is not omitted by the unstructured converter. Keep
	// controller-owned status out of desired-state output so render-upgrade can
	// be piped directly into validate or submit.
	delete(valueMap, "status")
	object := &unstructured.Unstructured{Object: valueMap}
	return writeResource(app.Stdout, object, *output)
}

type versionExecutor struct{ runner CommandRunner }

func (executor versionExecutor) Execute(ctx context.Context, invocation versionmatrix.Invocation) (string, string, error) {
	if executor.runner == nil {
		return "", "", errors.New("command runner is required")
	}
	result, err := executor.runner.Run(ctx, Command{Program: invocation.Program, Args: invocation.Args, Dir: invocation.Directory, Stdin: bytes.NewReader(invocation.Stdin)})
	return result.Stdout, result.Stderr, err
}

func (app *App) commandRunner() CommandRunner {
	if app.CommandRunner != nil {
		return app.CommandRunner
	}
	return ExecCommandRunner{}
}
