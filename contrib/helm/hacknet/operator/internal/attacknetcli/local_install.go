package attacknetcli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/imagearchive"
)

// KindImageLoadMode controls whether a non-kind cluster skips or fails local
// image loading.
type KindImageLoadMode string

const (
	// KindImageLoadAuto skips loading when the active cluster is not kind.
	KindImageLoadAuto KindImageLoadMode = "auto"
	// KindImageLoadRequire requires every current cluster node to be kind-on-Docker.
	KindImageLoadRequire KindImageLoadMode = "require"
	// KindImageLoadDisabled bypasses local image loading explicitly.
	KindImageLoadDisabled KindImageLoadMode = "disabled"
)

// NamespaceInjectionMode controls the Chaos Mesh namespace annotation.
type NamespaceInjectionMode string

const (
	// NamespaceInjectionEnabled enables Chaos Mesh injection and is the local default.
	NamespaceInjectionEnabled NamespaceInjectionMode = "enabled"
	// NamespaceInjectionDisabled leaves the namespace annotation unchanged.
	NamespaceInjectionDisabled NamespaceInjectionMode = "disabled"
)

// LocalInstallImages names the five images installed by the chart.
type LocalInstallImages struct {
	TopologyOperator string
	RunOperator      string
	BurnchainClock   string
	Probe            string
	IOPressure       string
}

// LocalInstallOptions controls one local chart installation.
type LocalInstallOptions struct {
	ChartDir                string
	Namespace               string
	Release                 string
	Images                  LocalInstallImages
	KindImageLoad           KindImageLoadMode
	ChaosNamespaceInjection NamespaceInjectionMode
	ForceCRDConflicts       bool
	ForceHelmConflicts      bool
	RecoverFailedRelease    bool
	DockerProgram           string
	KubectlProgram          string
	HelmProgram             string
	Now                     func() time.Time
}

// InstalledImage records one immutable deployment image.
type InstalledImage struct {
	Purpose       string `json:"purpose"`
	RequestedRef  string `json:"requestedRef"`
	ImmutableID   string `json:"immutableID"`
	DeploymentRef string `json:"deploymentRef"`
}

// KindNode describes one node observed during local image loading.
type KindNode struct {
	Name            string `json:"name"`
	ProviderID      string `json:"providerID"`
	OperatingSystem string `json:"operatingSystem"`
	Architecture    string `json:"architecture"`
}

// KindImageImport proves one image reference was retained by one kind node.
type KindImageImport struct {
	Node           string `json:"node"`
	RequestedRef   string `json:"requestedRef"`
	ImportedRef    string `json:"importedRef"`
	RuntimeImageID string `json:"runtimeImageID"`
	Verified       bool   `json:"verified"`
}

// KindImageLoadResult records local image-loading outcome and evidence.
type KindImageLoadResult struct {
	SchemaVersion string            `json:"schemaVersion"`
	Outcome       string            `json:"outcome"`
	Reason        string            `json:"reason,omitempty"`
	CapturedAt    string            `json:"capturedAt,omitempty"`
	Nodes         []KindNode        `json:"nodes"`
	Images        []KindImageImport `json:"images"`
}

// KindImageLoadOptions controls standalone kind image loading.
type KindImageLoadOptions struct {
	Mode               KindImageLoadMode
	DockerProgram      string
	KubectlProgram     string
	Now                func() time.Time
	ExpectedRuntimeIDs map[string]string
}

// KindImageLoader imports exact local image references into every kind node.
type KindImageLoader struct {
	Runner CommandRunner
}

// LocalInstallResult records exactly what an install admitted.
type LocalInstallResult struct {
	SchemaVersion string              `json:"schemaVersion"`
	Namespace     string              `json:"namespace"`
	Release       string              `json:"release"`
	HelmVersion   string              `json:"helmVersion"`
	Images        []InstalledImage    `json:"images"`
	KindLoad      KindImageLoadResult `json:"kindImageLoad"`
}

// LocalInstaller applies CRDs explicitly and performs an atomic Helm install.
type LocalInstaller struct {
	Runner CommandRunner
}

type installImage struct {
	purpose string
	ref     string
	id      string
	repo    string
	tag     string
	deploy  string
}

var helmMajorPattern = regexp.MustCompile(`^v?([0-9]+)\.`)

// Install installs the local chart without force-conflict ownership takeover
// unless each force option is explicitly enabled.
func (installer LocalInstaller) Install(ctx context.Context, options LocalInstallOptions) (LocalInstallResult, error) {
	if installer.Runner == nil {
		return LocalInstallResult{}, fmt.Errorf("command runner is required")
	}
	if options.ChartDir == "" {
		return LocalInstallResult{}, fmt.Errorf("chart directory is required")
	}
	applyInstallDefaults(&options)
	if err := validateInstallOptions(options); err != nil {
		return LocalInstallResult{}, err
	}
	helmVersionResult, err := installer.Runner.Run(ctx, Command{Program: options.HelmProgram, Args: []string{"version", "--template", "{{.Version}}"}})
	if err != nil {
		return LocalInstallResult{}, fmt.Errorf("determine Helm version: %w", err)
	}
	helmVersion := strings.TrimSpace(helmVersionResult.Stdout)
	failureArg, err := helmFailureArgument(helmVersion)
	if err != nil {
		return LocalInstallResult{}, err
	}
	if options.ForceHelmConflicts && helmMajor(helmVersion) != "4" {
		return LocalInstallResult{}, fmt.Errorf("Helm --force-conflicts requires Helm 4; detected %q", helmVersion)
	}
	if err := installer.rejectFailedRelease(ctx, options); err != nil {
		return LocalInstallResult{}, err
	}
	if err := installer.requireChaosMeshAPIs(ctx, options); err != nil {
		return LocalInstallResult{}, err
	}
	images, err := installer.resolveImages(ctx, options)
	if err != nil {
		return LocalInstallResult{}, err
	}
	load := KindImageLoadResult{SchemaVersion: "stacks-attacknet-kind-image-load/v1", Outcome: "Disabled", Nodes: []KindNode{}, Images: []KindImageImport{}}
	if options.KindImageLoad != KindImageLoadDisabled {
		refs := make([]string, len(images))
		for index := range images {
			refs[index] = images[index].deploy
		}
		load, err = (KindImageLoader{Runner: installer.Runner}).Load(ctx, KindImageLoadOptions{
			Mode: options.KindImageLoad, DockerProgram: options.DockerProgram,
			KubectlProgram: options.KubectlProgram, Now: options.Now,
		}, refs)
		if err != nil {
			return LocalInstallResult{}, err
		}
	}
	if err := installer.ensureNamespace(ctx, options); err != nil {
		return LocalInstallResult{}, err
	}
	if err := installer.applyCRDs(ctx, options); err != nil {
		return LocalInstallResult{}, err
	}
	if err := installer.installHelm(ctx, options, images, failureArg); err != nil {
		return LocalInstallResult{}, err
	}
	result := LocalInstallResult{SchemaVersion: "stacks-attacknet-local-install/v1", Namespace: options.Namespace, Release: options.Release, HelmVersion: helmVersion, KindLoad: load}
	for _, image := range images {
		result.Images = append(result.Images, InstalledImage{Purpose: image.purpose, RequestedRef: image.ref, ImmutableID: image.id, DeploymentRef: image.deploy})
	}
	return result, nil
}

func helmFailureArgument(version string) (string, error) {
	major := helmMajor(version)
	if major == "" {
		return "", fmt.Errorf("unsupported Helm version %q; expected major 3 or 4", version)
	}
	switch major {
	case "3":
		return "--atomic", nil
	case "4":
		return "--rollback-on-failure", nil
	default:
		return "", fmt.Errorf("unsupported Helm version %q; expected major 3 or 4", version)
	}
}

func helmMajor(version string) string {
	match := helmMajorPattern.FindStringSubmatch(version)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func applyInstallDefaults(options *LocalInstallOptions) {
	if options.Namespace == "" {
		options.Namespace = "hacknet-system"
	}
	if options.Release == "" {
		options.Release = "hacknet"
	}
	if options.Images.TopologyOperator == "" {
		options.Images.TopologyOperator = "stacks-hacknet-operator:dev"
	}
	if options.Images.RunOperator == "" {
		options.Images.RunOperator = "stacks-hacknet-run-operator:dev"
	}
	if options.Images.BurnchainClock == "" {
		options.Images.BurnchainClock = "stacks-hacknet-burnchain-clock:dev"
	}
	if options.Images.IOPressure == "" {
		options.Images.IOPressure = "stacks-hacknet-io-pressure:dev"
	}
	if options.Images.Probe == "" {
		options.Images.Probe = "stacks-hacknet-probe:dev"
	}
	if options.KindImageLoad == "" {
		options.KindImageLoad = KindImageLoadAuto
	}
	if options.ChaosNamespaceInjection == "" {
		options.ChaosNamespaceInjection = NamespaceInjectionEnabled
	}
	if options.DockerProgram == "" {
		options.DockerProgram = "docker"
	}
	if options.KubectlProgram == "" {
		options.KubectlProgram = "kubectl"
	}
	if options.HelmProgram == "" {
		options.HelmProgram = "helm"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
}

func validateInstallOptions(options LocalInstallOptions) error {
	switch options.KindImageLoad {
	case KindImageLoadAuto, KindImageLoadRequire, KindImageLoadDisabled:
	default:
		return fmt.Errorf("kind image load mode must be auto, require, or disabled")
	}
	switch options.ChaosNamespaceInjection {
	case NamespaceInjectionEnabled, NamespaceInjectionDisabled:
	default:
		return fmt.Errorf("Chaos namespace injection must be enabled or disabled")
	}
	return nil
}

func (installer LocalInstaller) resolveImages(ctx context.Context, options LocalInstallOptions) ([]installImage, error) {
	inputs := []struct{ purpose, ref string }{
		{"topology-operator", options.Images.TopologyOperator}, {"run-operator", options.Images.RunOperator},
		{"burnchain-clock", options.Images.BurnchainClock}, {"io-pressure", options.Images.IOPressure},
		{"probe", options.Images.Probe},
	}
	images := make([]installImage, 0, len(inputs))
	for _, input := range inputs {
		id, err := inspectImageID(ctx, installer.Runner, options.DockerProgram, input.ref)
		if err != nil {
			return nil, err
		}
		repo, tag, deploy, err := immutableLocalRef(input.ref, id)
		if err != nil {
			return nil, err
		}
		if _, err := installer.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{"image", "tag", input.ref, deploy}}); err != nil {
			return nil, fmt.Errorf("tag immutable %s image: %w", input.purpose, err)
		}
		images = append(images, installImage{purpose: input.purpose, ref: input.ref, id: id, repo: repo, tag: tag, deploy: deploy})
	}
	return images, nil
}

func (installer LocalInstaller) rejectFailedRelease(ctx context.Context, options LocalInstallOptions) error {
	result, err := installer.Runner.Run(ctx, Command{Program: options.HelmProgram, Args: []string{"status", options.Release, "-n", options.Namespace, "-o", "json"}})
	if err != nil {
		message := strings.ToLower(result.Stdout + "\n" + result.Stderr)
		if strings.Contains(message, "release:") && strings.Contains(message, "not found") {
			return nil
		}
		return fmt.Errorf("inspect Helm release %s/%s: %w", options.Namespace, options.Release, err)
	}
	var status struct {
		Info struct {
			Status string `json:"status"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &status); err != nil {
		return fmt.Errorf("decode Helm release status: %w", err)
	}
	if status.Info.Status == "failed" && !options.RecoverFailedRelease {
		return fmt.Errorf("Helm release %s/%s is failed; inspect it or explicitly enable recovery", options.Namespace, options.Release)
	}
	return nil
}

func (installer LocalInstaller) ensureNamespace(ctx context.Context, options LocalInstallOptions) error {
	_, err := installer.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: []string{"get", "namespace", options.Namespace}})
	if err != nil {
		if _, createErr := installer.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: []string{"create", "namespace", options.Namespace}}); createErr != nil {
			return fmt.Errorf("create namespace %s: %w", options.Namespace, createErr)
		}
	}
	if options.ChaosNamespaceInjection == NamespaceInjectionEnabled {
		if _, err := installer.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: []string{"annotate", "namespace", options.Namespace, "chaos-mesh.org/inject=enabled", "--overwrite"}}); err != nil {
			return fmt.Errorf("enable Chaos Mesh namespace injection: %w", err)
		}
	}
	return nil
}

func (installer LocalInstaller) applyCRDs(ctx context.Context, options LocalInstallOptions) error {
	crds := []string{
		"testing.stacks.org_stacksnetworks.yaml",
		"testing.stacks.org_burnchainpolicies.yaml",
		"testing.stacks.org_faultcampaigns.yaml",
		"testing.stacks.org_attacknetruns.yaml",
		"testing.stacks.org_upgradecampaigns.yaml",
	}
	for _, crd := range crds {
		args := []string{"apply", "--server-side", "--field-manager=hacknet-local-installer"}
		if options.ForceCRDConflicts {
			args = append(args, "--force-conflicts")
		}
		args = append(args, "-f", filepath.Join(options.ChartDir, "crds", crd))
		if _, err := installer.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: args}); err != nil {
			return fmt.Errorf("apply CRD %s: %w", crd, err)
		}
	}
	args := []string{
		"wait", "--for=condition=Established", "--timeout=60s",
		"crd/stacksnetworks.testing.stacks.org",
		"crd/burnchainpolicies.testing.stacks.org",
		"crd/faultcampaigns.testing.stacks.org",
		"crd/attacknetruns.testing.stacks.org",
		"crd/upgradecampaigns.testing.stacks.org",
	}
	if _, err := installer.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: args}); err != nil {
		return fmt.Errorf("wait for Attacknet CRDs: %w", err)
	}
	return nil
}

func (installer LocalInstaller) requireChaosMeshAPIs(ctx context.Context, options LocalInstallOptions) error {
	for _, crd := range []string{
		"podchaos.chaos-mesh.org",
		"networkchaos.chaos-mesh.org",
		"dnschaos.chaos-mesh.org",
		"iochaos.chaos-mesh.org",
		"timechaos.chaos-mesh.org",
	} {
		if _, err := installer.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: []string{"get", "crd", crd}}); err != nil {
			return fmt.Errorf("required Chaos Mesh CRD %s is unavailable; install pinned Chaos Mesh before Attacknet: %w", crd, err)
		}
	}
	return nil
}

func (installer LocalInstaller) installHelm(ctx context.Context, options LocalInstallOptions, images []installImage, failureArg string) error {
	byPurpose := map[string]installImage{}
	for _, image := range images {
		byPurpose[image.purpose] = image
	}
	args := []string{"upgrade", "--install", options.Release, options.ChartDir, "--namespace", options.Namespace, "--create-namespace", "--wait", failureArg,
		"--set-string", "operator.podAnnotations.attacknet-build=" + byPurpose["topology-operator"].id,
		"--set-string", "runOperator.podAnnotations.attacknet-build=" + byPurpose["run-operator"].id,
		"--set-string", "operator.image.repository=" + byPurpose["topology-operator"].repo,
		"--set-string", "operator.image.tag=" + byPurpose["topology-operator"].tag,
		"--set-string", "runOperator.image.repository=" + byPurpose["run-operator"].repo,
		"--set-string", "runOperator.image.tag=" + byPurpose["run-operator"].tag,
		"--set-string", "burnchainClock.image.repository=" + byPurpose["burnchain-clock"].repo,
		"--set-string", "burnchainClock.image.tag=" + byPurpose["burnchain-clock"].tag,
		"--set-string", "probe.image.repository=" + byPurpose["probe"].repo,
		"--set-string", "probe.image.tag=" + byPurpose["probe"].tag,
		"--set-string", "runOperator.ioPressureImage.repository=" + byPurpose["io-pressure"].repo,
		"--set-string", "runOperator.ioPressureImage.tag=" + byPurpose["io-pressure"].tag,
	}
	if options.ForceHelmConflicts {
		args = append(args, "--force-conflicts")
	}
	if _, err := installer.Runner.Run(ctx, Command{Program: options.HelmProgram, Args: args}); err != nil {
		return fmt.Errorf("install Helm release: %w", err)
	}
	return nil
}

type nodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			ProviderID string `json:"providerID"`
		} `json:"spec"`
		Status struct {
			NodeInfo struct {
				OperatingSystem string `json:"operatingSystem"`
				Architecture    string `json:"architecture"`
			} `json:"nodeInfo"`
		} `json:"status"`
	} `json:"items"`
}

type criImageInspect struct {
	Status struct {
		ID string `json:"id"`
	} `json:"status"`
}

// Load imports images for the current kind cluster and returns verification
// evidence. Auto mode returns a structured skipped receipt for non-kind clusters.
func (loader KindImageLoader) Load(ctx context.Context, options KindImageLoadOptions, refs []string) (KindImageLoadResult, error) {
	if loader.Runner == nil {
		return KindImageLoadResult{}, fmt.Errorf("command runner is required")
	}
	if len(refs) == 0 {
		return KindImageLoadResult{}, fmt.Errorf("at least one image is required")
	}
	if options.Mode == "" {
		options.Mode = KindImageLoadAuto
	}
	if options.Mode != KindImageLoadAuto && options.Mode != KindImageLoadRequire {
		return KindImageLoadResult{}, fmt.Errorf("kind image loader mode must be auto or require")
	}
	if options.DockerProgram == "" {
		options.DockerProgram = "docker"
	}
	if options.KubectlProgram == "" {
		options.KubectlProgram = "kubectl"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	result, err := loader.Runner.Run(ctx, Command{Program: options.KubectlProgram, Args: []string{"get", "nodes", "-o", "json"}})
	if err != nil {
		return KindImageLoadResult{}, fmt.Errorf("list Kubernetes nodes: %w", err)
	}
	var list nodeList
	if err := json.Unmarshal([]byte(result.Stdout), &list); err != nil {
		return KindImageLoadResult{}, fmt.Errorf("decode Kubernetes nodes: %w", err)
	}
	if len(list.Items) == 0 {
		return KindImageLoadResult{}, fmt.Errorf("current cluster has no nodes")
	}
	platform := ""
	allKind := true
	receipt := KindImageLoadResult{SchemaVersion: "stacks-attacknet-kind-image-load/v1", Nodes: []KindNode{}, Images: []KindImageImport{}}
	for _, item := range list.Items {
		node := KindNode{Name: item.Metadata.Name, ProviderID: item.Spec.ProviderID, OperatingSystem: item.Status.NodeInfo.OperatingSystem, Architecture: item.Status.NodeInfo.Architecture}
		receipt.Nodes = append(receipt.Nodes, node)
		if !isKindDockerProvider(item.Spec.ProviderID, item.Metadata.Name) {
			allKind = false
		}
		if node.OperatingSystem == "" || node.Architecture == "" {
			return KindImageLoadResult{}, fmt.Errorf("node %s did not report operating system and architecture", node.Name)
		}
		candidate := node.OperatingSystem + "/" + node.Architecture
		if platform != "" && platform != candidate {
			return KindImageLoadResult{}, fmt.Errorf("kind image loading requires one node platform; found %s and %s", platform, candidate)
		}
		platform = candidate
	}
	if !allKind {
		if options.Mode == KindImageLoadRequire {
			return KindImageLoadResult{}, fmt.Errorf("current cluster is not entirely kind-on-Docker")
		}
		receipt.Outcome = "Skipped"
		receipt.Reason = "cluster is not entirely kind-on-Docker"
		return receipt, nil
	}
	sort.Slice(receipt.Nodes, func(i, j int) bool { return receipt.Nodes[i].Name < receipt.Nodes[j].Name })
	temporary, err := os.CreateTemp("", "attacknet-kind-images-*.tar")
	if err != nil {
		return KindImageLoadResult{}, fmt.Errorf("create image archive: %w", err)
	}
	archive := temporary.Name()
	if err := temporary.Close(); err != nil {
		return KindImageLoadResult{}, fmt.Errorf("close image archive: %w", err)
	}
	defer os.Remove(archive)
	archiveRefs, aliases, err := loader.archiveReferences(ctx, options.DockerProgram, refs)
	if err != nil {
		return KindImageLoadResult{}, err
	}
	args := []string{"save", "--platform", platform, "--output", archive}
	args = append(args, archiveRefs...)
	_, saveErr := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: args})
	cleanupErr := loader.removeHostAliases(ctx, options.DockerProgram, aliases)
	if saveErr != nil {
		return KindImageLoadResult{}, fmt.Errorf("export local images: %w", saveErr)
	}
	if cleanupErr != nil {
		return KindImageLoadResult{}, cleanupErr
	}
	archiveExpected := make(map[string]string, len(archiveRefs))
	for _, ref := range refs {
		archiveExpected[archiveReference(ref, aliases)] = options.ExpectedRuntimeIDs[ref]
	}
	archiveIDs, err := imagearchive.PlatformConfigIDs(archive, archiveRefs, archiveExpected)
	if err != nil {
		return KindImageLoadResult{}, err
	}
	runtimeIDs := make(map[string]string, len(refs))
	for _, ref := range refs {
		runtimeIDs[ref] = archiveIDs[archiveReference(ref, aliases)]
	}
	for _, node := range receipt.Nodes {
		if _, err := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{"container", "inspect", node.Name}}); err != nil {
			return KindImageLoadResult{}, fmt.Errorf("inspect kind node container %s: %w", node.Name, err)
		}
		retained, err := loader.kindImageNames(ctx, options.DockerProgram, node.Name)
		if err != nil {
			return KindImageLoadResult{}, err
		}
		// containerd does not replace an existing named image during import.
		// Remove only the requested tags first so a successful import cannot be
		// mistaken for an update while kubelet continues selecting stale bytes.
		for _, ref := range append(append([]string(nil), refs...), aliasReferences(aliases)...) {
			normalized := imagearchive.NormalizeReference(ref)
			if !retained[normalized] {
				continue
			}
			if _, err := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{
				"exec", node.Name, "ctr", "-n", "k8s.io", "images", "rm", normalized,
			}}); err != nil {
				return KindImageLoadResult{}, fmt.Errorf("remove stale image tag %s from kind node %s: %w", normalized, node.Name, err)
			}
		}
		file, err := os.Open(archive)
		if err != nil {
			return KindImageLoadResult{}, fmt.Errorf("open image archive: %w", err)
		}
		_, importErr := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{"exec", "-i", node.Name, "ctr", "-n", "k8s.io", "images", "import", "-"}, Stdin: file})
		closeErr := file.Close()
		if importErr != nil {
			return KindImageLoadResult{}, fmt.Errorf("import images into kind node %s: %w", node.Name, importErr)
		}
		if closeErr != nil {
			return KindImageLoadResult{}, fmt.Errorf("close image archive: %w", closeErr)
		}
		retained, err = loader.kindImageNames(ctx, options.DockerProgram, node.Name)
		if err != nil {
			return KindImageLoadResult{}, err
		}
		for _, ref := range refs {
			normalized := imagearchive.NormalizeReference(ref)
			if alias := archiveReference(ref, aliases); alias != ref && retained[imagearchive.NormalizeReference(alias)] {
				if _, err := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{
					"exec", node.Name, "ctr", "-n", "k8s.io", "images", "tag", imagearchive.NormalizeReference(alias), normalized,
				}}); err != nil {
					return KindImageLoadResult{}, fmt.Errorf("tag digest-only image %s on kind node %s: %w", normalized, node.Name, err)
				}
				retained, err = loader.kindImageNames(ctx, options.DockerProgram, node.Name)
				if err != nil {
					return KindImageLoadResult{}, err
				}
			}
			if !retained[normalized] {
				return KindImageLoadResult{}, fmt.Errorf("kind node %s did not retain %s", node.Name, normalized)
			}
			inspected, err := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{
				"exec", node.Name, "crictl", "inspecti", normalized,
			}})
			if err != nil {
				return KindImageLoadResult{}, fmt.Errorf("inspect imported image %s on kind node %s: %w", normalized, node.Name, err)
			}
			var image criImageInspect
			if err := json.Unmarshal([]byte(inspected.Stdout), &image); err != nil {
				return KindImageLoadResult{}, fmt.Errorf("decode imported image %s on kind node %s: %w", normalized, node.Name, err)
			}
			if image.Status.ID != runtimeIDs[ref] {
				return KindImageLoadResult{}, fmt.Errorf(
					"kind node %s retained stale bytes for %s: CRI image ID %s, expected %s",
					node.Name, normalized, image.Status.ID, runtimeIDs[ref],
				)
			}
			receipt.Images = append(receipt.Images, KindImageImport{Node: node.Name, RequestedRef: ref, ImportedRef: normalized, RuntimeImageID: runtimeIDs[ref], Verified: true})
		}
		for _, alias := range aliasReferences(aliases) {
			if _, err := loader.Runner.Run(ctx, Command{Program: options.DockerProgram, Args: []string{
				"exec", node.Name, "ctr", "-n", "k8s.io", "images", "rm", imagearchive.NormalizeReference(alias),
			}}); err != nil {
				return KindImageLoadResult{}, fmt.Errorf("remove temporary image alias on kind node %s: %w", node.Name, err)
			}
		}
	}
	receipt.Outcome = "Loaded"
	receipt.CapturedAt = options.Now().UTC().Format(time.RFC3339Nano)
	return receipt, nil
}

type imageAlias struct {
	Original  string
	Temporary string
}

func (loader KindImageLoader) archiveReferences(ctx context.Context, docker string, refs []string) ([]string, []imageAlias, error) {
	archiveRefs := make([]string, 0, len(refs))
	aliases := make([]imageAlias, 0)
	for _, ref := range refs {
		if !strings.Contains(ref, "@sha256:") {
			archiveRefs = append(archiveRefs, ref)
			continue
		}
		hash := sha256.Sum256([]byte(ref))
		alias := fmt.Sprintf("attacknet-kind-import:%x", hash[:8])
		if _, err := loader.Runner.Run(ctx, Command{Program: docker, Args: []string{"tag", ref, alias}}); err != nil {
			_ = loader.removeHostAliases(ctx, docker, aliases)
			return nil, nil, fmt.Errorf("create temporary image alias for %s: %w", ref, err)
		}
		aliases = append(aliases, imageAlias{Original: ref, Temporary: alias})
		archiveRefs = append(archiveRefs, alias)
	}
	return archiveRefs, aliases, nil
}

func (loader KindImageLoader) removeHostAliases(ctx context.Context, docker string, aliases []imageAlias) error {
	for _, alias := range aliases {
		if _, err := loader.Runner.Run(ctx, Command{Program: docker, Args: []string{"image", "rm", alias.Temporary}}); err != nil {
			return fmt.Errorf("remove temporary host image alias %s: %w", alias.Temporary, err)
		}
	}
	return nil
}

func archiveReference(ref string, aliases []imageAlias) string {
	for _, alias := range aliases {
		if alias.Original == ref {
			return alias.Temporary
		}
	}
	return ref
}

func aliasReferences(aliases []imageAlias) []string {
	refs := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		refs = append(refs, alias.Temporary)
	}
	return refs
}

func (loader KindImageLoader) kindImageNames(ctx context.Context, docker, node string) (map[string]bool, error) {
	listed, err := loader.Runner.Run(ctx, Command{Program: docker, Args: []string{
		"exec", node, "ctr", "-n", "k8s.io", "images", "ls", "-q",
	}})
	if err != nil {
		return nil, fmt.Errorf("list images on kind node %s: %w", node, err)
	}
	retained := map[string]bool{}
	for _, line := range strings.Split(listed.Stdout, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			retained[name] = true
		}
	}
	return retained, nil
}

func isKindDockerProvider(providerID, node string) bool {
	return strings.HasPrefix(providerID, "kind://docker/") && strings.HasSuffix(providerID, "/"+node)
}
