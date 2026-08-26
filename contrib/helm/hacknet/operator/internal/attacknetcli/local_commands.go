package attacknetcli

import (
	"context"
	"fmt"
	"time"
)

func (app *App) runImage(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet image build|load [OPTIONS]")
	}
	switch args[0] {
	case "build":
		return app.runImageBuild(ctx, args[1:])
	case "load":
		return app.runImageLoad(ctx, args[1:])
	default:
		return usageError(fmt.Sprintf("unknown image command %q", args[0]))
	}
}

func (app *App) runImageBuild(ctx context.Context, args []string) error {
	flags := newFlagSet("image build", app.Stderr)
	repositoryRoot := flags.String("repo-root", "", "Stacks Core repository root")
	buildStacks := flags.Bool("stacks", false, "also build the Stacks node image")
	docker := flags.String("docker", "docker", "Docker-compatible executable")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 0 || *repositoryRoot == "" {
		return usageError("usage: attacknet image build --repo-root PATH [--stacks]")
	}
	runner, err := app.requireCommandRunner()
	if err != nil {
		return err
	}
	result, err := (LocalImageBuilder{Runner: runner}).Build(ctx, LocalBuildOptions{
		RepositoryRoot: *repositoryRoot, BuildStacksImage: *buildStacks, DockerProgram: *docker,
	})
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, result)
}

func (app *App) runImageLoad(ctx context.Context, args []string) error {
	flags := newFlagSet("image load", app.Stderr)
	mode := flags.String("mode", string(KindImageLoadAuto), "auto, require, or disabled")
	docker := flags.String("docker", "docker", "Docker-compatible executable")
	kubectl := flags.String("kubectl", "kubectl", "kubectl executable")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() == 0 {
		return usageError("usage: attacknet image load [--mode auto|require|disabled] IMAGE [IMAGE...]")
	}
	loadMode := KindImageLoadMode(*mode)
	switch loadMode {
	case KindImageLoadAuto, KindImageLoadRequire, KindImageLoadDisabled:
	default:
		return usageError("--mode must be auto, require, or disabled")
	}
	runner, err := app.requireCommandRunner()
	if err != nil {
		return err
	}
	result, err := (KindImageLoader{Runner: runner}).Load(ctx, KindImageLoadOptions{
		Mode: loadMode, DockerProgram: *docker, KubectlProgram: *kubectl, Now: app.Now,
	}, flags.Args())
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, result)
}

func (app *App) runInstall(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "local" {
		return usageError("usage: attacknet install local --chart-dir PATH [OPTIONS]")
	}
	flags := newFlagSet("install local", app.Stderr)
	chartDir := flags.String("chart-dir", "", "Hacknet Helm chart directory")
	namespace := flags.String("namespace", "hacknet-system", "operator namespace")
	release := flags.String("release", "hacknet", "Helm release name")
	topologyImage := flags.String("topology-image", "stacks-hacknet-operator:dev", "topology operator image")
	runImage := flags.String("run-image", "stacks-hacknet-run-operator:dev", "run operator image")
	clockImage := flags.String("clock-image", "stacks-hacknet-burnchain-clock:dev", "burnchain clock image")
	probeImage := flags.String("probe-image", "stacks-hacknet-probe:dev", "trusted actor probe image")
	ioImage := flags.String("io-pressure-image", "stacks-hacknet-io-pressure:dev", "I/O pressure helper image")
	loadMode := flags.String("kind-image-load", string(KindImageLoadAuto), "auto, require, or disabled")
	injection := flags.String("chaos-injection", string(NamespaceInjectionEnabled), "enabled or disabled")
	forceCRDs := flags.Bool("force-crd-conflicts", false, "take server-side apply ownership of conflicting CRD fields")
	forceHelm := flags.Bool("force-helm-conflicts", false, "allow Helm 4 server-side conflict takeover")
	recoverFailed := flags.Bool("recover-failed-release", false, "allow upgrade of a failed Helm release")
	docker := flags.String("docker", "docker", "Docker-compatible executable")
	kubectl := flags.String("kubectl", "kubectl", "kubectl executable")
	helm := flags.String("helm", "helm", "Helm executable")
	if err := flags.Parse(args[1:]); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 0 || *chartDir == "" {
		return usageError("usage: attacknet install local --chart-dir PATH [OPTIONS]")
	}
	runner, err := app.requireCommandRunner()
	if err != nil {
		return err
	}
	result, err := (LocalInstaller{Runner: runner}).Install(ctx, LocalInstallOptions{
		ChartDir: *chartDir, Namespace: *namespace, Release: *release,
		Images:        LocalInstallImages{TopologyOperator: *topologyImage, RunOperator: *runImage, BurnchainClock: *clockImage, Probe: *probeImage, IOPressure: *ioImage},
		KindImageLoad: KindImageLoadMode(*loadMode), ChaosNamespaceInjection: NamespaceInjectionMode(*injection),
		ForceCRDConflicts: *forceCRDs, ForceHelmConflicts: *forceHelm, RecoverFailedRelease: *recoverFailed,
		DockerProgram: *docker, KubectlProgram: *kubectl, HelmProgram: *helm, Now: func() time.Time { return app.Now() },
	})
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, result)
}
