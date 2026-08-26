package attacknetcli

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordingRunner struct {
	commands []Command
	run      func(Command) (CommandResult, error)
}

func (runner *recordingRunner) Run(_ context.Context, command Command) (CommandResult, error) {
	copyCommand := command
	copyCommand.Args = append([]string(nil), command.Args...)
	runner.commands = append(runner.commands, copyCommand)
	if runner.run == nil {
		return CommandResult{}, nil
	}
	return runner.run(command)
}

func TestLocalImageBuilderUsesExactDockerArguments(t *testing.T) {
	t.Parallel()
	const imageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		if reflect.DeepEqual(command.Args[:2], []string{"image", "inspect"}) {
			return CommandResult{Stdout: imageID + "\n"}, nil
		}
		return CommandResult{}, nil
	}}
	builder := LocalImageBuilder{Runner: runner}
	result, err := builder.Build(context.Background(), LocalBuildOptions{RepositoryRoot: "/repo", BuildStacksImage: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Images) != 7 {
		t.Fatalf("got %d built images, want 7", len(result.Images))
	}
	wantFirst := Command{Program: "docker", Args: []string{"build", "--build-arg", "BINARY=topology-operator", "--tag", "stacks-hacknet-operator:dev", "/repo/contrib/helm/hacknet/operator"}}
	assertCommand(t, runner.commands[0], wantFirst)
	wantIOPressure := []string{"build", "--tag", "stacks-hacknet-io-pressure:dev", "--file", "/repo/contrib/attacknet/images/io-pressure/Dockerfile", "/repo"}
	if !reflect.DeepEqual(runner.commands[8].Args, wantIOPressure) {
		t.Fatalf("I/O-pressure build args = %#v, want %#v", runner.commands[8].Args, wantIOPressure)
	}
	wantStacks := []string{"build", "--tag", "stacks-core-attacknet:main", "--file", "/repo/contrib/attacknet/images/cli/Dockerfile", "/repo"}
	if !reflect.DeepEqual(runner.commands[12].Args, wantStacks) {
		t.Fatalf("Stacks build args = %#v, want %#v", runner.commands[12].Args, wantStacks)
	}
}

func TestLocalInstallerPreservesSafetyCriticalOrdering(t *testing.T) {
	t.Parallel()
	const imageID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		switch {
		case command.Program == "helm" && reflect.DeepEqual(command.Args, []string{"version", "--template", "{{.Version}}"}):
			return CommandResult{Stdout: "v3.19.0\n"}, nil
		case command.Program == "docker" && len(command.Args) >= 2 && command.Args[0] == "image" && command.Args[1] == "inspect":
			return CommandResult{Stdout: imageID + "\n"}, nil
		case command.Program == "helm" && len(command.Args) > 0 && command.Args[0] == "status":
			return CommandResult{Stderr: "Error: release: not found"}, errors.New("exit 1")
		default:
			return CommandResult{}, nil
		}
	}}
	installer := LocalInstaller{Runner: runner}
	result, err := installer.Install(context.Background(), LocalInstallOptions{
		ChartDir: "/repo/contrib/helm/hacknet", Namespace: "attacknet", Release: "attacknet",
		KindImageLoad: KindImageLoadDisabled, ChaosNamespaceInjection: NamespaceInjectionEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Images) != 5 || result.KindLoad.Outcome != "Disabled" {
		t.Fatalf("unexpected result: %#v", result)
	}
	assertBefore(t, runner.commands, "docker image tag", "kubectl apply")
	assertBefore(t, runner.commands, "kubectl wait", "helm upgrade")
	helm := findCommand(t, runner.commands, "helm", "upgrade")
	joined := strings.Join(helm.Args, " ")
	for _, required := range []string{"--atomic", "--wait", "operator.image.tag=local-0123456789abcdef", "runOperator.ioPressureImage.tag=local-0123456789abcdef", "probe.image.tag=local-0123456789abcdef"} {
		if !strings.Contains(joined, required) {
			t.Errorf("Helm args do not contain %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--force", "--force-conflicts"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("Helm args unexpectedly contain %q: %s", forbidden, joined)
		}
	}
	for _, command := range runner.commands {
		if command.Program == "kubectl" && len(command.Args) > 0 && command.Args[0] == "apply" && contains(command.Args, "--force-conflicts") {
			t.Fatalf("CRD apply unexpectedly forced conflicts: %#v", command.Args)
		}
	}
}

func TestLocalInstallerRejectsFailedReleaseBeforeClusterMutation(t *testing.T) {
	t.Parallel()
	const imageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		if command.Program == "helm" && command.Args[0] == "version" {
			return CommandResult{Stdout: "v4.0.0"}, nil
		}
		if command.Program == "docker" && len(command.Args) > 1 && command.Args[1] == "inspect" {
			return CommandResult{Stdout: imageID}, nil
		}
		if command.Program == "helm" && command.Args[0] == "status" {
			return CommandResult{Stdout: `{"info":{"status":"failed"}}`}, nil
		}
		return CommandResult{}, nil
	}}
	_, err := (LocalInstaller{Runner: runner}).Install(context.Background(), LocalInstallOptions{ChartDir: "/chart", KindImageLoad: KindImageLoadDisabled})
	if err == nil || !strings.Contains(err.Error(), "explicitly enable recovery") {
		t.Fatalf("got %v, want failed-release guard", err)
	}
	for _, command := range runner.commands {
		if command.Program == "kubectl" || (command.Program == "helm" && command.Args[0] == "upgrade") {
			t.Fatalf("cluster mutated after failed-release guard: %#v", command)
		}
	}
}

func TestLocalInstallerFailsClosedWhenHelmStatusIsUnavailable(t *testing.T) {
	t.Parallel()
	const imageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		switch {
		case command.Program == "helm" && command.Args[0] == "version":
			return CommandResult{Stdout: "v4.0.0"}, nil
		case command.Program == "docker" && len(command.Args) > 1 && command.Args[1] == "inspect":
			return CommandResult{Stdout: imageID}, nil
		case command.Program == "helm" && command.Args[0] == "status":
			return CommandResult{Stderr: "Kubernetes cluster unreachable"}, errors.New("exit 1")
		default:
			return CommandResult{}, nil
		}
	}}
	_, err := (LocalInstaller{Runner: runner}).Install(context.Background(), LocalInstallOptions{ChartDir: "/chart", KindImageLoad: KindImageLoadDisabled})
	if err == nil || !strings.Contains(err.Error(), "inspect Helm release") {
		t.Fatalf("got %v, want status lookup failure", err)
	}
	for _, command := range runner.commands {
		if command.Program == "kubectl" || (command.Program == "helm" && command.Args[0] == "upgrade") {
			t.Fatalf("cluster mutated after status lookup failure: %#v", command)
		}
	}
}

func TestLocalInstallerRejectsHelmThreeForceConflictsBeforeImageMutation(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		if command.Program == "helm" && command.Args[0] == "version" {
			return CommandResult{Stdout: "v3.19.0"}, nil
		}
		return CommandResult{}, nil
	}}
	_, err := (LocalInstaller{Runner: runner}).Install(context.Background(), LocalInstallOptions{
		ChartDir: "/chart", KindImageLoad: KindImageLoadDisabled, ForceHelmConflicts: true,
	})
	if err == nil || !strings.Contains(err.Error(), "requires Helm 4") {
		t.Fatalf("got %v, want Helm 4 requirement", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("got %d commands, want only Helm version discovery", len(runner.commands))
	}
}

func TestHelmFailureArgumentMatchesSupportedMajor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version string
		want    string
		ok      bool
	}{
		{version: "v3.19.0", want: "--atomic", ok: true},
		{version: "v4.0.0", want: "--rollback-on-failure", ok: true},
		{version: "v2.17.0", ok: false},
		{version: "development", ok: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			got, err := helmFailureArgument(test.version)
			if (err == nil) != test.ok || got != test.want {
				t.Fatalf("helmFailureArgument(%q) = %q, %v; want %q, ok=%t", test.version, got, err, test.want, test.ok)
			}
		})
	}
}

func TestKindImageLoaderAutoSkipsNonKindCluster(t *testing.T) {
	t.Parallel()
	nodes := `{"items":[{"metadata":{"name":"node-a"},"spec":{"providerID":"docker-desktop://node-a"},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64"}}}]}`
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		if command.Program == "kubectl" {
			return CommandResult{Stdout: nodes}, nil
		}
		return CommandResult{}, errors.New("Docker must not run")
	}}
	result, err := (KindImageLoader{Runner: runner}).Load(context.Background(), KindImageLoadOptions{
		Mode: KindImageLoadAuto, DockerProgram: "docker", KubectlProgram: "kubectl", Now: time.Now,
	}, []string{"example:local"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "Skipped" || result.Reason == "" {
		t.Fatalf("unexpected receipt: %#v", result)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("got %d commands, want only Kubernetes discovery", len(runner.commands))
	}
}

func TestKindImageLoaderRequiresUniformKindCluster(t *testing.T) {
	t.Parallel()
	nodes := `{"items":[{"metadata":{"name":"node-a"},"spec":{"providerID":"other://node-a"},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64"}}}]}`
	runner := &recordingRunner{run: func(Command) (CommandResult, error) { return CommandResult{Stdout: nodes}, nil }}
	_, err := (KindImageLoader{Runner: runner}).Load(context.Background(), KindImageLoadOptions{
		Mode: KindImageLoadRequire, DockerProgram: "docker", KubectlProgram: "kubectl", Now: time.Now,
	}, []string{"example:local"})
	if err == nil || !strings.Contains(err.Error(), "not entirely kind-on-Docker") {
		t.Fatalf("got %v, want kind requirement failure", err)
	}
}

func TestKindImageLoaderImportsAndVerifiesEveryNode(t *testing.T) {
	t.Parallel()
	const imageID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nodes := `{"items":[` +
		`{"metadata":{"name":"cluster-worker"},"spec":{"providerID":"kind://docker/cluster/cluster-worker"},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64"}}},` +
		`{"metadata":{"name":"cluster-control-plane"},"spec":{"providerID":"kind://docker/cluster/cluster-control-plane"},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64"}}}` +
		`]}`
	imports := 0
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		switch {
		case command.Program == "kubectl":
			return CommandResult{Stdout: nodes}, nil
		case command.Program == "docker" && len(command.Args) > 0 && command.Args[0] == "save":
			writeTestImageArchive(t, optionValue(command.Args, "--output"), "example:local", imageID)
			return CommandResult{}, nil
		case command.Program == "docker" && len(command.Args) >= 7 && command.Args[0] == "exec" && command.Args[len(command.Args)-2] == "ls":
			return CommandResult{Stdout: "docker.io/library/example:local\n"}, nil
		case command.Program == "docker" && contains(command.Args, "import"):
			imports++
			return CommandResult{}, nil
		case command.Program == "docker" && contains(command.Args, "inspecti"):
			return CommandResult{Stdout: `{"status":{"id":"` + imageID + `"}}`}, nil
		default:
			return CommandResult{}, nil
		}
	}}
	fixedTime := time.Date(2026, time.August, 26, 5, 0, 0, 0, time.UTC)
	receipt, err := (KindImageLoader{Runner: runner}).Load(context.Background(), KindImageLoadOptions{
		Mode: KindImageLoadRequire, DockerProgram: "docker", KubectlProgram: "kubectl", Now: func() time.Time { return fixedTime },
	}, []string{"example:local"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != "Loaded" || len(receipt.Images) != 2 || receipt.CapturedAt != fixedTime.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	if receipt.Nodes[0].Name != "cluster-control-plane" {
		t.Fatalf("nodes are not deterministically ordered: %#v", receipt.Nodes)
	}
	removals := 0
	for _, command := range runner.commands {
		if command.Program == "docker" && contains(command.Args, "import") {
			if command.Stdin == nil {
				t.Fatal("kind import did not stream the image archive on stdin")
			}
		}
		if command.Program == "docker" && contains(command.Args, "rm") {
			removals++
		}
	}
	if imports != 2 {
		t.Fatalf("got %d imports, want one per node", imports)
	}
	if removals != 2 {
		t.Fatalf("got %d stale-tag removals, want one per node", removals)
	}
}

func TestKindImageLoaderRejectsStaleCRIImageIdentity(t *testing.T) {
	t.Parallel()
	const expectedID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const staleID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nodes := `{"items":[{"metadata":{"name":"cluster-worker"},"spec":{"providerID":"kind://docker/cluster/cluster-worker"},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64"}}}]}`
	runner := &recordingRunner{run: func(command Command) (CommandResult, error) {
		switch {
		case command.Program == "kubectl":
			return CommandResult{Stdout: nodes}, nil
		case command.Program == "docker" && len(command.Args) > 0 && command.Args[0] == "save":
			writeTestImageArchive(t, optionValue(command.Args, "--output"), "example:local", expectedID)
			return CommandResult{}, nil
		case command.Program == "docker" && len(command.Args) >= 7 && command.Args[0] == "exec" && command.Args[len(command.Args)-2] == "ls":
			return CommandResult{Stdout: "docker.io/library/example:local\n"}, nil
		case command.Program == "docker" && contains(command.Args, "inspecti"):
			return CommandResult{Stdout: `{"status":{"id":"` + staleID + `"}}`}, nil
		default:
			return CommandResult{}, nil
		}
	}}
	_, err := (KindImageLoader{Runner: runner}).Load(context.Background(), KindImageLoadOptions{
		Mode: KindImageLoadRequire, DockerProgram: "docker", KubectlProgram: "kubectl",
	}, []string{"example:local"})
	if err == nil || !strings.Contains(err.Error(), "retained stale bytes") {
		t.Fatalf("got %v, want stale CRI image rejection", err)
	}
}

func optionValue(arguments []string, option string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == option {
			return arguments[index+1]
		}
	}
	return ""
}

func writeTestImageArchive(t *testing.T, target, ref, imageID string) {
	t.Helper()
	file, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	manifest, err := json.Marshal([]dockerArchiveManifestEntry{{
		Config: "blobs/sha256/" + strings.TrimPrefix(imageID, "sha256:"), RepoTags: []string{ref},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExecCommandRunnerHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (ExecCommandRunner{}).Run(ctx, Command{Program: "true", Stdin: io.Reader(nil)})
	if err == nil {
		t.Fatal("cancelled command unexpectedly succeeded")
	}
}

func assertCommand(t *testing.T, got, want Command) {
	t.Helper()
	if got.Program != want.Program || !reflect.DeepEqual(got.Args, want.Args) {
		t.Fatalf("command = %s %#v, want %s %#v", got.Program, got.Args, want.Program, want.Args)
	}
}

func commandLabel(command Command) string {
	return strings.Join(append([]string{command.Program}, command.Args...), " ")
}

func assertBefore(t *testing.T, commands []Command, first, second string) {
	t.Helper()
	firstIndex, secondIndex := -1, -1
	for index, command := range commands {
		label := commandLabel(command)
		if firstIndex < 0 && strings.HasPrefix(label, first) {
			firstIndex = index
		}
		if secondIndex < 0 && strings.HasPrefix(label, second) {
			secondIndex = index
		}
	}
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("expected %q before %q; commands: %#v", first, second, commands)
	}
}

func findCommand(t *testing.T, commands []Command, program, firstArg string) Command {
	t.Helper()
	for _, command := range commands {
		if command.Program == program && len(command.Args) > 0 && command.Args[0] == firstArg {
			return command
		}
	}
	t.Fatalf("command %s %s not found", program, firstArg)
	return Command{}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
