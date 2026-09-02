package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/conversion"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

// CommandContract is the generated human/agent contract for one CLI command.
type CommandContract struct {
	Name            string   `json:"name"`
	Purpose         string   `json:"purpose"`
	SideEffectClass string   `json:"sideEffectClass"`
	Controller      bool     `json:"controllerOwnedWorkflow"`
	InputKinds      []string `json:"inputKinds,omitempty"`
	OutputKinds     []string `json:"outputKinds,omitempty"`
}

var commandContracts = []CommandContract{
	{Name: "validate", Purpose: "Validate and normalize one typed v1beta1 resource locally", SideEffectClass: "local-read", Controller: false, InputKinds: kindNames(), OutputKinds: []string{"yaml", "json"}},
	{Name: "convert", Purpose: "Convert one supported v1alpha1 resource to v1beta1 locally", SideEffectClass: "local-read", Controller: false, InputKinds: []string{"FaultCampaign", "AttacknetRun"}, OutputKinds: []string{"yaml", "json"}},
	{Name: "submit", Purpose: "Server-side apply or admission-plan one typed v1beta1 resource", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: kindNames()},
	{Name: "get", Purpose: "Read one typed resource", SideEffectClass: "runtime-read", OutputKinds: []string{"yaml", "json"}},
	{Name: "delete", Purpose: "Delete one typed resource and optionally wait for finalizer cleanup", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: kindNames()},
	{Name: "watch", Purpose: "Stream resource observations without making decisions", SideEffectClass: "runtime-read", OutputKinds: []string{"jsonl"}},
	{Name: "wait", Purpose: "Wait for a fresh controller-owned phase or condition", SideEffectClass: "runtime-read", OutputKinds: []string{"yaml", "json"}},
	{Name: "evidence snapshot", Purpose: "Capture one digest-bound resource/status snapshot", SideEffectClass: "local-filesystem-write", OutputKinds: []string{"json"}},
	{Name: "evidence verify-signer-report", Purpose: "Verify one signed adversarial-signer observer report", SideEffectClass: "local-read", InputKinds: []string{"SignedSignerReport"}, OutputKinds: []string{"json"}},
	{Name: "doctor", Purpose: "Check Kubernetes and Attacknet v1beta1 API availability", SideEffectClass: "runtime-read", OutputKinds: []string{"text", "json"}},
	{Name: "dashboard start", Purpose: "Start a loopback-only Grafana or Chaos Mesh port-forward", SideEffectClass: "local-process-mutation", OutputKinds: []string{"json"}},
	{Name: "dashboard stop", Purpose: "Stop one owned dashboard port-forward", SideEffectClass: "local-process-mutation", OutputKinds: []string{"json"}},
	{Name: "dashboard status", Purpose: "Inspect one owned dashboard port-forward", SideEffectClass: "runtime-read", OutputKinds: []string{"json"}},
	{Name: "burnchain status", Purpose: "Read one controller-owned burnchain policy and clock status", SideEffectClass: "runtime-read", OutputKinds: []string{"yaml", "json"}},
	{Name: "burnchain pause", Purpose: "Request that the burnchain policy stop steady-state mining", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"BurnchainPolicy"}},
	{Name: "burnchain resume", Purpose: "Request that the burnchain policy resume steady-state mining", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"BurnchainPolicy"}},
	{Name: "burnchain cadence", Purpose: "Set the burnchain policy steady-state cadence", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"BurnchainPolicy"}},
	{Name: "burnchain flash", Purpose: "Submit one idempotent bounded burnchain flash request", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"BurnchainPolicy"}},
	{Name: "image build", Purpose: "Build the local Attacknet image set and resolve immutable IDs", SideEffectClass: "local-process-mutation", OutputKinds: []string{"json"}},
	{Name: "image load", Purpose: "Load exact local image references into every kind node", SideEffectClass: "local-process-mutation", OutputKinds: []string{"json"}},
	{Name: "version prepare", Purpose: "Resolve and build an immutable mixed-version descriptor", SideEffectClass: "local-process-mutation", InputKinds: []string{"VersionPlan"}, OutputKinds: []string{"json"}},
	{Name: "version load", Purpose: "Import every sealed profile image into all local kind nodes", SideEffectClass: "local-process-mutation", InputKinds: []string{"VersionDescriptor"}, OutputKinds: []string{"json"}},
	{Name: "version render-static", Purpose: "Apply a sealed profile assignment to a StacksNetwork", SideEffectClass: "local-read", InputKinds: []string{"VersionDescriptor", "StacksNetwork"}, OutputKinds: []string{"yaml", "json"}},
	{Name: "version render-upgrade", Purpose: "Render a sealed descriptor as an UpgradeCampaign", SideEffectClass: "local-read", InputKinds: []string{"VersionDescriptor"}, OutputKinds: []string{"yaml", "json"}},
	{Name: "install local", Purpose: "Install immutable local images and the Hacknet chart safely", SideEffectClass: "runtime-mutation", OutputKinds: []string{"json"}},
	{Name: "evidence incident", Purpose: "Capture a bounded admitted-identity incident bundle", SideEffectClass: "local-filesystem-write", OutputKinds: []string{"json"}},
	{Name: "teardown", Purpose: "Export complete evidence before deleting one StacksNetwork", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"StacksNetwork"}, OutputKinds: []string{"json"}},
	{Name: "fuzz plan", Purpose: "Resolve and compile one finite deterministic fuzz session", SideEffectClass: "runtime-read", InputKinds: []string{"FuzzPlan"}, OutputKinds: []string{"json"}},
	{Name: "fuzz run", Purpose: "Execute one finite descriptor through ordinary controller APIs", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"FuzzDescriptor"}, OutputKinds: []string{"json"}},
	{Name: "fuzz resume", Purpose: "Resume one exact journaled fuzz session", SideEffectClass: "runtime-mutation", Controller: false, InputKinds: []string{"FuzzDescriptor"}, OutputKinds: []string{"json"}},
	{Name: "fuzz status", Purpose: "Read one verified local fuzz-session journal", SideEffectClass: "local-read", OutputKinds: []string{"json"}},
	{Name: "fuzz lock status", Purpose: "Inspect the exact local corpus writer lock", SideEffectClass: "local-read", OutputKinds: []string{"json"}},
	{Name: "fuzz lock break", Purpose: "Break one exact stale corpus lock and retain an audit receipt", SideEffectClass: "local-filesystem-write", OutputKinds: []string{"json"}},
	{Name: "fuzz lease status", Purpose: "Inspect the exact cluster fuzz-session Lease", SideEffectClass: "runtime-read", OutputKinds: []string{"json"}},
	{Name: "fuzz lease break", Purpose: "Break one exact stale session Lease with retained audit receipts", SideEffectClass: "runtime-mutation", Controller: false, OutputKinds: []string{"json"}},
	{Name: "corpus list", Purpose: "List verified semantic corpus entries", SideEffectClass: "local-read", OutputKinds: []string{"json"}},
	{Name: "corpus show", Purpose: "Read verified entries for one semantic fingerprint", SideEffectClass: "local-read", OutputKinds: []string{"json"}},
	{Name: "corpus verify", Purpose: "Verify the complete content-addressed corpus", SideEffectClass: "local-read", OutputKinds: []string{"json"}},
	{Name: "corpus replay", Purpose: "Replay one verified corpus entry on a fresh network", SideEffectClass: "runtime-mutation", Controller: false, OutputKinds: []string{"json"}},
	{Name: "reduce", Purpose: "Run bounded removal-only reduction for one confirmed corpus entry", SideEffectClass: "runtime-mutation", Controller: false, OutputKinds: []string{"json"}},
}

const maximumCLIInputBytes = 8 << 20

func kindNames() []string {
	kinds := Kinds()
	result := make([]string, len(kinds))
	for index := range kinds {
		result[index] = kinds[index].Name
	}
	return result
}

// App contains CLI dependencies and I/O streams.
type App struct {
	Backend            Backend
	BackendFactory     func() (Backend, error)
	DefaultNamespace   string
	Stdin              io.Reader
	Stdout             io.Writer
	Stderr             io.Writer
	Now                func() time.Time
	PortForwards       PortForwardManager
	CommandRunner      CommandRunner
	IncidentReader     IncidentEvidenceReader
	IncidentFactory    func() (IncidentEvidenceReader, error)
	LogExporter        RetainedLogExporter
	LogExportFactory   func() (RetainedLogExporter, error)
	FuzzRuntimeFactory func(string, string) (fuzzsession.Runtime, error)
	backendOnce        sync.Once
	backendErr         error
	incidentOnce       sync.Once
	incidentErr        error
	logExportOnce      sync.Once
	logExportErr       error
}

// NewLazyApp constructs an application whose Kubernetes clients are created
// only after command syntax and local input have been validated.
func NewLazyApp(factory func() (Backend, error), namespace string, stdin io.Reader, stdout, stderr io.Writer) *App {
	app := NewApp(nil, namespace, stdin, stdout, stderr)
	app.BackendFactory = factory
	return app
}

// NewApp constructs a CLI application around an explicit Kubernetes backend.
func NewApp(backend Backend, namespace string, stdin io.Reader, stdout, stderr io.Writer) *App {
	return &App{
		Backend: backend, DefaultNamespace: resolveNamespace(namespace, "default"),
		Stdin: stdin, Stdout: stdout, Stderr: stderr, Now: time.Now,
	}
}

// Run executes one command and returns a process-style exit code.
func (app *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		app.writeHelp()
		return 0
	}
	var err error
	switch args[0] {
	case "commands":
		err = app.runCommands(args[1:])
	case "validate":
		err = app.runValidate(args[1:])
	case "convert":
		err = app.runConvert(args[1:])
	case "submit":
		err = app.runSubmit(ctx, args[1:])
	case "get":
		err = app.runGet(ctx, args[1:])
	case "delete":
		err = app.runDelete(ctx, args[1:])
	case "watch":
		err = app.runWatch(ctx, args[1:])
	case "wait":
		err = app.runWait(ctx, args[1:])
	case "evidence":
		err = app.runEvidence(ctx, args[1:])
	case "doctor":
		err = app.runDoctor(ctx, args[1:])
	case "dashboard":
		err = app.runDashboard(ctx, args[1:])
	case "burnchain":
		err = app.runBurnchain(ctx, args[1:])
	case "image":
		err = app.runImage(ctx, args[1:])
	case "version":
		err = app.runVersion(ctx, args[1:])
	case "install":
		err = app.runInstall(ctx, args[1:])
	case "teardown":
		err = app.runTeardown(ctx, args[1:])
	case "fuzz":
		err = app.runFuzz(ctx, args[1:])
	case "corpus":
		err = app.runCorpus(ctx, args[1:])
	case "reduce":
		err = app.runReduce(ctx, args[1:])
	default:
		err = usageError(fmt.Sprintf("unknown command %q", args[0]))
	}
	if err == nil {
		return 0
	}
	fmt.Fprintf(app.Stderr, "attacknet: %v\n", err)
	var usage commandUsageError
	if errors.As(err, &usage) {
		return 2
	}
	return 1
}

func (app *App) runConvert(args []string) error {
	flags := newFlagSet("convert", app.Stderr)
	file := flags.String("file", "", "v1alpha1 YAML or JSON resource path, or - for stdin")
	namespace := flags.String("namespace", "", "default namespace when metadata.namespace is absent")
	output := flags.String("output", "yaml", "yaml or json")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *file == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet convert --file PATH [--namespace NS] [--output yaml|json]")
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	data, err := app.readInput(*file)
	if err != nil {
		return err
	}
	converted, err := conversion.V1Alpha1Document(data)
	if err != nil {
		return fmt.Errorf("convert submission: %w", err)
	}
	objectMetadata, ok := converted.(metav1.Object)
	if !ok {
		return errors.New("converted resource has no Kubernetes metadata")
	}
	fallback := app.DefaultNamespace
	if *namespace != "" {
		fallback = *namespace
	}
	if err := validateSubmissionMetadata(objectMetadata, fallback); err != nil {
		return fmt.Errorf("convert submission: %w", err)
	}
	objectMetadata.SetNamespace(resolveNamespace(objectMetadata.GetNamespace(), fallback))
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(converted)
	if err != nil {
		return fmt.Errorf("encode converted resource: %w", err)
	}
	delete(value, "status")
	return writeResource(app.Stdout, &unstructured.Unstructured{Object: value}, *output)
}

func (app *App) runValidate(args []string) error {
	flags := newFlagSet("validate", app.Stderr)
	file := flags.String("file", "", "YAML or JSON resource path, or - for stdin")
	namespace := flags.String("namespace", "", "default namespace when metadata.namespace is absent")
	output := flags.String("output", "yaml", "yaml or json")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *file == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet validate --file PATH [--namespace NS] [--output yaml|json]")
	}
	data, err := app.readInput(*file)
	if err != nil {
		return err
	}
	fallback := app.DefaultNamespace
	if *namespace != "" {
		fallback = *namespace
	}
	object, _, err := DecodeSubmission(data, fallback)
	if err != nil {
		return fmt.Errorf("validate submission: %w", err)
	}
	return writeResource(app.Stdout, object, *output)
}

func (app *App) runCommands(args []string) error {
	if len(args) != 1 || args[0] != "--json" {
		return usageError("usage: attacknet commands --json")
	}
	return writeJSON(app.Stdout, map[string]any{
		"schemaVersion": "stacks-attacknet-go-command-contract/v1",
		"commands":      commandContracts,
	})
}

func (app *App) runSubmit(ctx context.Context, args []string) error {
	flags := newFlagSet("submit", app.Stderr)
	file := flags.String("file", "", "YAML or JSON resource path, or - for stdin")
	namespace := flags.String("namespace", "", "override the resource namespace")
	output := flags.String("output", "yaml", "yaml or json")
	dryRun := flags.Bool("dry-run", false, "run server-side admission without persistence")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *file == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet submit --file PATH [--namespace NS] [--output yaml|json] [--dry-run]")
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	data, err := app.readInput(*file)
	if err != nil {
		return err
	}
	fallbackNamespace := app.DefaultNamespace
	if *namespace != "" {
		fallbackNamespace = *namespace
	}
	object, kind, err := DecodeSubmission(data, fallbackNamespace)
	if err != nil {
		return fmt.Errorf("validate submission: %w", err)
	}
	if *namespace != "" && object.GetNamespace() != *namespace {
		return fmt.Errorf("validate submission: resource namespace %q conflicts with requested namespace %q", object.GetNamespace(), *namespace)
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	var applied *unstructured.Unstructured
	if *dryRun {
		planning, ok := backend.(PlanningBackend)
		if !ok {
			return errors.New("Kubernetes backend does not support server-side dry-run")
		}
		applied, err = planning.DryRunApply(ctx, object, kind)
	} else {
		applied, err = backend.Apply(ctx, object, kind)
	}
	if err != nil {
		return err
	}
	return writeResource(app.Stdout, applied, *output)
}

func (app *App) runGet(ctx context.Context, args []string) error {
	flags, namespace, output := readFlags("get", app)
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	ref, err := resourceRef(flags.Args(), *namespace)
	if err != nil {
		return err
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	object, err := backend.Get(ctx, ref)
	if err != nil {
		return err
	}
	return writeResource(app.Stdout, object, *output)
}

func (app *App) runDelete(ctx context.Context, args []string) error {
	flags := newFlagSet("delete", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	wait := flags.Bool("wait", false, "wait until finalizers and foreground deletion complete")
	timeout := flags.Duration("timeout", 10*time.Minute, "maximum wait duration")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *timeout <= 0 {
		return usageError("--timeout must be positive")
	}
	ref, err := resourceRef(flags.Args(), *namespace)
	if err != nil {
		return err
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	if err := backend.Delete(ctx, ref); err != nil {
		return err
	}
	result := map[string]any{"deleted": true, "kind": ref.Kind.Name, "namespace": ref.Namespace, "name": ref.Name}
	if !*wait {
		return writeJSON(app.Stdout, result)
	}
	waitContext, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_, getErr := backend.Get(waitContext, ref)
		if apierrors.IsNotFound(getErr) {
			result["cleanupCompleted"] = true
			return writeJSON(app.Stdout, result)
		}
		if getErr != nil {
			return getErr
		}
		select {
		case <-waitContext.Done():
			return fmt.Errorf("wait for %s %s/%s deletion: %w", ref.Kind.Name, ref.Namespace, ref.Name, waitContext.Err())
		case <-ticker.C:
		}
	}
}

func (app *App) runWatch(ctx context.Context, args []string) error {
	flags := newFlagSet("watch", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	ref, err := resourceRef(flags.Args(), *namespace)
	if err != nil {
		return err
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	return app.stream(ctx, backend, ref)
}

func (app *App) runWait(ctx context.Context, args []string) error {
	flags, namespace, output := readFlags("wait", app)
	criterionValue := flags.String("for", "condition=Ready", "terminal, phase=VALUE, or condition=TYPE")
	timeout := flags.Duration("timeout", 10*time.Minute, "maximum wait duration")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *timeout <= 0 {
		return usageError("--timeout must be positive")
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	ref, err := resourceRef(flags.Args(), *namespace)
	if err != nil {
		return err
	}
	criterion, err := ParseCriterion(*criterionValue)
	if err != nil {
		return commandUsageError{err.Error()}
	}
	waitContext, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	object, err := WaitFor(waitContext, backend, ref, criterion)
	if err != nil {
		return err
	}
	return writeResource(app.Stdout, object, *output)
}

func (app *App) runEvidence(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet evidence snapshot|incident|verify-signer-report [OPTIONS]")
	}
	if args[0] == "incident" {
		return app.runIncidentEvidence(ctx, args[1:])
	}
	if args[0] == "verify-signer-report" {
		return app.runVerifySignerReport(args[1:])
	}
	if args[0] != "snapshot" {
		return usageError("usage: attacknet evidence snapshot|incident|verify-signer-report [OPTIONS]")
	}
	flags := newFlagSet("evidence snapshot", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	output := flags.String("output", "", "artifact path")
	if err := flags.Parse(args[1:]); err != nil {
		return commandUsageError{err.Error()}
	}
	if *output == "" {
		return usageError("--output is required")
	}
	ref, err := resourceRef(flags.Args(), *namespace)
	if err != nil {
		return err
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	object, err := backend.Get(ctx, ref)
	if err != nil {
		return err
	}
	snapshot, err := BuildEvidenceSnapshot(object, app.Now())
	if err != nil {
		return err
	}
	if err := WriteEvidenceSnapshot(*output, snapshot); err != nil {
		return err
	}
	return writeJSON(app.Stdout, map[string]any{"path": *output, "resourceDigest": snapshot.ResourceDigest, "scope": snapshot.Scope})
}

func (app *App) runDoctor(ctx context.Context, args []string) error {
	flags := newFlagSet("doctor", app.Stderr)
	output := flags.String("output", "text", "text or json")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 0 {
		return usageError("usage: attacknet doctor [--output text|json]")
	}
	if *output != "text" && *output != "json" {
		return usageError("--output must be text or json")
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	report, err := backend.Diagnose(ctx)
	if err != nil {
		return err
	}
	switch *output {
	case "json":
		if err := writeJSON(app.Stdout, report); err != nil {
			return err
		}
	case "text":
		fmt.Fprintf(app.Stdout, "Kubernetes %s\n", report.ServerVersion)
		for _, api := range report.APIs {
			state := "available"
			if !api.Available {
				state = "unavailable: " + api.Detail
			}
			fmt.Fprintf(app.Stdout, "%-18s %s\n", api.Kind, state)
		}
	}
	if !report.Ready {
		return errors.New("Attacknet v1beta1 APIs are not ready")
	}
	return nil
}

func (app *App) stream(ctx context.Context, backend Backend, ref ResourceRef) error {
	for {
		current, err := backend.Get(ctx, ref)
		if err != nil {
			return err
		}
		if err := writeWatchEvent(app.Stdout, watch.Added, current); err != nil {
			return err
		}
		stream, err := backend.Watch(ctx, ref, current.GetResourceVersion())
		if err != nil {
			return err
		}
		reconnect, err := app.consumeStream(ctx, stream)
		stream.Stop()
		if err != nil {
			return err
		}
		if !reconnect {
			return nil
		}
	}
}

func (app *App) consumeStream(ctx context.Context, stream watch.Interface) (bool, error) {
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case event, open := <-stream.ResultChan():
			if !open {
				return true, nil
			}
			if event.Type == watch.Bookmark {
				continue
			}
			if event.Type == watch.Error {
				return false, fmt.Errorf("resource watch failed: %#v", event.Object)
			}
			object, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				return false, fmt.Errorf("watch returned %T, expected Unstructured", event.Object)
			}
			if err := writeWatchEvent(app.Stdout, event.Type, object); err != nil {
				return false, err
			}
			if event.Type == watch.Deleted {
				return false, nil
			}
		}
	}
}

func (app *App) requireBackend() (Backend, error) {
	app.backendOnce.Do(func() {
		if app.Backend != nil {
			return
		}
		if app.BackendFactory == nil {
			app.backendErr = errors.New("Kubernetes backend is unavailable")
			return
		}
		app.Backend, app.backendErr = app.BackendFactory()
		if app.backendErr == nil && app.Backend == nil {
			app.backendErr = errors.New("Kubernetes backend factory returned nil")
		}
	})
	return app.Backend, app.backendErr
}

func (app *App) requireIncidentReader() (IncidentEvidenceReader, error) {
	app.incidentOnce.Do(func() {
		if app.IncidentReader != nil {
			return
		}
		if app.IncidentFactory == nil {
			app.incidentErr = errors.New("Kubernetes incident evidence reader is unavailable")
			return
		}
		app.IncidentReader, app.incidentErr = app.IncidentFactory()
		if app.incidentErr == nil && app.IncidentReader == nil {
			app.incidentErr = errors.New("Kubernetes incident evidence reader factory returned nil")
		}
	})
	return app.IncidentReader, app.incidentErr
}

func (app *App) requireLogExporter() (RetainedLogExporter, error) {
	app.logExportOnce.Do(func() {
		if app.LogExporter != nil {
			return
		}
		if app.LogExportFactory == nil {
			app.logExportErr = errors.New("Kubernetes retained-log exporter is unavailable")
			return
		}
		app.LogExporter, app.logExportErr = app.LogExportFactory()
		if app.logExportErr == nil && app.LogExporter == nil {
			app.logExportErr = errors.New("Kubernetes retained-log exporter factory returned nil")
		}
	})
	return app.LogExporter, app.logExportErr
}

func (app *App) requireCommandRunner() (CommandRunner, error) {
	if app.CommandRunner == nil {
		return nil, errors.New("local command runner is unavailable")
	}
	return app.CommandRunner, nil
}

func (app *App) readInput(path string) ([]byte, error) {
	if path == "-" {
		return readLimitedInput(app.Stdin, "stdin")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input %s: %w", path, err)
	}
	defer file.Close()
	return readLimitedInput(file, path)
}

func readLimitedInput(reader io.Reader, source string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximumCLIInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if len(data) > maximumCLIInputBytes {
		return nil, fmt.Errorf("input %s exceeds 8 MiB", source)
	}
	return data, nil
}

func readFlags(name string, app *App) (*flag.FlagSet, *string, *string) {
	flags := newFlagSet(name, app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	output := flags.String("output", "yaml", "yaml or json")
	return flags, namespace, output
}

func resourceRef(args []string, namespace string) (ResourceRef, error) {
	if len(args) != 2 {
		return ResourceRef{}, usageError("resource commands require KIND NAME after options")
	}
	kind, err := LookupKind(args[0])
	if err != nil {
		return ResourceRef{}, commandUsageError{err.Error()}
	}
	if args[1] == "" {
		return ResourceRef{}, usageError("resource name is required")
	}
	if problems := kubevalidation.IsDNS1123Subdomain(args[1]); len(problems) != 0 {
		return ResourceRef{}, usageError("resource name is not a valid DNS subdomain")
	}
	resolvedNamespace := resolveNamespace(namespace, "default")
	if problems := kubevalidation.IsDNS1123Label(resolvedNamespace); len(problems) != 0 {
		return ResourceRef{}, usageError("namespace is not a valid DNS label")
	}
	return ResourceRef{Kind: kind, Namespace: resolvedNamespace, Name: args[1]}, nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func writeResource(writer io.Writer, object *unstructured.Unstructured, format string) error {
	encoded, err := EncodeResource(object, format)
	if err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}

func validateResourceOutput(format string) error {
	switch format {
	case "yaml", "yml", "json":
		return nil
	default:
		return usageError("--output must be yaml or json")
	}
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeWatchEvent(writer io.Writer, eventType watch.EventType, object *unstructured.Unstructured) error {
	return writeJSON(writer, map[string]any{"type": eventType, "object": object.Object})
}

func (app *App) writeHelp() {
	fmt.Fprintln(app.Stdout, "usage: attacknet COMMAND [OPTIONS]")
	fmt.Fprintln(app.Stdout)
	for _, command := range commandContracts {
		fmt.Fprintf(app.Stdout, "  %-20s %s\n", command.Name, command.Purpose)
	}
	fmt.Fprintln(app.Stdout, "  commands --json      Emit the typed machine contract")
}

type commandUsageError struct{ message string }

func (err commandUsageError) Error() string { return err.message }

func usageError(message string) error { return commandUsageError{message: message} }
