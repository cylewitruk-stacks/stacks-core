package attacknetcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

type fakeBackend struct {
	applyInput *unstructured.Unstructured
	applyKind  Kind
	get        *unstructured.Unstructured
	streams    []watch.Interface
	diagnosis  Diagnosis
	deleted    *ResourceRef
	dryRun     bool
}

func (backend *fakeBackend) DryRunApply(ctx context.Context, object *unstructured.Unstructured, kind Kind) (*unstructured.Unstructured, error) {
	backend.dryRun = true
	return backend.Apply(ctx, object, kind)
}

func (backend *fakeBackend) Apply(_ context.Context, object *unstructured.Unstructured, kind Kind) (*unstructured.Unstructured, error) {
	backend.applyInput, backend.applyKind = object.DeepCopy(), kind
	result := object.DeepCopy()
	result.SetUID("server-uid")
	result.SetResourceVersion("1")
	return result, nil
}

func (backend *fakeBackend) Get(context.Context, ResourceRef) (*unstructured.Unstructured, error) {
	return backend.get.DeepCopy(), nil
}

func (backend *fakeBackend) Delete(_ context.Context, ref ResourceRef) error {
	backend.deleted = &ref
	return nil
}

func (backend *fakeBackend) Watch(context.Context, ResourceRef, string) (watch.Interface, error) {
	stream := backend.streams[0]
	backend.streams = backend.streams[1:]
	return stream, nil
}

func (backend *fakeBackend) Diagnose(context.Context) (Diagnosis, error) {
	return backend.diagnosis, nil
}

func TestAppSubmitUsesTypedServerSideBoundary(t *testing.T) {
	backend := &fakeBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "experiment", strings.NewReader(policyYAML), stdout, stderr)
	if code := app.Run(context.Background(), []string{"submit", "--file", "-", "--output", "json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if backend.applyKind.Name != "BurnchainPolicy" || backend.applyInput.GetNamespace() != "experiment" {
		t.Fatalf("unexpected apply: %#v %#v", backend.applyKind, backend.applyInput)
	}
	if !strings.Contains(stdout.String(), `"uid": "server-uid"`) {
		t.Fatalf("server response not printed: %s", stdout.String())
	}
}

func TestAppSubmitDryRunUsesServerAdmissionWithoutChangingTheCommandContract(t *testing.T) {
	backend := &fakeBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "experiment", strings.NewReader(policyYAML), stdout, stderr)
	if code := app.Run(context.Background(), []string{"submit", "--file", "-", "--dry-run", "--output", "json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !backend.dryRun || backend.applyInput == nil {
		t.Fatal("submit --dry-run did not use the planning backend")
	}
	if !strings.Contains(stdout.String(), `"kind": "BurnchainPolicy"`) {
		t.Fatalf("planned resource is missing: %s", stdout.String())
	}
}

func TestAppDeleteUsesTypedForegroundBoundary(t *testing.T) {
	backend := &fakeBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "experiment", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"delete", "FaultCampaign", "partition"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if backend.deleted == nil || backend.deleted.Kind.Name != "FaultCampaign" || backend.deleted.Namespace != "experiment" || backend.deleted.Name != "partition" {
		t.Fatalf("unexpected delete: %#v", backend.deleted)
	}
	if !strings.Contains(stdout.String(), `"deleted": true`) {
		t.Fatalf("delete result not printed: %s", stdout.String())
	}
}

func TestBurnchainPauseMutatesOnlyTypedDesiredState(t *testing.T) {
	policy, _, err := DecodeSubmission([]byte(policyYAML), "experiment")
	if err != nil {
		t.Fatal(err)
	}
	policy.SetUID("policy-uid")
	policy.SetResourceVersion("9")
	policy.Object["status"] = map[string]any{"phase": "Ready", "observedGeneration": int64(1)}
	backend := &fakeBackend{get: policy}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "experiment", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"burnchain", "pause", "clock"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	paused, found, err := unstructured.NestedBool(backend.applyInput.Object, "spec", "paused")
	if err != nil || !found || !paused {
		t.Fatalf("pause desired state = %v found=%v err=%v", paused, found, err)
	}
	if _, found := backend.applyInput.Object["status"]; found || backend.applyInput.GetUID() != "" || backend.applyInput.GetResourceVersion() != "" {
		t.Fatalf("server-owned fields crossed apply boundary: %#v", backend.applyInput.Object)
	}
}

func TestBurnchainFlashValidatesBeforeBackendConstruction(t *testing.T) {
	created := false
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewLazyApp(func() (Backend, error) {
		created = true
		return &fakeBackend{}, nil
	}, "experiment", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"burnchain", "flash", "--blocks", "3", "clock"}); code != 2 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if created {
		t.Fatal("invalid flash initialized Kubernetes backend")
	}
}

func TestAppValidateIsHermeticAndNormalizesYAML(t *testing.T) {
	created := false
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewLazyApp(func() (Backend, error) {
		created = true
		return &fakeBackend{}, nil
	}, "experiment", strings.NewReader(policyYAML), stdout, stderr)
	if code := app.Run(context.Background(), []string{"validate", "--file", "-", "--output", "json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if created {
		t.Fatal("local validation initialized a Kubernetes backend")
	}
	if !strings.Contains(stdout.String(), `"apiVersion": "testing.stacks.org/v1beta1"`) || !strings.Contains(stdout.String(), `"namespace": "experiment"`) {
		t.Fatalf("unexpected normalized output: %s", stdout.String())
	}
}

func TestAppConvertIsHermeticAndEmitsV1Beta1YAML(t *testing.T) {
	created := false
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	legacy := `
apiVersion: testing.stacks.org/v1alpha1
kind: FaultCampaign
metadata: {name: migrated}
spec:
  networkRef: attacknet
  target: {actors: [follower-1]}
  fault:
    type: pod
    action: pod-kill
    mode: all
    duration: 10s
    parameters: {}
  safety:
    maxUnavailableSignerPercent: 30
    maxUnavailableMinerPercent: 50
`
	app := NewLazyApp(func() (Backend, error) {
		created = true
		return &fakeBackend{}, nil
	}, "experiment", strings.NewReader(legacy), stdout, stderr)
	if code := app.Run(context.Background(), []string{"convert", "--file", "-"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if created {
		t.Fatal("offline conversion initialized a Kubernetes backend")
	}
	for _, expected := range []string{"apiVersion: testing.stacks.org/v1beta1", "kind: FaultCampaign", "namespace: experiment", "maxConcurrentFaults: 1"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("converted YAML lacks %q:\n%s", expected, stdout.String())
		}
	}
}

func TestAppSubmitNamespaceOverrideFailsBeforeMutation(t *testing.T) {
	backend := &fakeBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	input := strings.Replace(policyYAML, "name: clock", "name: clock\n  namespace: declared", 1)
	app := NewApp(backend, "experiment", strings.NewReader(input), stdout, stderr)
	if code := app.Run(context.Background(), []string{"submit", "--file", "-", "--namespace", "requested"}); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if backend.applyInput != nil || !strings.Contains(stderr.String(), "conflicts with requested namespace") {
		t.Fatalf("namespace conflict was not rejected before mutation: %s", stderr.String())
	}
}

func TestAppGetUsesTypedResourceCatalog(t *testing.T) {
	kind, _ := LookupKind("BurnchainPolicy")
	backend := &fakeBackend{get: observedObject(kind, "clock", 1, 1, "Running")}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"get", "--output", "json", "burnchainpolicies", "clock"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"kind": "BurnchainPolicy"`) {
		t.Fatalf("unexpected get output: %s", stdout.String())
	}
}

func TestWaitIgnoresStaleStatusAndConsumesFreshWatch(t *testing.T) {
	kind, _ := LookupKind("StacksNetwork")
	stale := observedObject(kind, "network", 3, 2, "Ready")
	fresh := observedObject(kind, "network", 3, 3, "Ready")
	stream := watch.NewRaceFreeFake()
	backend := &fakeBackend{get: stale, streams: []watch.Interface{stream}}
	go func() {
		stream.Modify(fresh)
	}()
	criterion, err := ParseCriterion("condition=Ready")
	if err != nil {
		t.Fatal(err)
	}
	result, err := WaitFor(context.Background(), backend, ResourceRef{Kind: kind, Namespace: "test", Name: "network"}, criterion)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetResourceVersion() != "3" {
		t.Fatalf("returned stale resource: %#v", result.Object)
	}
}

func TestWaitReconnectsAfterClosedWatch(t *testing.T) {
	kind, _ := LookupKind("AttacknetRun")
	current := observedObject(kind, "run", 1, 1, "Running")
	completed := observedObject(kind, "run", 1, 1, "Passed")
	closed := watch.NewRaceFreeFake()
	closed.Stop()
	next := watch.NewRaceFreeFake()
	backend := &fakeBackend{get: current, streams: []watch.Interface{closed, next}}
	go func() { next.Modify(completed) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := WaitFor(ctx, backend, ResourceRef{Kind: kind, Namespace: "test", Name: "run"}, Criterion{Mode: "terminal"})
	if err != nil {
		t.Fatal(err)
	}
	phase, _, _ := unstructured.NestedString(result.Object, "status", "phase")
	if phase != "Passed" {
		t.Fatalf("phase = %s", phase)
	}
}

func TestTerminalWaitRefusesNonterminalKind(t *testing.T) {
	kind, _ := LookupKind("StacksNetwork")
	_, err := (Criterion{Mode: "terminal"}).Satisfied(observedObject(kind, "network", 1, 1, "Ready"), kind)
	if err == nil || !strings.Contains(err.Error(), "no terminal phase contract") {
		t.Fatalf("got %v", err)
	}
}

func TestAppEvidenceSnapshotIsExplicitlyBounded(t *testing.T) {
	kind, _ := LookupKind("FaultCampaign")
	object := observedObject(kind, "partition", 1, 1, "Passed")
	object.SetUID("campaign-uid")
	backend := &fakeBackend{get: object}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.Now = func() time.Time { return time.Unix(10, 0) }
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if code := app.Run(context.Background(), []string{"evidence", "snapshot", "--output", path, "FaultCampaign", "partition"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot EvidenceSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Scope != "single-resource-status" || snapshot.ResourceDigest == "" || len(snapshot.Limitations) != 2 {
		t.Fatalf("unbounded or unsealed snapshot: %#v", snapshot)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence permissions = %o", info.Mode().Perm())
	}
}

func TestAppIncidentEvidenceUsesLazyTypedReader(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	output := filepath.Join(t.TempDir(), "incident")
	created := false
	app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
	app.IncidentFactory = func() (IncidentEvidenceReader, error) {
		created = true
		return fixture.reader, nil
	}
	if code := app.Run(context.Background(), []string{"evidence", "incident", "--output", output, "network"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !created {
		t.Fatal("incident command did not construct its typed reader")
	}
	if _, err := os.Stat(filepath.Join(output, "manifest.json")); err != nil {
		t.Fatalf("incident manifest was not published: %v", err)
	}
	if !strings.Contains(stdout.String(), `"artifactCount"`) || !strings.Contains(stdout.String(), `"inventoryReady": true`) {
		t.Fatalf("unexpected incident command output: %s", stdout.String())
	}
}

func TestAppHostCommandsValidateBeforeProcessExecution(t *testing.T) {
	runner := &recordingRunner{run: func(Command) (CommandResult, error) {
		return CommandResult{}, errors.New("must not execute")
	}}
	for _, args := range [][]string{
		{"image", "build"},
		{"image", "load", "--mode", "unsafe", "example:local"},
		{"install", "local"},
	} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
		app.CommandRunner = runner
		if code := app.Run(context.Background(), args); code != 2 {
			t.Fatalf("%v exit = %d, want usage failure: %s", args, code, stderr.String())
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid host commands executed processes: %#v", runner.commands)
	}
}

func TestAppDoctorReturnsFailureWhenAPIsAreMissing(t *testing.T) {
	backend := &fakeBackend{diagnosis: Diagnosis{
		SchemaVersion: "stacks-attacknet-doctor/v2", ServerVersion: "v1.36.2", Ready: false,
		APIs: []APIDiagnosis{{Kind: "StacksNetwork", Available: false, Detail: "missing"}},
	}}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"doctor", "--output", "json"}); code != 1 {
		t.Fatalf("got exit %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"ready": false`) {
		t.Fatalf("missing diagnostic output: %s", stdout.String())
	}
}

func TestCommandContractDeclaresNoControllerWorkflow(t *testing.T) {
	seen := map[string]bool{}
	for _, command := range commandContracts {
		if seen[command.Name] {
			t.Fatalf("duplicate command %s", command.Name)
		}
		seen[command.Name] = true
		if command.Controller {
			t.Fatalf("CLI command claims controller workflow ownership: %#v", command)
		}
		if command.SideEffectClass == "" {
			t.Fatalf("command omits its side-effect class: %#v", command)
		}
	}
}

func TestLazyBackendIsNotConstructedForOfflineCommandsOrInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		code  int
	}{
		{name: "help", args: []string{"help"}, code: 0},
		{name: "command contract", args: []string{"commands", "--json"}, code: 0},
		{name: "invalid get syntax", args: []string{"get", "StacksNetwork"}, code: 2},
		{name: "invalid submission", args: []string{"submit", "--file", "-"}, stdin: "not: [valid", code: 1},
		{name: "invalid submit output", args: []string{"submit", "--file", "-", "--output", "xml"}, stdin: policyYAML, code: 2},
		{name: "invalid get output", args: []string{"get", "--output", "xml", "StacksNetwork", "network"}, code: 2},
		{name: "invalid doctor output", args: []string{"doctor", "--output", "yaml"}, code: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			app := NewLazyApp(func() (Backend, error) {
				calls++
				return &fakeBackend{}, nil
			}, "test", strings.NewReader(test.stdin), &bytes.Buffer{}, &bytes.Buffer{})
			if code := app.Run(context.Background(), test.args); code != test.code {
				t.Fatalf("exit code = %d, want %d", code, test.code)
			}
			if calls != 0 {
				t.Fatalf("backend factory called %d times before local validation completed", calls)
			}
		})
	}
}

func TestLazyBackendIsConstructedOnceForRuntimeCommands(t *testing.T) {
	kind, _ := LookupKind("StacksNetwork")
	backend := &fakeBackend{get: observedObject(kind, "network", 1, 1, "Ready")}
	calls := 0
	app := NewLazyApp(func() (Backend, error) {
		calls++
		return backend, nil
	}, "test", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	for range 2 {
		if code := app.Run(context.Background(), []string{"get", "StacksNetwork", "network"}); code != 0 {
			t.Fatalf("get exit code = %d", code)
		}
	}
	if calls != 1 {
		t.Fatalf("backend factory called %d times, want once", calls)
	}
}

func observedObject(kind Kind, name string, generation, observed int64, phase string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": kind.GVK.GroupVersion().String(), "kind": kind.Name,
		"metadata": map[string]any{"name": name, "namespace": "test", "generation": generation, "resourceVersion": "3"},
		"status": map[string]any{
			"observedGeneration": observed, "phase": phase,
			"conditions": []any{map[string]any{"type": "Ready", "status": "True", "observedGeneration": observed}},
		},
	}}
	object.SetGroupVersionKind(kind.GVK)
	return object
}

var _ Backend = (*fakeBackend)(nil)
