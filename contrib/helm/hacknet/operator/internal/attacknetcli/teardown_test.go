package attacknetcli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

type teardownBackend struct {
	fakeBackend
	deleted         bool
	object          *unstructured.Unstructured
	deleteUID       types.UID
	deleteVersion   string
	replacementRace bool
}

func (backend *teardownBackend) Delete(_ context.Context, ref ResourceRef) error {
	return errors.New("teardown must not use name-only deletion")
}

func (backend *teardownBackend) DeleteExact(
	_ context.Context, ref ResourceRef, uid types.UID, resourceVersion string,
) error {
	backend.deleteUID = uid
	backend.deleteVersion = resourceVersion
	if backend.replacementRace {
		return apierrors.NewConflict(
			schema.GroupResource{Group: "testing.stacks.org", Resource: "stacksnetworks"},
			ref.Name, errors.New("resource identity changed"),
		)
	}
	backend.deleted = true
	backend.fakeBackend.deleted = &ref
	return nil
}

func (backend *teardownBackend) Get(context.Context, ResourceRef) (*unstructured.Unstructured, error) {
	if backend.deleted {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "testing.stacks.org", Resource: "stacksnetworks"}, "network")
	}
	if backend.object != nil {
		return backend.object.DeepCopy(), nil
	}
	return &unstructured.Unstructured{}, nil
}

type fakeLogExporter struct{ err error }

type changingIncidentReader struct {
	IncidentEvidenceReader
	reads int
}

func (reader *changingIncidentReader) GetNetwork(ctx context.Context, namespace, name string) (*attacknetv1beta1.StacksNetwork, error) {
	network, err := reader.IncidentEvidenceReader.GetNetwork(ctx, namespace, name)
	reader.reads++
	if err == nil && reader.reads > 1 {
		network.Status.InventoryDigest = "sha256:replacement"
	}
	return network, err
}

func (exporter fakeLogExporter) Export(_ context.Context, _, _ string, _, _ time.Time, output string) (LokiExportMetadata, error) {
	if exporter.err != nil {
		return LokiExportMetadata{Complete: false}, exporter.err
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return LokiExportMetadata{}, err
	}
	metadata := LokiExportMetadata{SchemaVersion: lokiExportSchema, Complete: true, EntryCount: 1, LogArtifact: "logs.jsonl.gz"}
	if err := writePrivateJSON(filepath.Join(output, "kubernetes-source.json"), map[string]any{
		"service": map[string]any{"metadata": map[string]any{"uid": "loki-service-uid"}},
		"pod":     map[string]any{"metadata": map[string]any{"uid": "loki-pod-uid"}},
	}); err != nil {
		return LokiExportMetadata{}, err
	}
	if err := writePrivateJSON(filepath.Join(output, "export.json"), metadata); err != nil {
		return LokiExportMetadata{}, err
	}
	if err := os.WriteFile(filepath.Join(output, "logs.jsonl.gz"), []byte("compressed"), 0o600); err != nil {
		return LokiExportMetadata{}, err
	}
	return metadata, nil
}

func TestTeardownExportsCompleteEvidenceBeforeDeletion(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	backend := &teardownBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.IncidentReader = fixture.reader
	app.LogExporter = fakeLogExporter{}
	app.Now = func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }
	output := filepath.Join(t.TempDir(), "teardown")
	code := app.Run(context.Background(), []string{"teardown", "--output", output, "--start", "2026-08-26T11:00:00Z", "network"})
	if code != 0 {
		t.Fatalf("teardown failed (%d): %s", code, stderr.String())
	}
	if !backend.deleted {
		t.Fatal("StacksNetwork was not deleted after complete evidence")
	}
	if backend.deleteUID == "" || backend.deleteVersion == "" {
		t.Fatal("StacksNetwork deletion was not bound to UID and resourceVersion")
	}
	raw, err := os.ReadFile(filepath.Join(output, "teardown.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"deletionComplete": true`)) {
		t.Fatalf("teardown manifest is incomplete: %s, %v", raw, err)
	}
	if !bytes.Contains(raw, []byte(`"lokiSource"`)) {
		t.Fatalf("teardown manifest does not bind Loki Kubernetes source identity: %s", raw)
	}
}

func TestTeardownPreservesNetworkWhenLokiExportFails(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	backend := &teardownBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.IncidentReader = fixture.reader
	app.LogExporter = fakeLogExporter{err: errors.New("Loki unavailable")}
	app.Now = func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }
	output := filepath.Join(t.TempDir(), "teardown")
	code := app.Run(context.Background(), []string{"teardown", "--output", output, "--start", "2026-08-26T11:00:00Z", "network"})
	if code == 0 || backend.deleted || !strings.Contains(stderr.String(), "StacksNetwork was preserved") {
		t.Fatalf("failed export did not fail closed: code=%d deleted=%v stderr=%s", code, backend.deleted, stderr.String())
	}
}

func TestTeardownPreservesNetworkWhenIdentityChangesAfterCapture(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	backend := &teardownBackend{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.IncidentReader = &changingIncidentReader{IncidentEvidenceReader: fixture.reader}
	app.LogExporter = fakeLogExporter{}
	app.Now = func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }
	output := filepath.Join(t.TempDir(), "teardown")
	code := app.Run(context.Background(), []string{"teardown", "--output", output, "--start", "2026-08-26T11:00:00Z", "network"})
	if code == 0 || backend.deleted || !strings.Contains(stderr.String(), "identity changed") {
		t.Fatalf("identity divergence did not preserve the network: code=%d deleted=%v stderr=%s", code, backend.deleted, stderr.String())
	}
}

func TestTeardownPreservesReplacementRacingExactDelete(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	backend := &teardownBackend{replacementRace: true}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.IncidentReader = fixture.reader
	app.LogExporter = fakeLogExporter{}
	app.Now = func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }
	output := filepath.Join(t.TempDir(), "teardown")
	code := app.Run(context.Background(), []string{
		"teardown", "--output", output, "--start", "2026-08-26T11:00:00Z", "network",
	})
	if code == 0 || backend.deleted || backend.deleteUID == "" || backend.deleteVersion == "" {
		t.Fatalf("racing replacement was not rejected by exact deletion: code=%d deleted=%v stderr=%s", code, backend.deleted, stderr.String())
	}
}

func TestTeardownBindsRunStatusAndDerivesIntervalStart(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	backend := &teardownBackend{object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "testing.stacks.org/v1beta1",
		"kind":       "AttacknetRun",
		"metadata":   map[string]any{"name": "run", "namespace": "test"},
		"spec":       map[string]any{"networkRef": "network"},
		"status":     map[string]any{"startedAt": "2026-08-26T11:00:00Z", "phase": "Passed"},
	}}}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.IncidentReader = fixture.reader
	app.LogExporter = fakeLogExporter{}
	app.Now = func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }
	output := filepath.Join(t.TempDir(), "teardown")
	code := app.Run(context.Background(), []string{"teardown", "--output", output, "--run", "run", "network"})
	if code != 0 {
		t.Fatalf("run-bound teardown failed (%d): %s", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(output, "teardown.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"run": "run"`)) || !bytes.Contains(raw, []byte(`"attacknetRun"`)) {
		t.Fatalf("run evidence is not bound: %s, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(output, "attacknet-run.json")); err != nil {
		t.Fatalf("run artifact is absent: %v", err)
	}
}
