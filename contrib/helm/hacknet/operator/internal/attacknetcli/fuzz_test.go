package attacknetcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

type fuzzTeardownBackend struct {
	fakeBackend
	objects   map[string]*unstructured.Unstructured
	deletions []string
}

type fuzzSourceBackend struct {
	fakeBackend
	objects map[string]*unstructured.Unstructured
}

type fuzzSuspensionBackend struct {
	fakeBackend
	object          *unstructured.Unstructured
	suspendedUID    types.UID
	suspendedGen    int64
	suspensionCalls int
	churnRV         bool
	churnGeneration bool
}

func (backend *fuzzSourceBackend) Get(_ context.Context, ref ResourceRef) (*unstructured.Unstructured, error) {
	object := backend.objects[fuzzResourceKey(ref)]
	if object == nil {
		return nil, apierrors.NewNotFound(
			schema.GroupResource{Group: ref.Kind.GVK.Group, Resource: ref.Kind.GVR.Resource},
			ref.Name,
		)
	}
	return object.DeepCopy(), nil
}

func (backend *fuzzSuspensionBackend) Get(context.Context, ResourceRef) (*unstructured.Unstructured, error) {
	result := backend.object.DeepCopy()
	if backend.churnRV {
		backend.object.SetResourceVersion("status-write")
	}
	if backend.churnGeneration {
		backend.object.SetGeneration(backend.object.GetGeneration() + 1)
	}
	return result, nil
}

func (backend *fuzzSuspensionBackend) SuspendExact(
	_ context.Context, _ ResourceRef, uid types.UID, generation int64,
) (*unstructured.Unstructured, error) {
	backend.suspensionCalls++
	backend.suspendedUID, backend.suspendedGen = uid, generation
	if backend.object.GetUID() != uid || backend.object.GetGeneration() != generation {
		return nil, errors.New("exact suspension precondition failed")
	}
	backend.object.SetGeneration(backend.object.GetGeneration() + 1)
	backend.object.SetResourceVersion("after-suspend")
	if err := unstructured.SetNestedField(backend.object.Object, true, "spec", "suspended"); err != nil {
		return nil, err
	}
	if err := unstructured.SetNestedField(backend.object.Object, "Suspended", "status", "phase"); err != nil {
		return nil, err
	}
	if err := unstructured.SetNestedField(
		backend.object.Object, backend.object.GetGeneration(), "status", "observedGeneration",
	); err != nil {
		return nil, err
	}
	return backend.object.DeepCopy(), nil
}

func fuzzResourceKey(ref ResourceRef) string {
	return ref.Namespace + "/" + ref.Kind.Name + "/" + ref.Name
}

func (backend *fuzzTeardownBackend) Get(_ context.Context, ref ResourceRef) (*unstructured.Unstructured, error) {
	object := backend.objects[fuzzResourceKey(ref)]
	if object == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: ref.Kind.GVK.Group, Resource: ref.Kind.GVR.Resource}, ref.Name)
	}
	return object.DeepCopy(), nil
}

func (backend *fuzzTeardownBackend) DeleteExact(
	_ context.Context, ref ResourceRef, uid types.UID, resourceVersion string,
) error {
	key := fuzzResourceKey(ref)
	object := backend.objects[key]
	if object == nil {
		return apierrors.NewNotFound(schema.GroupResource{Group: ref.Kind.GVK.Group, Resource: ref.Kind.GVR.Resource}, ref.Name)
	}
	if object.GetUID() != uid || object.GetResourceVersion() != resourceVersion {
		return apierrors.NewConflict(schema.GroupResource{Group: ref.Kind.GVK.Group, Resource: ref.Kind.GVR.Resource}, ref.Name, errors.New("identity changed"))
	}
	backend.deletions = append(backend.deletions, ref.Kind.Name)
	delete(backend.objects, key)
	return nil
}

func (backend *fuzzTeardownBackend) DeleteUID(
	_ context.Context, ref ResourceRef, uid types.UID,
) error {
	key := fuzzResourceKey(ref)
	object := backend.objects[key]
	if object == nil {
		return apierrors.NewNotFound(schema.GroupResource{Group: ref.Kind.GVK.Group, Resource: ref.Kind.GVR.Resource}, ref.Name)
	}
	if object.GetUID() != uid {
		return apierrors.NewConflict(schema.GroupResource{Group: ref.Kind.GVK.Group, Resource: ref.Kind.GVR.Resource}, ref.Name, errors.New("identity changed"))
	}
	backend.deletions = append(backend.deletions, ref.Kind.Name)
	delete(backend.objects, key)
	return nil
}

type networkOnlyIncidentReader struct {
	IncidentEvidenceReader
	network *attacknetv1beta1.StacksNetwork
}

func (reader networkOnlyIncidentReader) GetNetwork(context.Context, string, string) (*attacknetv1beta1.StacksNetwork, error) {
	return reader.network.DeepCopy(), nil
}

func TestFuzzTeardownDeletesReferencedRunBeforeNetwork(t *testing.T) {
	network := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork", Namespace: "test", Name: "network", UID: "network-uid", ResourceVersion: "11"}
	run := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun", Namespace: "test", Name: "run", UID: "run-uid", ResourceVersion: "12"}
	faultTemplate := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "FaultCampaign", Namespace: "test", Name: "fault-template", UID: "fault-template-uid", ResourceVersion: "14"}
	upgradeTemplate := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "UpgradeCampaign", Namespace: "test", Name: "upgrade-template", UID: "upgrade-template-uid", ResourceVersion: "15"}
	policy := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy", Namespace: "test", Name: "clock", UID: "policy-uid", ResourceVersion: "13"}
	backend := &fuzzTeardownBackend{objects: map[string]*unstructured.Unstructured{}}
	for _, identity := range []fuzzcorpus.ResourceIdentity{network, run, faultTemplate, upgradeTemplate, policy} {
		kind, err := LookupKind(identity.Kind)
		if err != nil {
			t.Fatal(err)
		}
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(kind.GVK)
		object.SetNamespace(identity.Namespace)
		object.SetName(identity.Name)
		object.SetUID(types.UID(identity.UID))
		object.SetResourceVersion(identity.ResourceVersion)
		backend.objects[fuzzResourceKey(ResourceRef{Kind: kind, Namespace: identity.Namespace, Name: identity.Name})] = object
	}
	// Status reconciliation advances resource versions after observation. The
	// immutable UID remains the deletion boundary.
	runKind, _ := LookupKind(run.Kind)
	backend.objects[fuzzResourceKey(ResourceRef{Kind: runKind, Namespace: run.Namespace, Name: run.Name})].SetResourceVersion("99")
	runtimeBoundary := &KubernetesFuzzRuntime{
		Backend: backend,
		Incident: networkOnlyIncidentReader{network: &attacknetv1beta1.StacksNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: network.Name, Namespace: network.Namespace, UID: types.UID(network.UID), ResourceVersion: network.ResourceVersion},
			Status:     attacknetv1beta1.StacksNetworkStatus{Phase: "Suspended"},
		}},
	}
	if err := runtimeBoundary.Teardown(context.Background(), fuzzsession.ObservedAttempt{Network: network, Run: run, Templates: []fuzzcorpus.ResourceIdentity{faultTemplate, upgradeTemplate}, Policies: []fuzzcorpus.ResourceIdentity{policy}}); err != nil {
		t.Fatal(err)
	}
	want := []string{"AttacknetRun", "FaultCampaign", "UpgradeCampaign", "StacksNetwork", "BurnchainPolicy"}
	if fmt.Sprint(backend.deletions) != fmt.Sprint(want) {
		t.Fatalf("teardown order = %v, want %v", backend.deletions, want)
	}
}

func TestTerminalRunEvidenceBindsExactIdentityAndChildDecisions(t *testing.T) {
	identity := fuzzcorpus.ResourceIdentity{
		APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun",
		Namespace: "test", Name: "run", UID: "run-uid", Generation: 3,
	}
	kind, _ := LookupKind(identity.Kind)
	decision := map[string]any{
		"executionId": "trial-001-execution-001",
		"child":       "child",
		"childUid":    "child-uid",
		"phase":       "Failed",
	}
	upgradeDecision := map[string]any{
		"executionId": "trial-001-execution-002",
		"child":       "upgrade",
		"childUid":    "upgrade-uid",
		"phase":       "Passed",
		"evidence":    map[string]any{"kind": "UpgradeCampaign", "status": map[string]any{"phase": "Passed"}},
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": attacknetv1beta1.GroupVersion.String(), "kind": "AttacknetRun",
		"metadata": map[string]any{"name": identity.Name, "namespace": identity.Namespace,
			"uid": identity.UID, "generation": int64(3), "resourceVersion": "17"},
		"status": map[string]any{
			"phase": "Failed", "reason": "ChildCampaignFailed", "attribution": "Untriaged",
			"decisions": []any{decision, upgradeDecision},
		},
	}}
	object.SetGroupVersionKind(kind.GVK)
	childKind, _ := LookupKind("FaultCampaign")
	child := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": attacknetv1beta1.GroupVersion.String(), "kind": "FaultCampaign",
		"metadata": map[string]any{
			"name": "child", "namespace": identity.Namespace, "uid": "child-uid",
			"ownerReferences": []any{map[string]any{
				"apiVersion": attacknetv1beta1.GroupVersion.String(), "kind": "AttacknetRun",
				"name": identity.Name, "uid": identity.UID, "controller": true,
			}},
		},
		"status": map[string]any{
			"phase": "Failed", "reason": "EffectNotProven",
		},
	}}
	child.SetGroupVersionKind(childKind.GVK)
	upgradeKind, _ := LookupKind("UpgradeCampaign")
	upgrade := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": attacknetv1beta1.GroupVersion.String(), "kind": "UpgradeCampaign",
		"metadata": map[string]any{
			"name": "upgrade", "namespace": identity.Namespace, "uid": "upgrade-uid",
			"ownerReferences": []any{map[string]any{
				"apiVersion": attacknetv1beta1.GroupVersion.String(), "kind": "AttacknetRun",
				"name": identity.Name, "uid": identity.UID, "controller": true,
			}},
		},
		"status": map[string]any{"phase": "Passed"},
	}}
	upgrade.SetGroupVersionKind(upgradeKind.GVK)
	backend := &fuzzSourceBackend{objects: map[string]*unstructured.Unstructured{
		fuzzResourceKey(ResourceRef{Kind: kind, Namespace: identity.Namespace, Name: identity.Name}):            object,
		fuzzResourceKey(ResourceRef{Kind: childKind, Namespace: identity.Namespace, Name: child.GetName()}):     child,
		fuzzResourceKey(ResourceRef{Kind: upgradeKind, Namespace: identity.Namespace, Name: upgrade.GetName()}): upgrade,
	}}
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: backend}
	attempt := fuzzsession.ObservedAttempt{Run: identity, Result: fuzzsession.TrialResult{
		Phase: "Failed", Reason: "ChildCampaignFailed", Attribution: "Untriaged",
	}}
	artifacts, err := runtimeBoundary.captureTerminalRun(context.Background(), attempt)
	if err != nil || len(artifacts) != 3 || artifacts[0].Name != "control/attacknetrun.json" ||
		artifacts[1].Name != "control/faultcampaigns/child.json" ||
		artifacts[2].Name != "control/upgradecampaigns/upgrade.json" ||
		!bytes.Contains(artifacts[1].Data, []byte(`"EffectNotProven"`)) ||
		!bytes.Contains(artifacts[2].Data, []byte(`"phase":"Passed"`)) {
		t.Fatalf("terminal run evidence = %#v, err=%v", artifacts, err)
	}
	object.SetUID("replacement")
	if _, err := runtimeBoundary.captureTerminalRun(context.Background(), attempt); err == nil ||
		!strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement run was accepted: %v", err)
	}
}

func TestFuzzTeardownRefusesReplacedUpgradeTemplate(t *testing.T) {
	network := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork", Namespace: "test", Name: "network", UID: "network-uid", ResourceVersion: "11"}
	run := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun", Namespace: "test", Name: "run", UID: "run-uid", ResourceVersion: "12"}
	upgrade := fuzzcorpus.ResourceIdentity{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "UpgradeCampaign", Namespace: "test", Name: "upgrade-template", UID: "original-upgrade-uid", ResourceVersion: "13"}
	backend := &fuzzTeardownBackend{objects: map[string]*unstructured.Unstructured{}}
	for _, identity := range []fuzzcorpus.ResourceIdentity{network, run, upgrade} {
		kind, err := LookupKind(identity.Kind)
		if err != nil {
			t.Fatal(err)
		}
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(kind.GVK)
		object.SetNamespace(identity.Namespace)
		object.SetName(identity.Name)
		object.SetUID(types.UID(identity.UID))
		object.SetResourceVersion(identity.ResourceVersion)
		backend.objects[fuzzResourceKey(ResourceRef{Kind: kind, Namespace: identity.Namespace, Name: identity.Name})] = object
	}
	upgradeKind, _ := LookupKind(upgrade.Kind)
	upgradeKey := fuzzResourceKey(ResourceRef{Kind: upgradeKind, Namespace: upgrade.Namespace, Name: upgrade.Name})
	backend.objects[upgradeKey].SetUID(types.UID("replacement-upgrade-uid"))
	runtimeBoundary := &KubernetesFuzzRuntime{
		Backend: backend,
		Incident: networkOnlyIncidentReader{network: &attacknetv1beta1.StacksNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: network.Name, Namespace: network.Namespace, UID: types.UID(network.UID)},
			Status:     attacknetv1beta1.StacksNetworkStatus{Phase: "Suspended"},
		}},
	}
	err := runtimeBoundary.Teardown(context.Background(), fuzzsession.ObservedAttempt{
		Network: network, Run: run, Templates: []fuzzcorpus.ResourceIdentity{upgrade},
	})
	if err == nil || !strings.Contains(err.Error(), "UID changed before teardown") {
		t.Fatalf("replaced upgrade template teardown error = %v", err)
	}
	if _, found := backend.objects[upgradeKey]; !found {
		t.Fatal("teardown deleted a replacement upgrade template")
	}
	for _, kind := range backend.deletions {
		if kind == "UpgradeCampaign" {
			t.Fatal("teardown issued a delete for a replacement upgrade template")
		}
	}
}

func TestReadyInventoryBarrierRequiresTwoMatchingCompleteObservations(t *testing.T) {
	barrier := readyInventoryBarrier{expectedGeneration: 1}
	object := &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{
		"observedGeneration": int64(1),
		"phase":              "Ready", "inventoryReady": true,
		"inventoryDigest": "sha256:" + strings.Repeat("a", 64),
	}}}
	object.SetGeneration(1)
	if ready, err := barrier.observe(object); err != nil || ready {
		t.Fatalf("first observation crossed stability barrier: ready=%v err=%v", ready, err)
	}
	if ready, err := barrier.observe(object); err != nil || !ready {
		t.Fatalf("matching observation did not cross barrier: ready=%v err=%v", ready, err)
	}
	object.Object["status"].(map[string]any)["inventoryDigest"] = "sha256:" + strings.Repeat("b", 64)
	if ready, err := barrier.observe(object); err != nil || ready {
		t.Fatalf("changed digest crossed stability barrier: ready=%v err=%v", ready, err)
	}
}

func TestReadyInventoryBarrierRejectsSpecDriftAndStaleStatus(t *testing.T) {
	barrier := readyInventoryBarrier{expectedGeneration: 2}
	object := &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{
		"observedGeneration": int64(1), "phase": "Ready", "inventoryReady": true,
		"inventoryDigest": "sha256:" + strings.Repeat("a", 64),
	}}}
	object.SetGeneration(2)
	if ready, err := barrier.observe(object); err != nil || ready {
		t.Fatalf("stale observed generation crossed barrier: ready=%v err=%v", ready, err)
	}
	object.SetGeneration(3)
	if _, err := barrier.observe(object); err == nil || !strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("same-UID spec drift error = %v", err)
	}
}

func TestFuzzRunDryRunRendersResourcesWithoutRuntime(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "descriptor.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
	app.FuzzRuntimeFactory = func(string, string) (fuzzsession.Runtime, error) {
		t.Fatal("dry-run constructed a mutation runtime")
		return nil, nil
	}
	code := app.Run(context.Background(), []string{
		"fuzz", "run", "--descriptor", path, "--corpus", t.TempDir(), "--dry-run",
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"mutatedCluster": false`) ||
		!strings.Contains(stdout.String(), `"kind": "StacksNetwork"`) ||
		!strings.Contains(stdout.String(), `"kind": "AttacknetRun"`) {
		t.Fatalf("dry-run output is incomplete: %s", stdout.String())
	}
}

func TestFuzzResumeFindsExactlyOneDescriptorAmongAdvisoryArtifacts(t *testing.T) {
	for _, test := range []struct {
		name             string
		descriptorCopies int
		wantCode         int
	}{
		{name: "interrupted advisory session", descriptorCopies: 1, wantCode: 0},
		{name: "ambiguous descriptor", descriptorCopies: 2, wantCode: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor := fuzzDescriptorWithAdvisoryForCLI(t)
			root := t.TempDir()
			store, err := fuzzcorpus.Open(root, 1<<30, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			descriptorReference, err := store.PutCanonicalObject(
				"session-descriptor", "application/json", descriptor,
			)
			if err != nil {
				t.Fatal(err)
			}
			advisoryBytes, err := fuzzplan.AdvisoryObjectBytes(descriptor.Advisories[0])
			if err != nil {
				t.Fatal(err)
			}
			advisoryReference, err := store.PutObject(
				"advisory-trial-1", "application/json", advisoryBytes,
			)
			if err != nil {
				t.Fatal(err)
			}
			artifacts := []fuzzcorpus.ObjectReference{advisoryReference}
			for range test.descriptorCopies {
				artifacts = append(artifacts, descriptorReference)
			}
			journal, err := store.OpenOrCreateJournal(descriptor.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.Append(fuzzcorpus.JournalRecord{
				Kind: "SessionPlanned", Phase: "Planned", Artifacts: artifacts,
			}); err != nil {
				t.Fatal(err)
			}
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
			code := app.Run(context.Background(), []string{
				"fuzz", "resume", "--session", descriptor.Digest,
				"--corpus", root, "--dry-run",
			})
			if code != test.wantCode {
				t.Fatalf("exit %d, want %d: %s", code, test.wantCode, stderr.String())
			}
			if test.wantCode == 0 && (!strings.Contains(stdout.String(), `"operation": "resume"`) ||
				!strings.Contains(stdout.String(), `"mutatedCluster": false`)) {
				t.Fatalf("resume dry-run output is incomplete: %s", stdout.String())
			}
			if test.wantCode != 0 && !strings.Contains(stderr.String(), "exactly one session-descriptor") {
				t.Fatalf("ambiguous descriptor error = %s", stderr.String())
			}
		})
	}
}

func TestFuzzSourcePreflightAcceptsExactPlanningInputs(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	backend := &fuzzSourceBackend{objects: fuzzSourceObjects(t, descriptor)}
	if err := validateFuzzDescriptorSources(context.Background(), backend, descriptor); err != nil {
		t.Fatalf("exact planning inputs were rejected: %v", err)
	}
}

func TestFuzzRunRejectsTemplateDriftBeforeConstructingRuntime(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	objects := fuzzSourceObjects(t, descriptor)
	template := descriptor.Templates[0]
	kind, err := LookupKind(template.Kind)
	if err != nil {
		t.Fatal(err)
	}
	objects[fuzzResourceKey(ResourceRef{
		Kind: kind, Namespace: template.Namespace, Name: template.Name,
	})].SetGeneration(template.Generation + 1)
	backend := &fuzzSourceBackend{objects: objects}
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "descriptor.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(backend, "test", strings.NewReader(""), stdout, stderr)
	app.FuzzRuntimeFactory = func(string, string) (fuzzsession.Runtime, error) {
		t.Fatal("template drift constructed a mutation runtime")
		return nil, nil
	}
	code := app.Run(context.Background(), []string{
		"fuzz", "run", "--descriptor", path, "--corpus", t.TempDir(),
	})
	if code != 1 || !strings.Contains(stderr.String(), "changed after session planning") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestFuzzRuntimeRejectsJournaledGenerationDrift(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	materialized, err := fuzzplan.MaterializeTrial(descriptor, 1, "source", "Source", "test")
	if err != nil {
		t.Fatal(err)
	}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&materialized.Network)
	if err != nil {
		t.Fatal(err)
	}
	current := &unstructured.Unstructured{Object: value}
	current.SetUID("network-uid")
	current.SetGeneration(2)
	current.SetResourceVersion("7")
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: &fakeBackend{get: current}}
	_, err = runtimeBoundary.EnsureNetwork(context.Background(), &materialized.Network, &fuzzcorpus.ResourceIdentity{
		Kind: "StacksNetwork", Namespace: "test", Name: materialized.Network.Name,
		UID: "network-uid", Generation: 1, ResourceVersion: "6",
	})
	if err == nil || !strings.Contains(err.Error(), "identity differs from the journal") {
		t.Fatalf("generation drift error = %v", err)
	}
}

func TestFuzzRuntimeRefusesToApplyOverAnUnjournaledExistingResource(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	materialized, err := fuzzplan.MaterializeTrial(descriptor, 1, "source", "Source", "test")
	if err != nil {
		t.Fatal(err)
	}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&materialized.Network)
	if err != nil {
		t.Fatal(err)
	}
	foreign := &unstructured.Unstructured{Object: value}
	foreign.SetLabels(nil)
	foreign.SetUID("foreign-uid")
	foreign.SetGeneration(1)
	foreign.SetResourceVersion("7")
	backend := &fakeBackend{get: foreign}
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: backend}
	if _, err := runtimeBoundary.EnsureNetwork(
		context.Background(), &materialized.Network, nil,
	); err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("foreign same-name resource error = %v", err)
	}
	if backend.applyInput != nil {
		t.Fatal("unjournaled existing resource reached server-side apply")
	}
}

func TestObserveRunTerminalRequiresTheJournaledGeneration(t *testing.T) {
	run := &attacknetv1beta1.AttacknetRun{
		TypeMeta: metav1.TypeMeta{
			APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "run", Namespace: "test", UID: "run-uid", Generation: 2,
		},
		Status: attacknetv1beta1.AttacknetRunStatus{
			ObservedGeneration: 1, Phase: "Passed", Reason: "AllRecovered",
			ScheduleRef: &attacknetv1beta1.ScheduleReference{
				Digest: "sha256:" + strings.Repeat("d", 64),
			},
		},
	}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(run)
	if err != nil {
		t.Fatal(err)
	}
	object := &unstructured.Unstructured{Object: value}
	identity := fuzzcorpus.ResourceIdentity{
		Kind: "AttacknetRun", Namespace: "test", Name: "run", UID: "run-uid", Generation: 2,
	}
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: &fakeBackend{}}
	if _, terminal, err := runtimeBoundary.observeRunTerminal(
		context.Background(), identity, object,
	); err != nil || terminal {
		t.Fatalf("stale terminal status accepted: terminal=%v err=%v", terminal, err)
	}
	run.Status.ObservedGeneration = 2
	value, err = runtime.DefaultUnstructuredConverter.ToUnstructured(run)
	if err != nil {
		t.Fatal(err)
	}
	object.Object = value
	if _, terminal, err := runtimeBoundary.observeRunTerminal(
		context.Background(), identity, object,
	); err != nil || !terminal {
		t.Fatalf("current terminal status rejected: terminal=%v err=%v", terminal, err)
	}
	object.SetGeneration(3)
	if _, _, err := runtimeBoundary.observeRunTerminal(
		context.Background(), identity, object,
	); err == nil || !strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("same-UID run spec drift error = %v", err)
	}
}

func TestSuspendNetworkUsesAtomicExactIdentityBoundary(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": attacknetv1beta1.GroupVersion.String(), "kind": "StacksNetwork",
		"metadata": map[string]any{
			"name": "network", "namespace": "test", "uid": "network-uid",
			"resourceVersion": "before-suspend", "generation": int64(1),
		},
		"spec": map[string]any{"suspended": false},
		"status": map[string]any{
			"phase": "Ready", "observedGeneration": int64(1),
		},
	}}
	backend := &fuzzSuspensionBackend{object: object, churnRV: true}
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: backend}
	identity := identityFor(object)
	if err := runtimeBoundary.SuspendNetwork(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if backend.suspensionCalls != 1 || backend.suspendedUID != object.GetUID() ||
		backend.suspendedGen != 1 || backend.applyInput != nil {
		t.Fatalf("suspension did not use exact identity: %#v", backend)
	}
	changedSpec := object.DeepCopy()
	changedSpec.SetGeneration(1)
	changedSpec.SetResourceVersion("before-spec-change")
	backend = &fuzzSuspensionBackend{object: changedSpec, churnGeneration: true}
	if err := (&KubernetesFuzzRuntime{Backend: backend}).SuspendNetwork(context.Background(), identityFor(changedSpec)); err == nil || !strings.Contains(err.Error(), "exact suspension precondition failed") {
		t.Fatalf("concurrent spec generation change was accepted: %v", err)
	}
}

func TestMechanismFamiliesRejectsPostTerminalTemplateDrift(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	materialized, err := fuzzplan.MaterializeTrial(descriptor, 1, "source", "Source", "test")
	if err != nil {
		t.Fatal(err)
	}
	template := materialized.FaultTemplates[0].DeepCopy()
	template.UID = "attempt-template-uid"
	template.Generation = 1
	template.ResourceVersion = "9"
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(template)
	if err != nil {
		t.Fatal(err)
	}
	object := &unstructured.Unstructured{Object: value}
	kind, err := LookupKind("FaultCampaign")
	if err != nil {
		t.Fatal(err)
	}
	backend := &fuzzSourceBackend{objects: map[string]*unstructured.Unstructured{
		fuzzResourceKey(ResourceRef{Kind: kind, Namespace: "test", Name: template.Name}): object,
	}}
	generation := int64(1)
	materialized.Run.Spec.CampaignCatalog[0].ExpectedUID = string(template.UID)
	materialized.Run.Spec.CampaignCatalog[0].ExpectedGeneration = &generation
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: backend}
	if _, err := runtimeBoundary.mechanismFamilies(context.Background(), &materialized.Run); err != nil {
		t.Fatalf("exact template identity rejected: %v", err)
	}
	object.SetGeneration(2)
	if _, err := runtimeBoundary.mechanismFamilies(context.Background(), &materialized.Run); err == nil ||
		!strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("post-terminal generation drift error = %v", err)
	}
}

func fuzzSourceObjects(
	t *testing.T, descriptor fuzzplan.Descriptor,
) map[string]*unstructured.Unstructured {
	t.Helper()
	objects := make(map[string]*unstructured.Unstructured)
	for _, template := range descriptor.Templates {
		var value any
		switch template.Kind {
		case "FaultCampaign":
			value = &attacknetv1beta1.FaultCampaign{
				TypeMeta: metav1.TypeMeta{
					APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: template.Kind,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: template.Name, Namespace: template.Namespace,
					UID: types.UID(template.UID), Generation: template.Generation,
				},
				Spec: *template.FaultSpec.DeepCopy(),
			}
		case "UpgradeCampaign":
			value = &attacknetv1beta1.UpgradeCampaign{
				TypeMeta: metav1.TypeMeta{
					APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: template.Kind,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: template.Name, Namespace: template.Namespace,
					UID: types.UID(template.UID), Generation: template.Generation,
				},
				Spec: *template.UpgradeSpec.DeepCopy(),
			}
		default:
			t.Fatalf("unsupported template kind %s", template.Kind)
		}
		encoded, err := runtime.DefaultUnstructuredConverter.ToUnstructured(value)
		if err != nil {
			t.Fatal(err)
		}
		kind, err := LookupKind(template.Kind)
		if err != nil {
			t.Fatal(err)
		}
		objects[fuzzResourceKey(ResourceRef{
			Kind: kind, Namespace: template.Namespace, Name: template.Name,
		})] = &unstructured.Unstructured{Object: encoded}
	}
	policyKind, err := LookupKind("BurnchainPolicy")
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range descriptor.Network.Policies {
		value := &attacknetv1beta1.BurnchainPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: policy.Name, Namespace: policy.Namespace,
				UID: types.UID(policy.UID), Generation: policy.Generation,
			},
			Spec: *policy.Spec.DeepCopy(),
		}
		encoded, err := runtime.DefaultUnstructuredConverter.ToUnstructured(value)
		if err != nil {
			t.Fatal(err)
		}
		objects[fuzzResourceKey(ResourceRef{
			Kind: policyKind, Namespace: policy.Namespace, Name: policy.Name,
		})] = &unstructured.Unstructured{Object: encoded}
	}
	return objects
}

func TestCorpusReplayDryRunVerifiesEntryWithoutRuntime(t *testing.T) {
	descriptor := fuzzDescriptorForCLI(t)
	root := t.TempDir()
	store, err := fuzzcorpus.Open(root, 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	descriptorReference, err := store.PutExactIntegerObject("session-descriptor", "application/json", descriptor)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := store.PutObject("evidence-manifest", "application/json", []byte(`{"complete":true}`))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := fuzzcorpus.SemanticFingerprint(fuzzcorpus.FingerprintInput{
		SchemaVersion: fuzzcorpus.FingerprintSchema, Phase: "Failed",
		Reason: "ProtocolRecoveryViolated", Attribution: "ProtocolAssertion",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := store.PutEntry(fuzzcorpus.Entry{
		SchemaVersion: fuzzcorpus.EntrySchema, Fingerprint: fingerprint,
		Classification: "ConfirmedNetworkFailure", SessionDigest: descriptor.Digest,
		TrialOrdinal: 1, SourceRun: "source-run",
		ReplayCommand: []string{"attacknet", "corpus", "replay", "--corpus", root, fingerprint},
		Objects:       []fuzzcorpus.ObjectReference{descriptorReference, evidence},
		Attempts: []fuzzcorpus.Attempt{{
			ID: "source", Kind: "Source", NetworkUID: "network-uid", RunUID: "run-uid",
			ScheduleDigest: "sha256:" + strings.Repeat("d", 64),
			Classification: "ConfirmedNetworkFailure", EvidenceDigest: evidence.Digest,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
	app.FuzzRuntimeFactory = func(string, string) (fuzzsession.Runtime, error) {
		t.Fatal("corpus dry-run constructed a mutation runtime")
		return nil, nil
	}
	code := app.Run(context.Background(), []string{
		"corpus", "replay", "--corpus", root, "--entry", entry.Digest,
		"--attempt-id", "manual-replay", "--dry-run", fingerprint,
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"operation": "corpus-replay"`) ||
		!strings.Contains(stdout.String(), `"attemptId": "manual-replay"`) ||
		!strings.Contains(stdout.String(), `"mutatedCluster": false`) {
		t.Fatalf("corpus dry-run output is incomplete: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{
		"corpus", "show", "--corpus", root, "--output", "json", fingerprint,
	})
	if code != 0 || !strings.Contains(stdout.String(), entry.Digest) {
		t.Fatalf("documented corpus show command failed (%d): %s / %s", code, stdout.String(), stderr.String())
	}
}

func TestFuzzLockBreakRequiresExactInspectedIdentityAndWritesAudit(t *testing.T) {
	root := t.TempDir()
	store, err := fuzzcorpus.Open(root, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.AcquireLock("sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.LockRecord()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
	code := app.Run(context.Background(), []string{
		"fuzz", "lock", "break", "--corpus", root,
		"--expected-owner", record.Owner,
		"--expected-process-id", fmt.Sprint(record.ProcessID),
		"--expected-acquired-at", record.AcquiredAt.Format(time.RFC3339Nano),
		"--reason", "operator confirmed stale process",
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if err := lock.Release(); err == nil {
		t.Fatal("broken lock unexpectedly remained releasable")
	}
	verification, err := store.Verify()
	if err != nil || verification.AuditRecords != 1 {
		t.Fatalf("expected verified lock-break audit: %#v: %v", verification, err)
	}
}

type leaseAdminRuntime struct {
	fuzzsession.Runtime
	identity fuzzcorpus.ResourceIdentity
	holder   string
	broken   bool
}

func (runtime *leaseAdminRuntime) SessionLease(context.Context) (fuzzcorpus.ResourceIdentity, string, error) {
	return runtime.identity, runtime.holder, nil
}

func (runtime *leaseAdminRuntime) BreakSession(
	_ context.Context, identity fuzzcorpus.ResourceIdentity, holder, reason string,
) error {
	if identity != runtime.identity || holder != runtime.holder || reason == "" {
		return errors.New("unexpected break request")
	}
	runtime.broken = true
	return nil
}

func TestFuzzLeaseBreakRequiresExactIdentity(t *testing.T) {
	root := t.TempDir()
	if _, err := fuzzcorpus.Open(root, 1<<20, time.Now); err != nil {
		t.Fatal(err)
	}
	runtimeBoundary := &leaseAdminRuntime{
		identity: fuzzcorpus.ResourceIdentity{
			APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: "test",
			Name: "attacknet-fuzz-session", UID: "lease-uid", ResourceVersion: "17",
		},
		holder: "sha256:" + strings.Repeat("b", 64),
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "default", strings.NewReader(""), stdout, stderr)
	requestedNamespace := ""
	app.FuzzRuntimeFactory = func(_ string, namespace string) (fuzzsession.Runtime, error) {
		requestedNamespace = namespace
		return runtimeBoundary, nil
	}
	code := app.Run(context.Background(), []string{
		"fuzz", "lease", "break", "--corpus", root,
		"--namespace", "test",
		"--expected-uid", "lease-uid", "--expected-resource-version", "17",
		"--expected-holder", runtimeBoundary.holder, "--reason", "operator confirmed stale holder",
	})
	if code != 0 || !runtimeBoundary.broken || requestedNamespace != "test" {
		t.Fatalf("exit %d, broken=%v, namespace=%q: %s", code, runtimeBoundary.broken, requestedNamespace, stderr.String())
	}
}

func TestFuzzStatusReturnsVerifiedReportCapacityAndCorpusState(t *testing.T) {
	root := t.TempDir()
	store, err := fuzzcorpus.Open(root, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	session := "sha256:" + strings.Repeat("c", 64)
	receipt, err := store.PutCanonicalObject("capacity", "application/json", map[string]any{
		"schemaVersion": "stacks-attacknet-fuzz-capacity/v1", "admitted": true,
		"snapshot": map[string]any{"corpusAvailableBytes": int64(4096)},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.PutCanonicalObject("session-report", "application/json", map[string]any{
		"schemaVersion": "stacks-attacknet-fuzz-session-report/v1", "sessionDigest": session,
		"status": "Complete", "completedTrials": []int32{1},
	})
	if err != nil || store.PutReportPointer(session, report) != nil {
		t.Fatalf("retain report: %v", err)
	}
	journal, err := store.OpenOrCreateJournal(session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{
		Kind: "CapacityAdmitted", Phase: "CapacityAdmitted", Artifacts: []fuzzcorpus.ObjectReference{receipt},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "SessionComplete", Phase: "Complete"}); err != nil {
		t.Fatal(err)
	}

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "test", strings.NewReader(""), stdout, stderr)
	code := app.Run(context.Background(), []string{
		"fuzz", "status", "--session", session, "--corpus", root, "--output", "json",
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result struct {
		Phase                string                     `json:"phase"`
		ReportReference      fuzzcorpus.ObjectReference `json:"reportReference"`
		Report               map[string]any             `json:"report"`
		CapacityReference    fuzzcorpus.ObjectReference `json:"capacityReference"`
		Capacity             map[string]any             `json:"capacity"`
		CorpusVerification   fuzzcorpus.Verification    `json:"corpusVerification"`
		ClassificationCounts map[string]int             `json:"classificationCounts"`
		Warnings             []string                   `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Phase != "Complete" || result.ReportReference.Digest != report.Digest ||
		result.CapacityReference.Digest != receipt.Digest || result.Report["status"] != "Complete" ||
		result.Capacity["admitted"] != true || !result.CorpusVerification.Valid || len(result.Warnings) != 0 {
		t.Fatalf("status omitted verified operator data: %#v", result)
	}
	for _, class := range []string{"Clean", "NetworkFailureCandidate", "ConfirmedNetworkFailure", "NotReproduced", "Inconclusive", "HarnessFailed"} {
		if count, found := result.ClassificationCounts[class]; !found || count != 0 {
			t.Fatalf("classification %s is not explicitly zero: %#v", class, result.ClassificationCounts)
		}
	}
}

func TestEnsurePolicyWaitsForTheRunControllersRestoredTransition(t *testing.T) {
	desired := &attacknetv1beta1.BurnchainPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "clock", Namespace: "test"},
		Spec: attacknetv1beta1.BurnchainPolicySpec{
			NetworkRef: "network", BitcoinNodeRef: "bitcoin", Paused: false,
		},
	}
	observed := desired.DeepCopy()
	observed.Spec.Paused = true
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(observed)
	if err != nil {
		t.Fatal(err)
	}
	object := &unstructured.Unstructured{Object: value}
	object.SetUID("policy-uid")
	object.SetGeneration(2)
	object.SetResourceVersion("7")
	backend := &fakeBackend{get: object}
	runtimeBoundary := &KubernetesFuzzRuntime{Backend: backend}
	expected := &fuzzcorpus.ResourceIdentity{UID: "policy-uid", Generation: 1, ResourceVersion: "1"}
	if _, err := runtimeBoundary.EnsurePolicy(context.Background(), desired, expected, false); err == nil {
		t.Fatal("unexpected policy pause was accepted before a run was journaled")
	}
	pausedContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := runtimeBoundary.EnsurePolicy(pausedContext, desired, expected, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("still-paused policy was adopted as restored: %v", err)
	}
	observed.Spec.Paused = false
	observed.Status = attacknetv1beta1.BurnchainPolicyStatus{
		ObservedGeneration: 2, Phase: "Ready",
	}
	value, err = runtime.DefaultUnstructuredConverter.ToUnstructured(observed)
	if err != nil {
		t.Fatal(err)
	}
	object.Object = value
	object.SetUID("policy-uid")
	object.SetGeneration(2)
	object.SetResourceVersion("8")
	identity, err := runtimeBoundary.EnsurePolicy(context.Background(), desired, expected, true)
	if err != nil {
		t.Fatalf("restored controller-owned generation transition was rejected: %v", err)
	}
	if identity != *expected {
		t.Fatalf("resume replaced journaled policy identity: %#v", identity)
	}
	object.Object["spec"].(map[string]any)["networkRef"] = "replacement"
	if _, err := runtimeBoundary.EnsurePolicy(context.Background(), desired, expected, true); err == nil {
		t.Fatal("immutable policy drift was accepted as a pause transition")
	}
}

func fuzzDescriptorForCLI(t *testing.T) fuzzplan.Descriptor {
	return fuzzDescriptorForCLIOptions(t, false)
}

func fuzzDescriptorWithAdvisoryForCLI(t *testing.T) fuzzplan.Descriptor {
	return fuzzDescriptorForCLIOptions(t, true)
}

func fuzzDescriptorForCLIOptions(t *testing.T, withAdvisory bool) fuzzplan.Descriptor {
	t.Helper()
	faultSpec := attacknetv1beta1.FaultCampaignSpec{
		Template: true,
		Stages: []attacknetv1beta1.FaultStageSpec{{
			ID: "stage", Faults: []attacknetv1beta1.FaultActionSpec{{
				ID: "action", Target: attacknetv1beta1.FaultTarget{Actors: []string{"miner-1"}},
			}},
		}},
	}
	faultDigest, err := canonical.ArtifactDigest(faultSpec)
	if err != nil {
		t.Fatal(err)
	}
	plan := fuzzplan.Plan{
		SchemaVersion: fuzzplan.PlanSchema, SessionID: "cli-session", Seed: "seed",
		MaxTrials: 1, MaxDuration: metav1.Duration{Duration: time.Hour},
		Network: fuzzplan.NetworkPlan{TemplateFile: "network.yaml"},
		Templates: []fuzzplan.TemplatePlan{{
			ID: "fault", Kind: "FaultCampaign", Name: "fault-template",
			Weight: 1, MaxUses: 1, ExpectedUID: "template-uid",
		}},
		Generation: fuzzplan.GenerationPlan{
			MinExecutions: 1, MaxExecutions: 1,
			Triggers: []attacknetv1beta1.RunTriggerSpec{{}},
		},
		Run: fuzzplan.RunPlan{
			Budgets: attacknetv1beta1.RunBudgets{
				MaxCampaigns: 1, MaxWallTimeSeconds: 120,
				MaxCumulativeFaultSeconds: 60, MaxActiveFaults: 1,
				MaxSignerImpactPercent: 100, MaxBurnchainFaults: 1,
				MaxInconclusiveCampaigns: 1,
			},
			StopPolicy: attacknetv1beta1.StopPolicy{
				OnCampaignFailure: "Stop", OnInconclusive: "Stop",
				OnBudgetExhausted: "Stop", OnSuccess: "Continue",
			},
			AttributionPolicy: attacknetv1beta1.AttributionPolicy{
				RequiredOnFailure: true, RequireIncidentBundle: true,
				AllowedTerminalStates: []string{"Triaged", "Remediated", "Inconclusive"},
			},
		},
		Confirmation: fuzzplan.ConfirmationPlan{RequiredMatches: 1, MaxAttempts: 1},
		Capacity: fuzzplan.CapacityPlan{
			MinimumNodeBytes: 1, MinimumImageBytes: 1, MinimumCorpusBytes: 1,
		},
		Corpus: fuzzplan.CorpusPlan{Root: t.TempDir(), MaximumBytes: 1 << 30},
	}
	planDigest, err := fuzzplan.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	network := attacknetv1beta1.StacksNetwork{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork"},
		ObjectMeta: metav1.ObjectMeta{Name: "template", Namespace: "test"},
		Spec: attacknetv1beta1.StacksNetworkSpec{Burnchain: attacknetv1beta1.BurnchainTopologySpec{
			PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "template-clock"},
			Nodes:     []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin"}},
		}},
	}
	networkDigest, err := fuzzplan.NetworkTemplateDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	policySpec := attacknetv1beta1.BurnchainPolicySpec{NetworkRef: "template", BitcoinNodeRef: "bitcoin"}
	policyDigest, err := canonical.ArtifactDigest(policySpec)
	if err != nil {
		t.Fatal(err)
	}
	advisories := []fuzzplan.AdvisoryArtifact{}
	if withAdvisory {
		advisory, sealErr := fuzzplan.SealAdvisory(fuzzplan.AdvisoryArtifact{
			SchemaVersion: "stacks-attacknet-advisory/v1", TrialOrdinal: 1,
			Candidates: []fuzzplan.AdvisoryCandidate{{
				ID: "fault", Score: 10, Rationale: "bounded preferred choice",
			}},
		})
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		advisories = append(advisories, advisory)
	}
	descriptor, err := fuzzplan.Compile(fuzzplan.ResolvedInput{
		Plan: plan, PlanDigest: planDigest,
		Network: fuzzplan.ResolvedNetwork{TemplateDigest: networkDigest, Template: network, Policies: []fuzzplan.ResolvedPolicy{{
			Name: "template-clock", Namespace: "test", UID: "clock-uid", Generation: 1,
			SpecDigest: policyDigest, Spec: policySpec,
		}}},
		Templates: []fuzzplan.ResolvedTemplate{{
			ID: "fault", Kind: "FaultCampaign", Name: "fault-template", Namespace: "test",
			UID: "template-uid", Generation: 1, SpecDigest: faultDigest,
			Weight: 1, MaxUses: 1, FaultSpec: &faultSpec,
		}},
		Advisories: advisories,
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
