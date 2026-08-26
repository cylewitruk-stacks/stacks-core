package attacknetcli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestCaptureIncidentEvidenceUsesExactAdmittedIdentityAndSealsArtifacts(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	output := filepath.Join(t.TempDir(), "incident")
	manifest, err := CaptureIncidentEvidence(context.Background(), fixture.reader, IncidentEvidenceOptions{
		Namespace: "test", NetworkName: "network", OutputDirectory: output,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Network.UID != "network-uid" || manifest.Network.InventoryDigest != "sha256:inventory" {
		t.Fatalf("network identity = %#v", manifest.Network)
	}
	if len(manifest.Errors) != 0 || len(manifest.Omissions) != 0 {
		t.Fatalf("unexpected capture problems: omissions=%#v errors=%#v", manifest.Omissions, manifest.Errors)
	}
	for _, expected := range []string{
		"resources/stacksnetwork.json", "identity/admitted-actors.json",
		"resources/statefulset/network-miner.json", "pods/network-miner-0.json",
		"events/events.json", "logs/network-miner-0/actor.log",
	} {
		artifact := findIncidentArtifact(manifest.Artifacts, expected)
		if artifact == nil {
			t.Fatalf("artifact %s is missing from %#v", expected, manifest.Artifacts)
		}
		content, readErr := os.ReadFile(filepath.Join(output, filepath.FromSlash(expected)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		digest := sha256.Sum256(content)
		if artifact.SHA256 != "sha256:"+hex.EncodeToString(digest[:]) || artifact.Bytes != int64(len(content)) {
			t.Fatalf("artifact binding for %s = %#v", expected, artifact)
		}
	}
	if findIncidentArtifact(manifest.Artifacts, "resources/configmap/impostor.json") != nil {
		t.Fatal("network-labelled resource with a different owner UID was captured")
	}
	encoded, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var observed IncidentEvidenceManifest
	if err := json.Unmarshal(encoded, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.SchemaVersion != "stacks-attacknet-incident-evidence/v1" || !observed.CapturedAt.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("persisted manifest = %#v", observed)
	}
	if fixture.logs.maxActive > 4 {
		t.Fatalf("log reader concurrency exceeded bound: %d", fixture.logs.maxActive)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("bundle permissions = %v", info.Mode().Perm())
	}
}

func TestCaptureIncidentEvidenceRefusesReplacementLogsAndRecordsPartialReads(t *testing.T) {
	fixture := newIncidentFixture(t, true)
	fixture.logs.err = errors.New("should not be called for replacement")
	output := filepath.Join(t.TempDir(), "incident")
	manifest, err := CaptureIncidentEvidence(context.Background(), fixture.reader, IncidentEvidenceOptions{Namespace: "test", NetworkName: "network", OutputDirectory: output})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.logs.calls != 0 {
		t.Fatalf("replacement Pod logs were read %d times", fixture.logs.calls)
	}
	if findIncidentArtifact(manifest.Artifacts, "logs/network-miner-0/actor.log") != nil {
		t.Fatal("replacement Pod log was published")
	}
	if !hasIncidentProblem(manifest.Omissions, "admitted-pod-replaced") {
		t.Fatalf("identity divergence omission is absent: %#v", manifest.Omissions)
	}
	if _, err := os.Stat(filepath.Join(output, "manifest.json")); err != nil {
		t.Fatalf("partial bundle was not atomically published: %v", err)
	}
}

func TestCaptureIncidentEvidenceBoundsLogBytesAndRefusesOverwrite(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	fixture.logs.content = []byte(strings.Repeat("x", 2048))
	output := filepath.Join(t.TempDir(), "incident")
	options := IncidentEvidenceOptions{Namespace: "test", NetworkName: "network", OutputDirectory: output, MaxArtifactBytes: 1024, MaxTotalBytes: 16384}
	manifest, err := CaptureIncidentEvidence(context.Background(), fixture.reader, options)
	if err != nil {
		t.Fatal(err)
	}
	artifact := findIncidentArtifact(manifest.Artifacts, "logs/network-miner-0/actor.log")
	if artifact == nil || artifact.Bytes != 1024 || !hasIncidentProblem(manifest.Omissions, "log-byte-limit") {
		t.Fatalf("bounded log result = artifact %#v omissions %#v", artifact, manifest.Omissions)
	}
	if _, err := CaptureIncidentEvidence(context.Background(), fixture.reader, options); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output overwrite error = %v", err)
	}
}

func TestCaptureIncidentEvidenceHonorsCancellationAndRecordsReadErrors(t *testing.T) {
	fixture := newIncidentFixture(t, false)
	fixture.logs.waitForCancellation = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output := filepath.Join(t.TempDir(), "incident")
	manifest, err := CaptureIncidentEvidence(ctx, fixture.reader, IncidentEvidenceOptions{Namespace: "test", NetworkName: "network", OutputDirectory: output})
	if err == nil {
		// The root identity read is allowed to observe cancellation before any
		// bundle can be safely scoped.
		if !hasIncidentProblem(manifest.Errors, "context-ended") {
			t.Fatalf("cancellation was not recorded: %#v", manifest.Errors)
		}
	} else if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("cancellation error = %v", err)
	}
}

type incidentFixture struct {
	reader *ClientGoIncidentReader
	logs   *fakeIncidentLogs
}

func newIncidentFixture(t *testing.T, replacement bool) incidentFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, attacknetv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	network := &attacknetv1beta1.StacksNetwork{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork"},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: "network-uid", Generation: 3},
		Status:     attacknetv1beta1.StacksNetworkStatus{ObservedGeneration: 3, InventoryReady: true, InventoryDigest: "sha256:inventory", Actors: []attacknetv1beta1.ActorStatus{{Name: "miner", Role: "miner", PodName: "network-miner-0", PodUID: "pod-uid", RuntimeImageID: "docker-pullable://image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},
	}
	networkObject, err := runtime.DefaultUnstructuredConverter.ToUnstructured(network)
	if err != nil {
		t.Fatal(err)
	}
	owner := true
	statefulSet := &appsv1.StatefulSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "StatefulSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "network-miner", Namespace: "test", UID: "sts-uid", Labels: map[string]string{incidentNetworkLabel: "network"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork", Name: "network", UID: "network-uid", Controller: &owner}}},
	}
	impostor := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "impostor", Namespace: "test", UID: "impostor-uid", Labels: map[string]string{incidentNetworkLabel: "network"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork", Name: "network", UID: "different-network-uid", Controller: &owner}}},
	}
	listKinds := map[schema.GroupVersionResource]string{
		incidentNetworkGVR:   "StacksNetworkList",
		incidentOwnedGVRs[0]: "ConfigMapList",
		incidentOwnedGVRs[1]: "PersistentVolumeClaimList",
		incidentOwnedGVRs[2]: "ServiceList",
		incidentOwnedGVRs[3]: "DeploymentList",
		incidentOwnedGVRs[4]: "StatefulSetList",
	}
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, &unstructured.Unstructured{Object: networkObject}, statefulSet, impostor)
	podUID := types.UID("pod-uid")
	if replacement {
		podUID = "replacement-uid"
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "network-miner-0", Namespace: "test", UID: podUID}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "actor", Image: "image:test"}}}}
	event := &corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "scheduled", Namespace: "test", UID: "event-uid"}, InvolvedObject: corev1.ObjectReference{UID: podUID}, Reason: "Scheduled", Message: "scheduled"}
	coreClient := kubernetesfake.NewSimpleClientset(pod, event)
	logs := &fakeIncidentLogs{content: []byte("one\ntwo\n")}
	return incidentFixture{reader: NewClientGoIncidentReaderWithClients(dynamicClient, coreClient, logs), logs: logs}
}

type fakeIncidentLogs struct {
	mu                  sync.Mutex
	content             []byte
	err                 error
	calls               int
	active              int
	maxActive           int
	waitForCancellation bool
}

func (logs *fakeIncidentLogs) Read(ctx context.Context, _, _, _ string, _, maxBytes int64) ([]byte, bool, error) {
	logs.mu.Lock()
	logs.calls++
	logs.active++
	if logs.active > logs.maxActive {
		logs.maxActive = logs.active
	}
	logs.mu.Unlock()
	defer func() {
		logs.mu.Lock()
		logs.active--
		logs.mu.Unlock()
	}()
	if logs.waitForCancellation {
		<-ctx.Done()
		return nil, false, ctx.Err()
	}
	if logs.err != nil {
		return nil, false, logs.err
	}
	content := append([]byte(nil), logs.content...)
	if int64(len(content)) > maxBytes {
		return content[:maxBytes], true, nil
	}
	return content, false, nil
}

func findIncidentArtifact(values []IncidentEvidenceArtifact, path string) *IncidentEvidenceArtifact {
	for index := range values {
		if values[index].Path == path {
			return &values[index]
		}
	}
	return nil
}

func hasIncidentProblem(values []IncidentEvidenceProblem, reason string) bool {
	for _, value := range values {
		if value.Reason == reason {
			return true
		}
	}
	return false
}

var _ PodLogReader = (*fakeIncidentLogs)(nil)
