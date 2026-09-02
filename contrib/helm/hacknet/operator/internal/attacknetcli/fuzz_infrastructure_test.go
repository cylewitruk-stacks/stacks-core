package attacknetcli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
)

func TestParseKubeletCapacityRequiresBothFilesystems(t *testing.T) {
	capacity, err := parseKubeletCapacity("worker", []byte(`{"node":{"fs":{"availableBytes":123},"runtime":{"imageFs":{"availableBytes":456}}}}`))
	if err != nil || capacity.Name != "worker" || capacity.RootAvailableBytes != 123 || capacity.ImageAvailableBytes != 456 {
		t.Fatalf("unexpected capacity: %#v, %v", capacity, err)
	}
	if _, err := parseKubeletCapacity("worker", []byte(`{"node":{"fs":{"availableBytes":123}}}`)); err == nil {
		t.Fatal("incomplete kubelet summary was accepted")
	}
}

func TestExplicitStorageClassesCoversAllActorFamilies(t *testing.T) {
	class := "local-path"
	descriptor := fuzzplan.Descriptor{Network: fuzzplan.ResolvedNetwork{Template: attacknetv1beta1.StacksNetwork{Spec: attacknetv1beta1.StacksNetworkSpec{
		Defaults:  attacknetv1beta1.NetworkDefaults{Workload: attacknetv1beta1.WorkloadPolicy{Storage: &attacknetv1beta1.StorageSpec{StorageClassName: &class}}},
		Nodes:     []attacknetv1beta1.StacksNodeSpec{{Workload: &attacknetv1beta1.WorkloadPolicy{Storage: &attacknetv1beta1.StorageSpec{StorageClassName: &class}}}},
		RawActors: []attacknetv1beta1.RawActorSpec{{Workload: &attacknetv1beta1.WorkloadPolicy{Storage: &attacknetv1beta1.StorageSpec{StorageClassName: &class}}}},
	}}}}
	classes := explicitStorageClasses(descriptor)
	if len(classes) != 1 {
		t.Fatalf("storage class collection = %#v", classes)
	}
}

func TestQualifiedStorageClassRejectsAmbiguousAndRemoteProvisioners(t *testing.T) {
	defaultAnnotations := map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}
	client := fake.NewClientset(
		&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "one", Annotations: defaultAnnotations}, Provisioner: "rancher.io/local-path"},
		&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "two", Annotations: defaultAnnotations}, Provisioner: "rancher.io/local-path"},
	)
	infra, err := NewKubernetesFuzzInfrastructure(client, "test", t.TempDir(), "escrow:test", corev1.PullIfNotPresent, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := infra.qualifiedStorageClass(context.Background(), fuzzplan.Descriptor{}); err == nil ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("multiple defaults were accepted: %v", err)
	}
	remote := "remote"
	client = fake.NewClientset(&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: remote}, Provisioner: "csi.example.invalid"})
	infra.client = client
	descriptor := fuzzplan.Descriptor{Network: fuzzplan.ResolvedNetwork{Template: attacknetv1beta1.StacksNetwork{
		Spec: attacknetv1beta1.StacksNetworkSpec{Defaults: attacknetv1beta1.NetworkDefaults{Workload: attacknetv1beta1.WorkloadPolicy{
			Storage: &attacknetv1beta1.StorageSpec{StorageClassName: &remote},
		}}},
	}}}
	if _, err := infra.qualifiedStorageClass(context.Background(), descriptor); err == nil ||
		!strings.Contains(err.Error(), "unqualified provisioner") {
		t.Fatalf("remote provisioner was accepted for local escrow: %v", err)
	}
}

func TestReserveNodeStorageResumesExactPVCAndCompletedWriter(t *testing.T) {
	const namespace = "test"
	digest := "sha256:" + strings.Repeat("a", 64)
	quantity := resource.MustParse("1Mi")
	descriptor := fuzzplan.Descriptor{Digest: digest, Capacity: fuzzplan.CapacityPlan{StorageEscrowBytes: 1 << 20}}
	pvcContract, err := capacityPVCContract(descriptor, "local-path")
	if err != nil {
		t.Fatal(err)
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "fuzz-escrow-aaaaaaaaaaaa-00", Namespace: namespace, UID: types.UID("pvc-uid"), ResourceVersion: "2", Annotations: map[string]string{sessionAnnotation: digest, escrowContract: pvcContract}},
		Spec:       corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: stringptr("local-path"), Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: quantity}}},
	}
	client := fake.NewClientset(pvc)
	infra, err := NewKubernetesFuzzInfrastructure(client, namespace, t.TempDir(), "escrow:test", corev1.PullIfNotPresent, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	desiredJob, err := infra.escrowJob(descriptor, "aaaaaaaaaaaa", 0, "worker", pvc.Name)
	if err != nil {
		t.Fatal(err)
	}
	if desiredJob.Spec.Template.Spec.NodeName != "" ||
		desiredJob.Spec.Template.Spec.NodeSelector[corev1.LabelHostname] != "worker" {
		t.Fatal("capacity writer must use scheduler-mediated exact-node placement")
	}
	if len(desiredJob.Spec.Template.Spec.Tolerations) != 2 {
		t.Fatal("capacity writer must tolerate only the control-plane scheduling taints")
	}
	desiredJob.UID, desiredJob.ResourceVersion, desiredJob.Status.Succeeded = types.UID("job-uid"), "3", 1
	if _, err := client.BatchV1().Jobs(namespace).Create(context.Background(), desiredJob, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	resources, err := infra.reserveNodeStorage(context.Background(), descriptor, "aaaaaaaaaaaa", 0, "worker", "local-path")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 || resources[0].UID != "pvc-uid" || resources[1].UID != "job-uid" {
		t.Fatalf("reservation identities = %#v", resources)
	}
}

func TestEscrowJobContractRejectsAnnotatedSecurityDrift(t *testing.T) {
	descriptor := fuzzplan.Descriptor{
		Digest:   "sha256:" + strings.Repeat("a", 64),
		Capacity: fuzzplan.CapacityPlan{StorageEscrowBytes: 1 << 20},
	}
	infra, err := NewKubernetesFuzzInfrastructure(
		fake.NewClientset(), "test", t.TempDir(), "escrow:test",
		corev1.PullIfNotPresent, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := infra.escrowJob(descriptor, "aaaaaaaaaaaa", 0, "worker", "claim")
	if err != nil {
		t.Fatal(err)
	}
	changed := desired.DeepCopy()
	unsafe := false
	changed.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = &unsafe
	if sameEscrowJob(changed, desired, descriptor.Digest) {
		t.Fatal("copied contract annotation hid capacity writer security drift")
	}
}

func TestReleaseReservationGarbageCollectsWriterPods(t *testing.T) {
	const namespace = "test"
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "fuzz-escrow-writer-aaaaaaaaaaaa-00", Namespace: namespace,
		UID: types.UID("job-uid"), ResourceVersion: "3",
	}}
	client := fake.NewClientset(job)
	infra, err := NewKubernetesFuzzInfrastructure(
		client, namespace, t.TempDir(), "escrow:test", corev1.PullIfNotPresent, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity := fuzzcorpus.ResourceIdentity{
		APIVersion: "batch/v1", Kind: "Job", Namespace: namespace,
		Name: job.Name, UID: string(job.UID), ResourceVersion: job.ResourceVersion,
	}
	if err := infra.ReleaseReservation(context.Background(), []fuzzcorpus.ResourceIdentity{identity}); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "delete" || action.GetResource().Resource != "jobs" {
			continue
		}
		options := action.(clienttesting.DeleteAction).GetDeleteOptions()
		if options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationBackground {
			t.Fatalf("Job delete propagation = %v", options.PropagationPolicy)
		}
		if options.Preconditions == nil || options.Preconditions.UID == nil ||
			*options.Preconditions.UID != job.UID {
			t.Fatal("Job deletion was not bound to the immutable UID")
		}
		if options.Preconditions.ResourceVersion != nil {
			t.Fatal("mutable Job resourceVersion was used as a deletion identity")
		}
		return
	}
	t.Fatal("Job delete was not issued")
}

func TestRuntimeSpecNormalizationMatchesKubernetesNullPruning(t *testing.T) {
	campaign := &attacknetv1beta1.FaultCampaign{
		Spec: attacknetv1beta1.FaultCampaignSpec{
			Template: true,
			Stages: []attacknetv1beta1.FaultStageSpec{{
				ID: "bounded", Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "withhold", Fault: attacknetv1beta1.FaultSpec{
						Type: "signer-behavior", Mode: "all",
					},
				}},
			}},
		},
	}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(campaign)
	if err != nil {
		t.Fatal(err)
	}
	removeNilObjectFields(value)
	stages := value["spec"].(map[string]any)["stages"].([]any)
	faults := stages[0].(map[string]any)["faults"].([]any)
	fault := faults[0].(map[string]any)["fault"].(map[string]any)
	if parameters, found := fault["parameters"]; found {
		t.Fatalf("optional null parameters survived API normalization: %#v", parameters)
	}
	array := map[string]any{"items": []any{nil, map[string]any{"optional": nil, "required": "value"}}}
	removeNilObjectFields(array)
	items := array["items"].([]any)
	if items[0] != nil || items[1].(map[string]any)["required"] != "value" {
		t.Fatalf("array content changed during object-field normalization: %#v", items)
	}
	if _, found := items[1].(map[string]any)["optional"]; found {
		t.Fatal("nested optional object field survived normalization")
	}
}

func TestCaptureWorkspaceDoesNotPolluteSemanticSessionNamespace(t *testing.T) {
	root := t.TempDir()
	store, err := fuzzcorpus.Open(root, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := newCaptureWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(workspace) != filepath.Join(root, ".pending") {
		t.Fatalf("capture workspace = %s", workspace)
	}
	if err := os.RemoveAll(workspace); err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify()
	if err != nil || !verification.Valid {
		t.Fatalf("capture workspace polluted corpus layout: %#v, %v", verification, err)
	}
}

func stringptr(value string) *string { return &value }
