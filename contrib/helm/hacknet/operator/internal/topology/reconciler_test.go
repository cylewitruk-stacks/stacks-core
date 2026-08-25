package topology

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestReconcileCreatesOwnedResourcesAndProgressingStatus(t *testing.T) {
	scheme := testScheme(t)
	network := testNetwork()
	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(network, &appsv1.StatefulSet{}, &corev1.Pod{}).WithObjects(network).Build()
	reconciler := &Reconciler{Client: client, Scheme: scheme, Now: func() time.Time { return time.Unix(100, 0).UTC() }}
	request := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: network.Namespace, Name: network.Name}}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	current := &attacknetv1alpha1.StacksNetwork{}
	if err := client.Get(context.Background(), request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Phase != "Progressing" || current.Status.InventoryReady || current.Status.InventoryDigest != "" {
		t.Fatalf("unexpected status: %#v", current.Status)
	}
	sets := &appsv1.StatefulSetList{}
	if err := client.List(context.Background(), sets); err != nil {
		t.Fatal(err)
	}
	if len(sets.Items) != 3 {
		t.Fatalf("got %d StatefulSets", len(sets.Items))
	}
}

func TestApplyRefusesUnownedCollision(t *testing.T) {
	scheme := testScheme(t)
	network := testNetwork()
	collision := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "attacknet-miner-1", Namespace: network.Namespace}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(network).WithObjects(network, collision).Build()
	reconciler := &Reconciler{Client: client, Scheme: scheme}
	resources, err := Render(network, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.apply(context.Background(), network, resources.Services[1]); err == nil {
		t.Fatal("unowned resource was adopted")
	}
}

func TestStatefulSetUpdatePreservesDefaultedImmutableFields(t *testing.T) {
	resources, err := Render(testNetwork(), testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.StatefulSets[1]
	current := desired.DeepCopy()
	storageClass := "local-path"
	volumeMode := corev1.PersistentVolumeFilesystem
	current.Spec.VolumeClaimTemplates[0].Spec.StorageClassName = &storageClass
	current.Spec.VolumeClaimTemplates[0].Spec.VolumeMode = &volumeMode
	desired.Spec.Template.Annotations["testing.stacks.org/update"] = "new"
	desired.Spec.VolumeClaimTemplates[0].Labels[roleLabel] = "changed-role"
	if err := mergeManagedObject(current, desired); err != nil {
		t.Fatal(err)
	}
	if current.Spec.VolumeClaimTemplates[0].Spec.StorageClassName == nil || *current.Spec.VolumeClaimTemplates[0].Spec.StorageClassName != storageClass {
		t.Fatal("API-defaulted storage class was not preserved")
	}
	if current.Spec.Template.Annotations["testing.stacks.org/update"] != "new" {
		t.Fatal("mutable Pod template was not updated")
	}

	changedStorage := desired.DeepCopy()
	changedStorage.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("2Gi")
	if err := mergeManagedObject(current, changedStorage); err == nil {
		t.Fatal("immutable storage-template change was silently accepted")
	}
}

func TestPruneRefusesLabelOnlyDeletionAuthority(t *testing.T) {
	scheme := testScheme(t)
	network := testNetwork()
	foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "foreign", Namespace: network.Namespace,
		Labels: map[string]string{managedByLabel: managedByValue, networkLabel: network.Name},
	}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(network, foreign).Build()
	reconciler := &Reconciler{Client: client, Scheme: scheme}
	resources, err := Render(network, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.applyAndPrune(context.Background(), network, resources); err == nil {
		t.Fatal("foreign label-matching resource was pruned")
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: network.Namespace, Name: foreign.Name}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("foreign resource was removed: %v", err)
	}
}
