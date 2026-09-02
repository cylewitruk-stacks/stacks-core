package ownership

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func TestPermissionNeutralControllerReferences(t *testing.T) {
	t.Parallel()

	owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owner", UID: types.UID("owner-uid")}}
	gvk := schema.GroupVersionKind{Group: "testing.stacks.org", Version: "v1alpha1", Kind: "Owner"}

	reference := Reference(owner, gvk)
	if reference.Controller == nil || !*reference.Controller {
		t.Fatal("Reference must remain a controller reference")
	}
	if reference.BlockOwnerDeletion != nil {
		t.Fatal("Reference must not request owner-deletion permission")
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	owner.GetObjectKind().SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	child := &corev1.Secret{}
	if err := SetControllerReference(owner, child, scheme); err != nil {
		t.Fatal(err)
	}
	if len(child.OwnerReferences) != 1 {
		t.Fatalf("got %d owner references, want 1", len(child.OwnerReferences))
	}
	if child.OwnerReferences[0].BlockOwnerDeletion != nil {
		t.Fatal("SetControllerReference must not request owner-deletion permission")
	}
}
