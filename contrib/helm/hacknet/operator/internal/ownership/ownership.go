// Package ownership creates controller references compatible with least-privilege operators.
package ownership

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Reference returns a controller reference that permits background garbage collection without
// requiring the controller to have delete permission on the owner resource.
func Reference(owner metav1.Object, gvk schema.GroupVersionKind) metav1.OwnerReference {
	reference := *metav1.NewControllerRef(owner, gvk)
	reference.BlockOwnerDeletion = nil
	return reference
}

// SetControllerReference assigns a permission-neutral controller reference to object.
func SetControllerReference(owner, object client.Object, scheme *runtime.Scheme) error {
	if err := controllerutil.SetControllerReference(owner, object, scheme); err != nil {
		return err
	}
	references := object.GetOwnerReferences()
	for index := range references {
		if references[index].UID == owner.GetUID() &&
			references[index].Controller != nil && *references[index].Controller {
			references[index].BlockOwnerDeletion = nil
		}
	}
	object.SetOwnerReferences(references)
	return nil
}
