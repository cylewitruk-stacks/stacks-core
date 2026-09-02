package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const fieldManager = "stacks-attacknet-cli"

// ResourceRef uniquely identifies one namespaced Attacknet resource.
type ResourceRef struct {
	Kind      Kind
	Namespace string
	Name      string
}

// Backend is the narrow Kubernetes boundary used by host-side commands.
type Backend interface {
	Apply(context.Context, *unstructured.Unstructured, Kind) (*unstructured.Unstructured, error)
	Get(context.Context, ResourceRef) (*unstructured.Unstructured, error)
	Delete(context.Context, ResourceRef) error
	Watch(context.Context, ResourceRef, string) (watch.Interface, error)
	Diagnose(context.Context) (Diagnosis, error)
}

// CreationBackend creates a resource without adopting or modifying an
// existing object with the same name.
type CreationBackend interface {
	Create(context.Context, *unstructured.Unstructured, Kind) (*unstructured.Unstructured, error)
}

// ExactSuspensionBackend suspends one StacksNetwork only while its immutable
// UID and last observed resource version still match.
type ExactSuspensionBackend interface {
	SuspendExact(context.Context, ResourceRef, types.UID, int64) (*unstructured.Unstructured, error)
}

// PlanningBackend can ask Kubernetes admission to evaluate an apply without
// persisting it. Controllers do not reconcile dry-run objects, so this proves
// schema/admission compatibility rather than runtime success.
type PlanningBackend interface {
	DryRunApply(context.Context, *unstructured.Unstructured, Kind) (*unstructured.Unstructured, error)
}

// IdentityDeleteBackend deletes only the exact resource instance previously
// observed by a caller. It prevents name reuse or concurrent replacement from
// turning a verified teardown into deletion of a different object.
type IdentityDeleteBackend interface {
	DeleteExact(context.Context, ResourceRef, types.UID, string) error
}

// UIDDeleteBackend deletes a mutable controller-owned resource only when its
// immutable API-server identity still matches. Resource versions are
// intentionally excluded because status reconciliation legitimately changes
// them between the final read and the delete request.
type UIDDeleteBackend interface {
	DeleteUID(context.Context, ResourceRef, types.UID) error
}

// Diagnosis reports cluster and Attacknet API availability without mutation.
type Diagnosis struct {
	SchemaVersion string         `json:"schemaVersion"`
	ServerVersion string         `json:"serverVersion"`
	APIs          []APIDiagnosis `json:"apis"`
	Ready         bool           `json:"ready"`
}

// APIDiagnosis describes availability of one required resource API.
type APIDiagnosis struct {
	Kind       string `json:"kind"`
	Resource   string `json:"resource"`
	Namespaced bool   `json:"namespaced"`
	Available  bool   `json:"available"`
	Detail     string `json:"detail,omitempty"`
}

// KubernetesBackend performs server-side apply and uncached dynamic reads.
type KubernetesBackend struct {
	dynamic   dynamic.Interface
	discovery discovery.DiscoveryInterface
}

// NewKubernetesBackend constructs a production backend from a REST config.
func NewKubernetesBackend(config *rest.Config) (*KubernetesBackend, error) {
	if config == nil {
		return nil, fmt.Errorf("Kubernetes REST config is required")
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes dynamic client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes discovery client: %w", err)
	}
	return &KubernetesBackend{dynamic: dynamicClient, discovery: discoveryClient}, nil
}

// Apply uses server-side apply without force ownership takeover.
func (backend *KubernetesBackend) Apply(ctx context.Context, object *unstructured.Unstructured, kind Kind) (*unstructured.Unstructured, error) {
	return backend.apply(ctx, object, kind, nil)
}

// Create creates one resource and returns AlreadyExists without modifying the
// object already using that name.
func (backend *KubernetesBackend) Create(
	ctx context.Context, object *unstructured.Unstructured, kind Kind,
) (*unstructured.Unstructured, error) {
	if object == nil {
		return nil, fmt.Errorf("resource is required")
	}
	result, err := backend.dynamic.Resource(kind.GVR).Namespace(object.GetNamespace()).Create(
		ctx, object, metav1.CreateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create %s %s/%s: %w",
			kind.Name, object.GetNamespace(), object.GetName(), err,
		)
	}
	return result, nil
}

// SuspendExact uses atomic JSON-patch tests to prevent name reuse or concurrent
// spec drift from applying suspension to a different admitted network.
func (backend *KubernetesBackend) SuspendExact(
	ctx context.Context,
	ref ResourceRef,
	uid types.UID,
	generation int64,
) (*unstructured.Unstructured, error) {
	patch, err := exactSuspensionPatch(uid, generation)
	if err != nil {
		return nil, fmt.Errorf("suspend %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	result, err := backend.dynamic.Resource(ref.Kind.GVR).Namespace(ref.Namespace).Patch(
		ctx, ref.Name, types.JSONPatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("suspend exact %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	return result, nil
}

func exactSuspensionPatch(uid types.UID, generation int64) ([]byte, error) {
	if uid == "" || generation < 1 {
		return nil, errors.New("UID and generation are required")
	}
	return json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": string(uid)},
		{"op": "test", "path": "/metadata/generation", "value": generation},
		{"op": "add", "path": "/spec/suspended", "value": true},
	})
}

// DryRunApply performs server-side apply admission without persistence.
func (backend *KubernetesBackend) DryRunApply(ctx context.Context, object *unstructured.Unstructured, kind Kind) (*unstructured.Unstructured, error) {
	return backend.apply(ctx, object, kind, []string{metav1.DryRunAll})
}

func (backend *KubernetesBackend) apply(ctx context.Context, object *unstructured.Unstructured, kind Kind, dryRun []string) (*unstructured.Unstructured, error) {
	if object == nil {
		return nil, fmt.Errorf("resource is required")
	}
	encoded, err := json.Marshal(object.Object)
	if err != nil {
		return nil, fmt.Errorf("encode resource for apply: %w", err)
	}
	result, err := backend.dynamic.Resource(kind.GVR).Namespace(object.GetNamespace()).Patch(
		ctx, object.GetName(), types.ApplyPatchType, encoded,
		metav1.PatchOptions{FieldManager: fieldManager, DryRun: dryRun},
	)
	if err != nil {
		action := "apply"
		if len(dryRun) != 0 {
			action = "dry-run apply"
		}
		return nil, fmt.Errorf("%s %s %s/%s: %w", action, kind.Name, object.GetNamespace(), object.GetName(), err)
	}
	return result, nil
}

// Get reads one resource directly from the API server.
func (backend *KubernetesBackend) Get(ctx context.Context, ref ResourceRef) (*unstructured.Unstructured, error) {
	result, err := backend.dynamic.Resource(ref.Kind.GVR).Namespace(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	return result, nil
}

// Delete requests foreground deletion so controller finalizers and owned
// resource cleanup complete before Kubernetes removes the resource.
func (backend *KubernetesBackend) Delete(ctx context.Context, ref ResourceRef) error {
	policy := metav1.DeletePropagationForeground
	err := backend.dynamic.Resource(ref.Kind.GVR).Namespace(ref.Namespace).Delete(ctx, ref.Name, metav1.DeleteOptions{PropagationPolicy: &policy})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	return nil
}

// DeleteExact requests foreground deletion with API-server-enforced identity
// and resource-version preconditions.
func (backend *KubernetesBackend) DeleteExact(
	ctx context.Context, ref ResourceRef, uid types.UID, resourceVersion string,
) error {
	if uid == "" || resourceVersion == "" {
		return fmt.Errorf("delete %s %s/%s requires UID and resourceVersion", ref.Kind.Name, ref.Namespace, ref.Name)
	}
	policy := metav1.DeletePropagationForeground
	options := metav1.DeleteOptions{
		PropagationPolicy: &policy,
		Preconditions: &metav1.Preconditions{
			UID: &uid, ResourceVersion: &resourceVersion,
		},
	}
	if err := backend.dynamic.Resource(ref.Kind.GVR).Namespace(ref.Namespace).Delete(ctx, ref.Name, options); err != nil {
		return fmt.Errorf("delete exact %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	return nil
}

// DeleteUID requests foreground deletion with an API-server-enforced UID
// precondition. It is appropriate for controller-owned resources whose status
// continues to advance after their identity has been sealed.
func (backend *KubernetesBackend) DeleteUID(
	ctx context.Context, ref ResourceRef, uid types.UID,
) error {
	if uid == "" {
		return fmt.Errorf("delete %s %s/%s requires UID", ref.Kind.Name, ref.Namespace, ref.Name)
	}
	options := uidBoundDeleteOptions(uid, metav1.DeletePropagationForeground)
	if err := backend.dynamic.Resource(ref.Kind.GVR).Namespace(ref.Namespace).Delete(ctx, ref.Name, options); err != nil {
		return fmt.Errorf("delete UID-bound %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	return nil
}

// uidBoundDeleteOptions protects deletion from name reuse while permitting
// normal controller status updates between the identity read and deletion.
func uidBoundDeleteOptions(uid types.UID, propagation metav1.DeletionPropagation) metav1.DeleteOptions {
	return metav1.DeleteOptions{
		PropagationPolicy: &propagation,
		Preconditions:     &metav1.Preconditions{UID: &uid},
	}
}

// Watch streams updates for exactly one named resource.
func (backend *KubernetesBackend) Watch(ctx context.Context, ref ResourceRef, resourceVersion string) (watch.Interface, error) {
	selector := "metadata.name=" + ref.Name
	result, err := backend.dynamic.Resource(ref.Kind.GVR).Namespace(ref.Namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector:       selector,
		ResourceVersion:     resourceVersion,
		AllowWatchBookmarks: true,
	})
	if err != nil {
		return nil, fmt.Errorf("watch %s %s/%s: %w", ref.Kind.Name, ref.Namespace, ref.Name, err)
	}
	return result, nil
}

// Diagnose verifies the Kubernetes server and all v1beta1 resource APIs.
func (backend *KubernetesBackend) Diagnose(_ context.Context) (Diagnosis, error) {
	version, err := backend.discovery.ServerVersion()
	if err != nil {
		return Diagnosis{}, fmt.Errorf("query Kubernetes server version: %w", err)
	}
	report := Diagnosis{SchemaVersion: "stacks-attacknet-doctor/v2", ServerVersion: version.GitVersion, Ready: true}
	resources, discoveryErr := backend.discovery.ServerResourcesForGroupVersion(resourceKinds[0].GVK.GroupVersion().String())
	available := map[string]metav1.APIResource{}
	if discoveryErr == nil {
		for _, resource := range resources.APIResources {
			available[resource.Name] = resource
		}
	}
	for _, kind := range resourceKinds {
		item := APIDiagnosis{Kind: kind.Name, Resource: kind.Plural}
		if resource, found := available[kind.Plural]; found {
			item.Available = true
			item.Namespaced = resource.Namespaced
			if !resource.Namespaced {
				item.Available = false
				item.Detail = "resource must be namespaced"
			}
		} else {
			item.Detail = "resource API is unavailable"
			if discoveryErr != nil && !apierrors.IsNotFound(discoveryErr) {
				item.Detail = discoveryErr.Error()
			}
		}
		report.Ready = report.Ready && item.Available
		report.APIs = append(report.APIs, item)
	}
	return report, nil
}
