package attacknetcli

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
)

type fixedEvidenceRenderer struct {
	items []unstructured.Unstructured
}

func (renderer fixedEvidenceRenderer) Render(
	context.Context, *unstructured.Unstructured,
) ([]unstructured.Unstructured, error) {
	return append([]unstructured.Unstructured(nil), renderer.items...), nil
}

func TestEvidenceObjectsAreNamespacedAndAllowlisted(t *testing.T) {
	network := fuzzcorpus.ResourceIdentity{
		APIVersion: "testing.stacks.org/v1beta1", Kind: "StacksNetwork",
		Namespace: "test", Name: "network", UID: "network-uid",
	}
	valid := evidenceObject("v1", "ConfigMap", "network-attacknet-events", "resource-uid", network)
	if _, err := validateEvidenceObject(valid, network); err != nil {
		t.Fatalf("valid resource rejected: %v", err)
	}
	for name, mutate := range map[string]func(*unstructured.Unstructured){
		"cluster scoped": func(value *unstructured.Unstructured) { value.SetNamespace("") },
		"wrong network": func(value *unstructured.Unstructured) {
			labels := value.GetLabels()
			labels[evidenceNetworkLabel] = "other"
			value.SetLabels(labels)
		},
		"unknown kind":   func(value *unstructured.Unstructured) { value.SetKind("ClusterRole") },
		"generated name": func(value *unstructured.Unstructured) { value.SetGenerateName("network-") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid.DeepCopy()
			mutate(candidate)
			if _, err := validateEvidenceObject(candidate, network); err == nil {
				t.Fatal("unsafe renderer output was accepted")
			}
		})
	}
}

func TestEvidencePlaneResumeRequiresExactOwnedMarker(t *testing.T) {
	network, networkIdentity := readyEvidenceNetwork()
	resource := evidenceObject("v1", "ConfigMap", "network-attacknet-events", "events-uid", networkIdentity)
	marker := evidenceObject("v1", "ConfigMap", stableEvidenceName(networkIdentity.Name, "attacknet-fuzz-evidence"), "marker-uid", networkIdentity)
	marker.Object["data"] = map[string]any{"networkUID": networkIdentity.UID}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), network, resource, marker)
	plane, err := NewKubernetesFuzzEvidencePlaneWithClient(client, fixedEvidenceRenderer{})
	if err != nil {
		t.Fatal(err)
	}
	expected := []fuzzcorpus.ResourceIdentity{evidenceIdentity(resource), evidenceIdentity(marker)}
	sortIdentities(expected)
	observed, err := plane.Ensure(context.Background(), networkIdentity, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 2 || observed[0] != expected[0] || observed[1] != expected[1] {
		t.Fatalf("resume changed journaled identities: %#v", observed)
	}

	replaced := marker.DeepCopy()
	replaced.SetUID("replacement-uid")
	replacedClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), network, resource, replaced)
	replacedPlane, _ := NewKubernetesFuzzEvidencePlaneWithClient(replacedClient, fixedEvidenceRenderer{})
	if _, err := replacedPlane.Ensure(context.Background(), networkIdentity, expected); err == nil ||
		!strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("replacement was not rejected: %v", err)
	}
}

func TestEvidencePlaneRefusesAdoptionAndReplacementDeletion(t *testing.T) {
	_, network := readyEvidenceNetwork()
	unowned := evidenceObject("v1", "ConfigMap", "network-attacknet-events", "events-uid", network)
	unowned.SetOwnerReferences(nil)
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), unowned)
	plane, _ := NewKubernetesFuzzEvidencePlaneWithClient(client, fixedEvidenceRenderer{})
	gvr := evidenceKinds["v1/ConfigMap"]
	if err := plane.assertCreatable(context.Background(), gvr, unowned, network); err == nil ||
		!strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("unowned resource was accepted: %v", err)
	}

	replacement := unowned.DeepCopy()
	replacement.SetUID("replacement-uid")
	replacement.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: network.APIVersion, Kind: network.Kind, Name: network.Name,
		UID: "network-uid",
	}})
	replacementClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), replacement)
	replacementPlane, _ := NewKubernetesFuzzEvidencePlaneWithClient(replacementClient, fixedEvidenceRenderer{})
	original := evidenceIdentity(replacement)
	original.UID = "original-uid"
	if err := replacementPlane.Release(context.Background(), []fuzzcorpus.ResourceIdentity{original}); err == nil ||
		!strings.Contains(err.Error(), "refusing to delete replaced") {
		t.Fatalf("replacement deletion was not rejected: %v", err)
	}
}

func TestEvidencePlaneReleaseUsesImmutableUIDPrecondition(t *testing.T) {
	_, network := readyEvidenceNetwork()
	resource := evidenceObject("v1", "ConfigMap", "network-attacknet-events", "events-uid", network)
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), resource)
	client.PrependReactor("delete", "configmaps", func(action clienttesting.Action) (bool, runtime.Object, error) {
		options := action.(clienttesting.DeleteAction).GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil ||
			*options.Preconditions.UID != resource.GetUID() {
			t.Fatal("evidence deletion was not bound to the immutable UID")
		}
		if options.Preconditions.ResourceVersion != nil {
			t.Fatal("mutable evidence resourceVersion was used as a deletion identity")
		}
		return false, nil, nil
	})
	plane, _ := NewKubernetesFuzzEvidencePlaneWithClient(client, fixedEvidenceRenderer{})
	if err := plane.Release(context.Background(), []fuzzcorpus.ResourceIdentity{evidenceIdentity(resource)}); err != nil {
		t.Fatal(err)
	}
}

func readyEvidenceNetwork() (*unstructured.Unstructured, fuzzcorpus.ResourceIdentity) {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "testing.stacks.org/v1beta1", "kind": "StacksNetwork",
		"metadata": map[string]any{
			"name": "network", "namespace": "test", "uid": "network-uid", "resourceVersion": "1",
		},
		"status": map[string]any{
			"phase": "Ready", "inventoryReady": true,
			"inventoryDigest": "sha256:" + strings.Repeat("a", 64),
		},
	}}
	return object, fuzzcorpus.ResourceIdentity{
		APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(),
		Name: object.GetName(), UID: string(object.GetUID()), ResourceVersion: object.GetResourceVersion(),
	}
}

func evidenceObject(
	apiVersion, kind, name, uid string, network fuzzcorpus.ResourceIdentity,
) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{
			"name": name, "namespace": network.Namespace, "uid": uid, "resourceVersion": "1",
			"labels": map[string]any{
				evidenceNetworkLabel:        network.Name,
				"app.kubernetes.io/part-of": "stacks-attacknet",
			},
			"ownerReferences": []any{map[string]any{
				"apiVersion": network.APIVersion, "kind": network.Kind,
				"name": network.Name, "uid": network.UID,
			}},
		},
	}}
}
