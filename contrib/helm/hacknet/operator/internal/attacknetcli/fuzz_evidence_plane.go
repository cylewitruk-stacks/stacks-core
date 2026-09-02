package attacknetcli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
)

const (
	evidenceFieldManager = "stacks-attacknet-fuzz-evidence"
	evidenceMarkerSchema = "stacks-attacknet-fuzz-evidence-plane/v1"
	evidenceNetworkLabel = "testing.stacks.org/network"
	maximumRenderBytes   = 8 << 20
)

var evidenceKinds = map[string]schema.GroupVersionResource{
	"v1/ConfigMap":                             {Version: "v1", Resource: "configmaps"},
	"v1/PersistentVolumeClaim":                 {Version: "v1", Resource: "persistentvolumeclaims"},
	"v1/Secret":                                {Version: "v1", Resource: "secrets"},
	"v1/Service":                               {Version: "v1", Resource: "services"},
	"v1/ServiceAccount":                        {Version: "v1", Resource: "serviceaccounts"},
	"apps/v1/DaemonSet":                        {Group: "apps", Version: "v1", Resource: "daemonsets"},
	"apps/v1/Deployment":                       {Group: "apps", Version: "v1", Resource: "deployments"},
	"apps/v1/StatefulSet":                      {Group: "apps", Version: "v1", Resource: "statefulsets"},
	"networking.k8s.io/v1/NetworkPolicy":       {Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	"rbac.authorization.k8s.io/v1/Role":        {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"},
	"rbac.authorization.k8s.io/v1/RoleBinding": {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"},
}

// EvidenceRenderer converts one admitted StacksNetwork into the fixed,
// product-owned observability resource set.
type EvidenceRenderer interface {
	Render(context.Context, *unstructured.Unstructured) ([]unstructured.Unstructured, error)
}

// JSEvidenceRenderer invokes the existing observability renderer without a
// shell and passes the event credential through a mode-0600 file.
type JSEvidenceRenderer struct {
	Node              string
	Path              string
	RunOperatorTarget string
}

// NewJSEvidenceRenderer validates the fixed renderer executable and source.
func NewJSEvidenceRenderer(path, runOperatorTarget string) (*JSEvidenceRenderer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("observability renderer path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve observability renderer: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("observability renderer must be a regular file: %w", err)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return nil, errors.New("node is required to run the bundled observability renderer")
	}
	if strings.TrimSpace(runOperatorTarget) == "" || strings.ContainsAny(runOperatorTarget, " \t\r\n/\\") {
		return nil, errors.New("run-operator target must be a non-empty service endpoint")
	}
	return &JSEvidenceRenderer{Node: node, Path: absolute, RunOperatorTarget: runOperatorTarget}, nil
}

// Render executes the fixed renderer and decodes its bounded List result.
func (renderer *JSEvidenceRenderer) Render(
	ctx context.Context, network *unstructured.Unstructured,
) ([]unstructured.Unstructured, error) {
	if renderer == nil || renderer.Node == "" || renderer.Path == "" || network == nil {
		return nil, errors.New("configured evidence renderer and network are required")
	}
	directory, err := os.MkdirTemp("", "stacks-attacknet-fuzz-evidence-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	manifestPath := filepath.Join(directory, "network.json")
	outputPath := filepath.Join(directory, "resources.json")
	tokenPath := filepath.Join(directory, "event-token")
	tokenOutputPath := filepath.Join(directory, "rendered-token")
	manifest, err := json.Marshal(network.Object)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate event credential: %w", err)
	}
	if err := os.WriteFile(tokenPath, []byte(hex.EncodeToString(token)+"\n"), 0o600); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, renderer.Node, renderer.Path, manifestPath,
		"--output="+outputPath,
		"--token-output="+tokenOutputPath,
		"--event-token-file="+tokenPath,
		"--run-operator-target="+renderer.RunOperatorTarget,
		"--prometheus-service-name="+fuzzplan.EvidencePrometheusServiceName(network.GetName()),
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("render observability resources: %w: %s", err, strings.TrimSpace(output.String()))
	}
	file, err := os.Open(outputPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximumRenderBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumRenderBytes {
		return nil, errors.New("rendered evidence plane exceeds the size limit")
	}
	var list unstructured.UnstructuredList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("decode rendered evidence plane: %w", err)
	}
	if list.GetAPIVersion() != "v1" || list.GetKind() != "List" || len(list.Items) == 0 {
		return nil, errors.New("renderer returned an empty or unsupported Kubernetes resource list")
	}
	return list.Items, nil
}

// KubernetesFuzzEvidencePlane manages one identity-bound telemetry stack per
// fresh fuzz attempt.
type KubernetesFuzzEvidencePlane struct {
	dynamic  dynamic.Interface
	renderer EvidenceRenderer
}

// NewKubernetesFuzzEvidencePlane constructs the production provisioner.
func NewKubernetesFuzzEvidencePlane(
	config *rest.Config, renderer EvidenceRenderer,
) (*KubernetesFuzzEvidencePlane, error) {
	if config == nil || renderer == nil {
		return nil, errors.New("Kubernetes config and evidence renderer are required")
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create evidence-plane client: %w", err)
	}
	return &KubernetesFuzzEvidencePlane{dynamic: client, renderer: renderer}, nil
}

// NewKubernetesFuzzEvidencePlaneWithClient constructs a provisioner for tests.
func NewKubernetesFuzzEvidencePlaneWithClient(
	client dynamic.Interface, renderer EvidenceRenderer,
) (*KubernetesFuzzEvidencePlane, error) {
	if client == nil || renderer == nil {
		return nil, errors.New("Kubernetes client and evidence renderer are required")
	}
	return &KubernetesFuzzEvidencePlane{dynamic: client, renderer: renderer}, nil
}

// Ensure creates a new telemetry stack or verifies the exact journaled stack.
func (plane *KubernetesFuzzEvidencePlane) Ensure(
	ctx context.Context,
	network fuzzcorpus.ResourceIdentity,
	expected []fuzzcorpus.ResourceIdentity,
) ([]fuzzcorpus.ResourceIdentity, error) {
	if err := validateExactIdentity(network); err != nil || network.Kind != "StacksNetwork" {
		return nil, errors.New("exact StacksNetwork identity is required for the evidence plane")
	}
	liveNetwork, err := plane.liveNetwork(ctx, network)
	if err != nil {
		return nil, err
	}
	if expected != nil {
		if len(expected) == 0 {
			return nil, errors.New("journaled evidence plane is empty")
		}
		if err := plane.verifyExpected(ctx, network, expected); err != nil {
			return nil, err
		}
		if err := plane.waitReady(ctx, expected); err != nil {
			return nil, err
		}
		return append([]fuzzcorpus.ResourceIdentity(nil), expected...), nil
	}
	items, err := plane.renderer.Render(ctx, liveNetwork)
	if err != nil {
		return nil, err
	}
	resources, err := plane.applyRendered(ctx, network, items)
	if err != nil {
		return nil, err
	}
	if err := plane.pruneStale(ctx, network, resources); err != nil {
		return nil, err
	}
	if err := plane.waitReady(ctx, resources); err != nil {
		return nil, err
	}
	marker, err := plane.applyMarker(ctx, network, resources)
	if err != nil {
		return nil, err
	}
	resources = append(resources, marker)
	sortIdentities(resources)
	return resources, nil
}

func (plane *KubernetesFuzzEvidencePlane) pruneStale(
	ctx context.Context,
	network fuzzcorpus.ResourceIdentity,
	desired []fuzzcorpus.ResourceIdentity,
) error {
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, identity := range desired {
		desiredKeys[identityKey(identity)] = struct{}{}
	}
	seen := map[schema.GroupVersionResource]struct{}{}
	stale := []fuzzcorpus.ResourceIdentity{}
	selector := evidenceNetworkLabel + "=" + network.Name + ",app.kubernetes.io/part-of=stacks-attacknet"
	for _, gvr := range evidenceKinds {
		if _, duplicate := seen[gvr]; duplicate {
			continue
		}
		seen[gvr] = struct{}{}
		list, err := plane.dynamic.Resource(gvr).Namespace(network.Namespace).List(
			ctx, metav1.ListOptions{LabelSelector: selector},
		)
		if err != nil {
			return fmt.Errorf("list stale evidence resources for %s: %w", gvr.Resource, err)
		}
		for index := range list.Items {
			item := &list.Items[index]
			identity := evidenceIdentity(item)
			if _, retained := desiredKeys[identityKey(identity)]; retained {
				continue
			}
			if !ownedByNetwork(item, network) {
				return fmt.Errorf("refusing stale evidence resource not owned by the exact network: %s", evidenceObjectKey(item))
			}
			stale = append(stale, identity)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return plane.Release(ctx, stale)
}

func (plane *KubernetesFuzzEvidencePlane) liveNetwork(
	ctx context.Context, expected fuzzcorpus.ResourceIdentity,
) (*unstructured.Unstructured, error) {
	kind, _ := LookupKind("StacksNetwork")
	live, err := plane.dynamic.Resource(kind.GVR).Namespace(expected.Namespace).Get(
		ctx, expected.Name, metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("read evidence-plane network: %w", err)
	}
	if string(live.GetUID()) != expected.UID {
		return nil, errors.New("StacksNetwork UID changed before evidence-plane provisioning")
	}
	if live.GetGeneration() != expected.Generation {
		return nil, errors.New("StacksNetwork generation changed before evidence-plane provisioning")
	}
	phase, _, _ := unstructured.NestedString(live.Object, "status", "phase")
	ready, _, _ := unstructured.NestedBool(live.Object, "status", "inventoryReady")
	digest, _, _ := unstructured.NestedString(live.Object, "status", "inventoryDigest")
	observedGeneration, _, _ := unstructured.NestedInt64(live.Object, "status", "observedGeneration")
	if phase != "Ready" || !ready || digest == "" || observedGeneration != expected.Generation {
		return nil, errors.New("StacksNetwork is not ready for evidence-plane provisioning")
	}
	return live, nil
}

func (plane *KubernetesFuzzEvidencePlane) applyRendered(
	ctx context.Context,
	network fuzzcorpus.ResourceIdentity,
	items []unstructured.Unstructured,
) ([]fuzzcorpus.ResourceIdentity, error) {
	sort.Slice(items, func(left, right int) bool {
		return evidenceObjectKey(&items[left]) < evidenceObjectKey(&items[right])
	})
	resources := make([]fuzzcorpus.ResourceIdentity, 0, len(items))
	for index := range items {
		item := items[index].DeepCopy()
		gvr, err := validateEvidenceObject(item, network)
		if err != nil {
			return nil, err
		}
		if err := plane.assertCreatable(ctx, gvr, item, network); err != nil {
			return nil, err
		}
		item.SetOwnerReferences([]metav1.OwnerReference{{
			APIVersion: network.APIVersion, Kind: network.Kind,
			Name: network.Name, UID: types.UID(network.UID),
		}})
		encoded, err := json.Marshal(item.Object)
		if err != nil {
			return nil, err
		}
		applied, err := plane.dynamic.Resource(gvr).Namespace(network.Namespace).Patch(
			ctx, item.GetName(), types.ApplyPatchType, encoded,
			metav1.PatchOptions{FieldManager: evidenceFieldManager},
		)
		if err != nil {
			return nil, fmt.Errorf("apply evidence resource %s: %w", evidenceObjectKey(item), err)
		}
		resources = append(resources, evidenceIdentity(applied))
	}
	return resources, nil
}

func (plane *KubernetesFuzzEvidencePlane) assertCreatable(
	ctx context.Context, gvr schema.GroupVersionResource,
	item *unstructured.Unstructured, network fuzzcorpus.ResourceIdentity,
) error {
	current, err := plane.dynamic.Resource(gvr).Namespace(network.Namespace).Get(
		ctx, item.GetName(), metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ownedByNetwork(current, network) {
		return fmt.Errorf("refusing to adopt existing evidence resource %s", evidenceObjectKey(item))
	}
	return nil
}

func (plane *KubernetesFuzzEvidencePlane) applyMarker(
	ctx context.Context,
	network fuzzcorpus.ResourceIdentity,
	resources []fuzzcorpus.ResourceIdentity,
) (fuzzcorpus.ResourceIdentity, error) {
	view := make([]fuzzcorpus.ResourceIdentity, len(resources))
	copy(view, resources)
	sortIdentities(view)
	digest, err := canonical.ArtifactDigest(view)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	encodedInventory, err := canonical.Marshal(view)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	name := stableEvidenceName(network.Name, "attacknet-fuzz-evidence")
	marker := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{
			"name": name, "namespace": network.Namespace,
			"labels": map[string]any{
				"app.kubernetes.io/name":    "attacknet-fuzz-evidence",
				"app.kubernetes.io/part-of": "stacks-attacknet",
				evidenceNetworkLabel:        network.Name,
			},
			"ownerReferences": []any{map[string]any{
				"apiVersion": network.APIVersion, "kind": network.Kind,
				"name": network.Name, "uid": network.UID,
			}},
		},
		"data": map[string]any{
			"schemaVersion":   evidenceMarkerSchema,
			"networkUID":      network.UID,
			"inventoryDigest": digest,
			"resources.json":  string(encodedInventory),
		},
	}}
	gvr := evidenceKinds["v1/ConfigMap"]
	if err := plane.assertCreatable(ctx, gvr, marker, network); err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	encoded, err := json.Marshal(marker.Object)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	applied, err := plane.dynamic.Resource(gvr).Namespace(network.Namespace).Patch(
		ctx, name, types.ApplyPatchType, encoded, metav1.PatchOptions{FieldManager: evidenceFieldManager},
	)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, fmt.Errorf("apply evidence marker: %w", err)
	}
	return evidenceIdentity(applied), nil
}

func (plane *KubernetesFuzzEvidencePlane) verifyExpected(
	ctx context.Context,
	network fuzzcorpus.ResourceIdentity,
	expected []fuzzcorpus.ResourceIdentity,
) error {
	markerName := stableEvidenceName(network.Name, "attacknet-fuzz-evidence")
	markerFound := false
	for _, identity := range expected {
		if err := validateExactIdentity(identity); err != nil || identity.Namespace != network.Namespace {
			return errors.New("journal contains an invalid evidence resource identity")
		}
		gvr, err := gvrForIdentity(identity)
		if err != nil {
			return err
		}
		current, err := plane.dynamic.Resource(gvr).Namespace(identity.Namespace).Get(
			ctx, identity.Name, metav1.GetOptions{},
		)
		if err != nil {
			return fmt.Errorf("read journaled evidence resource %s/%s: %w", identity.Kind, identity.Name, err)
		}
		if string(current.GetUID()) != identity.UID || !ownedByNetwork(current, network) {
			return fmt.Errorf("journaled evidence resource %s/%s changed identity", identity.Kind, identity.Name)
		}
		if identity.Kind == "ConfigMap" && identity.Name == markerName {
			markerFound = true
			if value, _, _ := unstructured.NestedString(current.Object, "data", "networkUID"); value != network.UID {
				return errors.New("evidence marker network identity changed")
			}
		}
	}
	if !markerFound {
		return errors.New("journaled evidence plane has no completion marker")
	}
	return nil
}

func (plane *KubernetesFuzzEvidencePlane) waitReady(
	ctx context.Context, resources []fuzzcorpus.ResourceIdentity,
) error {
	timeout, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		ready := true
		for _, identity := range resources {
			if identity.Kind != "Deployment" && identity.Kind != "StatefulSet" && identity.Kind != "DaemonSet" {
				continue
			}
			gvr, err := gvrForIdentity(identity)
			if err != nil {
				return err
			}
			current, err := plane.dynamic.Resource(gvr).Namespace(identity.Namespace).Get(
				timeout, identity.Name, metav1.GetOptions{},
			)
			if err != nil || string(current.GetUID()) != identity.UID {
				if err != nil {
					return err
				}
				return errors.New("evidence workload identity changed while waiting for readiness")
			}
			if !evidenceWorkloadReady(current) {
				ready = false
			}
		}
		if ready {
			return nil
		}
		select {
		case <-timeout.Done():
			return errors.New("timed out waiting for the evidence plane to become ready")
		case <-time.After(time.Second):
		}
	}
}

// Release deletes only the exact identities journaled by Ensure.
func (plane *KubernetesFuzzEvidencePlane) Release(
	ctx context.Context, resources []fuzzcorpus.ResourceIdentity,
) error {
	if len(resources) == 0 {
		return errors.New("evidence resource identities are required")
	}
	ordered := append([]fuzzcorpus.ResourceIdentity(nil), resources...)
	sort.SliceStable(ordered, func(left, right int) bool {
		leftRank, rightRank := evidenceDeletionRank(ordered[left].Kind), evidenceDeletionRank(ordered[right].Kind)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return identityKey(ordered[left]) < identityKey(ordered[right])
	})
	for _, identity := range ordered {
		if err := validateExactIdentity(identity); err != nil {
			return err
		}
		gvr, err := gvrForIdentity(identity)
		if err != nil {
			return err
		}
		client := plane.dynamic.Resource(gvr).Namespace(identity.Namespace)
		current, err := client.Get(ctx, identity.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if string(current.GetUID()) != identity.UID {
			return fmt.Errorf("refusing to delete replaced evidence resource %s/%s", identity.Kind, identity.Name)
		}
		options := uidBoundDeleteOptions(current.GetUID(), metav1.DeletePropagationForeground)
		if err := client.Delete(ctx, identity.Name, options); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete evidence resource %s/%s: %w", identity.Kind, identity.Name, err)
		}
	}
	return plane.waitAbsent(ctx, ordered)
}

func (plane *KubernetesFuzzEvidencePlane) waitAbsent(
	ctx context.Context, resources []fuzzcorpus.ResourceIdentity,
) error {
	timeout, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		remaining := false
		for _, identity := range resources {
			gvr, _ := gvrForIdentity(identity)
			_, err := plane.dynamic.Resource(gvr).Namespace(identity.Namespace).Get(timeout, identity.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return err
			}
			remaining = true
		}
		if !remaining {
			return nil
		}
		select {
		case <-timeout.Done():
			return errors.New("timed out deleting the evidence plane")
		case <-time.After(time.Second):
		}
	}
}

func validateEvidenceObject(
	object *unstructured.Unstructured, network fuzzcorpus.ResourceIdentity,
) (schema.GroupVersionResource, error) {
	if object == nil || object.GetName() == "" || object.GetGenerateName() != "" ||
		object.GetNamespace() != network.Namespace || object.GetLabels()[evidenceNetworkLabel] != network.Name ||
		object.GetLabels()["app.kubernetes.io/part-of"] != "stacks-attacknet" {
		return schema.GroupVersionResource{}, errors.New("renderer returned an unscoped evidence resource")
	}
	gvr, found := evidenceKinds[object.GetAPIVersion()+"/"+object.GetKind()]
	if !found {
		return schema.GroupVersionResource{}, fmt.Errorf("renderer returned unsupported evidence kind %s/%s", object.GetAPIVersion(), object.GetKind())
	}
	return gvr, nil
}

func validateExactIdentity(identity fuzzcorpus.ResourceIdentity) error {
	if identity.APIVersion == "" || identity.Kind == "" || identity.Namespace == "" ||
		identity.Name == "" || identity.UID == "" {
		return errors.New("exact Kubernetes resource identity is required")
	}
	return nil
}

func gvrForIdentity(identity fuzzcorpus.ResourceIdentity) (schema.GroupVersionResource, error) {
	gvr, found := evidenceKinds[identity.APIVersion+"/"+identity.Kind]
	if !found {
		return schema.GroupVersionResource{}, fmt.Errorf("unsupported evidence identity kind %s/%s", identity.APIVersion, identity.Kind)
	}
	return gvr, nil
}

func ownedByNetwork(object *unstructured.Unstructured, network fuzzcorpus.ResourceIdentity) bool {
	for _, owner := range object.GetOwnerReferences() {
		if owner.APIVersion == network.APIVersion && owner.Kind == network.Kind &&
			owner.Name == network.Name && string(owner.UID) == network.UID {
			return true
		}
	}
	return false
}

func evidenceWorkloadReady(object *unstructured.Unstructured) bool {
	generation := object.GetGeneration()
	observed, _, _ := unstructured.NestedInt64(object.Object, "status", "observedGeneration")
	if observed < generation {
		return false
	}
	switch object.GetKind() {
	case "Deployment":
		replicas, _, _ := unstructured.NestedInt64(object.Object, "spec", "replicas")
		available, _, _ := unstructured.NestedInt64(object.Object, "status", "availableReplicas")
		return replicas > 0 && available >= replicas
	case "StatefulSet":
		replicas, _, _ := unstructured.NestedInt64(object.Object, "spec", "replicas")
		ready, _, _ := unstructured.NestedInt64(object.Object, "status", "readyReplicas")
		return replicas > 0 && ready >= replicas
	case "DaemonSet":
		desired, _, _ := unstructured.NestedInt64(object.Object, "status", "desiredNumberScheduled")
		ready, _, _ := unstructured.NestedInt64(object.Object, "status", "numberReady")
		return desired > 0 && ready >= desired
	default:
		return true
	}
}

func evidenceIdentity(object *unstructured.Unstructured) fuzzcorpus.ResourceIdentity {
	return fuzzcorpus.ResourceIdentity{
		APIVersion: object.GetAPIVersion(), Kind: object.GetKind(),
		Namespace: object.GetNamespace(), Name: object.GetName(),
		UID: string(object.GetUID()), ResourceVersion: object.GetResourceVersion(),
	}
}

func evidenceObjectKey(object *unstructured.Unstructured) string {
	return object.GetAPIVersion() + "/" + object.GetKind() + "/" + object.GetNamespace() + "/" + object.GetName()
}

func identityKey(identity fuzzcorpus.ResourceIdentity) string {
	return identity.APIVersion + "/" + identity.Kind + "/" + identity.Namespace + "/" + identity.Name
}

func sortIdentities(identities []fuzzcorpus.ResourceIdentity) {
	sort.Slice(identities, func(left, right int) bool { return identityKey(identities[left]) < identityKey(identities[right]) })
}

func evidenceDeletionRank(kind string) int {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return 0
	case "Service", "NetworkPolicy", "RoleBinding":
		return 1
	case "ConfigMap", "Secret", "ServiceAccount", "Role":
		return 2
	case "PersistentVolumeClaim":
		return 3
	default:
		return 4
	}
}

func stableEvidenceName(network, suffix string) string {
	candidate := network + "-" + suffix
	if len(candidate) <= 63 {
		return candidate
	}
	digest := sha256.Sum256([]byte(candidate))
	return strings.TrimRight(candidate[:54], "-") + "-" + hex.EncodeToString(digest[:4])
}
