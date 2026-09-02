// Package attacknetcli implements the host-side Attacknet command surface.
//
// The package submits and observes typed resources. It deliberately contains
// no controller phase transitions, fault admission, or recovery policy.
package attacknetcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/document"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	attacknetrun "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/run"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/upgrade"
)

// Kind describes one public Attacknet resource kind.
type Kind struct {
	Name           string
	Plural         string
	GVK            schema.GroupVersionKind
	GVR            schema.GroupVersionResource
	terminalPhases map[string]struct{}
	newObject      func() runtime.Object
}

var resourceKinds = []Kind{
	newKind("StacksNetwork", "stacksnetworks", func() runtime.Object { return &attacknetv1beta1.StacksNetwork{} }),
	newKind("BurnchainPolicy", "burnchainpolicies", func() runtime.Object { return &attacknetv1beta1.BurnchainPolicy{} }),
	newTerminalKind("FaultCampaign", "faultcampaigns", []string{"Passed", "Failed", "Inconclusive"}, func() runtime.Object { return &attacknetv1beta1.FaultCampaign{} }),
	newTerminalKind("UpgradeCampaign", "upgradecampaigns", []string{"Passed", "Failed", "Inconclusive"}, func() runtime.Object { return &attacknetv1beta1.UpgradeCampaign{} }),
	newTerminalKind("AttacknetRun", "attacknetruns", []string{"Passed", "Failed", "Inconclusive"}, func() runtime.Object { return &attacknetv1beta1.AttacknetRun{} }),
}

func newKind(name, plural string, constructor func() runtime.Object) Kind {
	return Kind{
		Name: name, Plural: plural,
		GVK:       attacknetv1beta1.GroupVersion.WithKind(name),
		GVR:       attacknetv1beta1.GroupVersion.WithResource(plural),
		newObject: constructor,
	}
}

func newTerminalKind(name, plural string, phases []string, constructor func() runtime.Object) Kind {
	kind := newKind(name, plural, constructor)
	kind.terminalPhases = make(map[string]struct{}, len(phases))
	for _, phase := range phases {
		kind.terminalPhases[phase] = struct{}{}
	}
	return kind
}

// HasTerminalContract reports whether the kind defines terminal phases.
func (kind Kind) HasTerminalContract() bool { return len(kind.terminalPhases) != 0 }

// IsTerminal reports whether phase is terminal for this kind.
func (kind Kind) IsTerminal(phase string) bool {
	_, terminal := kind.terminalPhases[phase]
	return terminal
}

// Kinds returns a defensive copy of the supported resource catalog.
func Kinds() []Kind {
	result := make([]Kind, len(resourceKinds))
	copy(result, resourceKinds)
	return result
}

// LookupKind resolves a singular kind or plural resource name.
func LookupKind(value string) (Kind, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, kind := range resourceKinds {
		if normalized == strings.ToLower(kind.Name) || normalized == strings.ToLower(kind.Plural) {
			return kind, nil
		}
	}
	return Kind{}, fmt.Errorf("unsupported Attacknet resource kind %q", value)
}

type typeEnvelope struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// DecodeSubmission strictly decodes one v1beta1 YAML or JSON resource.
// Server-owned metadata and status are refused instead of being discarded.
func DecodeSubmission(data []byte, defaultNamespace string) (*unstructured.Unstructured, Kind, error) {
	envelope, topLevel, err := submissionEnvelope(data)
	if err != nil {
		return nil, Kind{}, err
	}
	if envelope.APIVersion != attacknetv1beta1.GroupVersion.String() {
		return nil, Kind{}, fmt.Errorf("apiVersion must be %s", attacknetv1beta1.GroupVersion)
	}
	kind, err := LookupKind(envelope.Kind)
	if err != nil || envelope.Kind != kind.Name {
		if err != nil {
			return nil, Kind{}, err
		}
		return nil, Kind{}, fmt.Errorf("kind must use canonical spelling %s", kind.Name)
	}
	if _, present := topLevel["status"]; present {
		return nil, Kind{}, errors.New("submitted resources must omit the controller-owned status field")
	}

	object := kind.newObject()
	if err := document.DecodeOne(data, object); err != nil {
		return nil, Kind{}, err
	}
	if err := validateSubmissionStructure(object); err != nil {
		return nil, Kind{}, fmt.Errorf("validate %s spec: %w", kind.Name, err)
	}
	metadata, ok := object.(metav1.Object)
	if !ok {
		return nil, Kind{}, errors.New("decoded resource has no Kubernetes metadata")
	}
	if err := validateSubmissionMetadata(metadata, defaultNamespace); err != nil {
		return nil, Kind{}, err
	}
	metadata.SetNamespace(resolveNamespace(metadata.GetNamespace(), defaultNamespace))
	if network, ok := object.(*attacknetv1beta1.StacksNetwork); ok {
		if err := topology.ValidateV1Beta1(network); err != nil {
			return nil, Kind{}, fmt.Errorf("validate %s topology: %w", kind.Name, err)
		}
	}

	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil, Kind{}, fmt.Errorf("convert %s to Kubernetes object: %w", kind.Name, err)
	}
	// Go's JSON encoder does not omit a zero-valued struct solely because its
	// field has omitempty. The source status key was rejected above, so removing
	// the synthesized empty object preserves the submitted intent and keeps the
	// CLI away from the status subresource.
	delete(value, "status")
	for _, field := range []string{
		"uid", "resourceVersion", "generation", "creationTimestamp",
		"deletionTimestamp", "deletionGracePeriodSeconds", "managedFields",
	} {
		unstructured.RemoveNestedField(value, "metadata", field)
	}
	result := &unstructured.Unstructured{Object: value}
	result.SetGroupVersionKind(kind.GVK)
	return result, kind, nil
}

func validateSubmissionStructure(object runtime.Object) error {
	switch resource := object.(type) {
	case *attacknetv1beta1.FaultCampaign:
		return fault.ValidateV1Beta1Structure(resource)
	case *attacknetv1beta1.AttacknetRun:
		return attacknetrun.ValidateV1Beta1Structure(resource)
	case *attacknetv1beta1.UpgradeCampaign:
		return upgrade.ValidateStructure(resource)
	default:
		return nil
	}
}

func submissionEnvelope(data []byte) (typeEnvelope, map[string]json.RawMessage, error) {
	normalized, err := yaml.YAMLToJSON(data)
	if err != nil {
		return typeEnvelope{}, nil, fmt.Errorf("read resource type: %w", err)
	}
	topLevel := map[string]json.RawMessage{}
	if err := json.Unmarshal(normalized, &topLevel); err != nil {
		return typeEnvelope{}, nil, fmt.Errorf("read resource envelope: %w", err)
	}
	var envelope typeEnvelope
	if err := json.Unmarshal(normalized, &envelope); err != nil {
		return typeEnvelope{}, nil, fmt.Errorf("decode resource envelope: %w", err)
	}
	if envelope.APIVersion == "" || envelope.Kind == "" {
		return typeEnvelope{}, nil, errors.New("apiVersion and kind are required")
	}
	return envelope, topLevel, nil
}

func validateSubmissionMetadata(metadata metav1.Object, defaultNamespace string) error {
	if metadata.GetName() == "" {
		return errors.New("metadata.name is required; generateName is not supported")
	}
	if problems := kubevalidation.IsDNS1123Subdomain(metadata.GetName()); len(problems) != 0 {
		return fmt.Errorf("metadata.name is invalid: %s", strings.Join(problems, "; "))
	}
	if metadata.GetGenerateName() != "" {
		return errors.New("metadata.generateName is not supported")
	}
	if metadata.GetUID() != "" || metadata.GetResourceVersion() != "" || metadata.GetGeneration() != 0 ||
		!metadata.GetCreationTimestamp().Time.IsZero() || metadata.GetDeletionTimestamp() != nil ||
		len(metadata.GetManagedFields()) != 0 {
		return errors.New("submitted resources must omit server-assigned metadata")
	}
	if len(metadata.GetOwnerReferences()) != 0 || len(metadata.GetFinalizers()) != 0 {
		return errors.New("submitted resources must omit controller-owned ownerReferences and finalizers")
	}
	if namespace := resolveNamespace(metadata.GetNamespace(), defaultNamespace); len(kubevalidation.IsDNS1123Label(namespace)) != 0 {
		return fmt.Errorf("resource namespace %q is invalid", namespace)
	}
	return nil
}

func resolveNamespace(value, fallback string) string {
	if value != "" {
		return value
	}
	if fallback != "" {
		return fallback
	}
	return "default"
}

// EncodeResource writes one object as human YAML or stable indented JSON.
func EncodeResource(object *unstructured.Unstructured, format string) ([]byte, error) {
	encoded, err := json.MarshalIndent(object.Object, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode resource: %w", err)
	}
	switch strings.ToLower(format) {
	case "json":
		return append(encoded, '\n'), nil
	case "yaml", "yml", "":
		result, err := yaml.JSONToYAML(encoded)
		if err != nil {
			return nil, fmt.Errorf("encode resource YAML: %w", err)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("output format must be yaml or json, got %q", format)
	}
}
