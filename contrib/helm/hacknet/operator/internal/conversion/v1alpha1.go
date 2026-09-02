// Package conversion provides explicit, offline API migration helpers.
package conversion

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/document"
)

// UnsupportedKindError explains why a legacy resource cannot be converted
// without operator-specific or lossy policy choices.
type UnsupportedKindError struct {
	Kind   string
	Reason string
}

// Error implements error.
func (err UnsupportedKindError) Error() string {
	return fmt.Sprintf("cannot convert v1alpha1 %s: %s", err.Kind, err.Reason)
}

type typeEnvelope struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// V1Alpha1Document converts one strictly decoded v1alpha1 single-fault
// FaultCampaign or serial AttacknetRun into its v1beta1 representation.
// StacksNetwork conversion is deliberately refused because the aggregate
// v1beta1 topology requires policy decisions that are not present in v1alpha1.
func V1Alpha1Document(data []byte) (runtime.Object, error) {
	envelope, topLevel, err := envelope(data)
	if err != nil {
		return nil, err
	}
	if envelope.APIVersion != attacknetv1alpha1.GroupVersion.String() {
		return nil, fmt.Errorf("apiVersion must be %s", attacknetv1alpha1.GroupVersion)
	}
	if _, present := topLevel["status"]; present {
		return nil, errors.New("legacy input must omit the controller-owned status field")
	}
	switch envelope.Kind {
	case "FaultCampaign":
		var source attacknetv1alpha1.FaultCampaign
		if err := document.DecodeOne(data, &source); err != nil {
			return nil, err
		}
		if err := validatePortableMetadata(source.ObjectMeta); err != nil {
			return nil, err
		}
		return FaultCampaign(&source)
	case "AttacknetRun":
		var source attacknetv1alpha1.AttacknetRun
		if err := document.DecodeOne(data, &source); err != nil {
			return nil, err
		}
		if err := validatePortableMetadata(source.ObjectMeta); err != nil {
			return nil, err
		}
		return AttacknetRun(&source)
	case "StacksNetwork":
		return nil, UnsupportedKindError{Kind: envelope.Kind, Reason: "the high-level topology, signer-set, burnchain-policy, and configuration-source choices have no lossless v1alpha1 mapping"}
	default:
		return nil, UnsupportedKindError{Kind: envelope.Kind, Reason: "only FaultCampaign and AttacknetRun have bounded compatibility mappings"}
	}
}

// FaultCampaign converts one legacy single-fault campaign to one v1beta1
// stage and action without weakening any safety limit.
func FaultCampaign(source *attacknetv1alpha1.FaultCampaign) (*attacknetv1beta1.FaultCampaign, error) {
	if source == nil {
		return nil, errors.New("source FaultCampaign is required")
	}
	signerLimit, err := percentToBasisPoints(source.Spec.Safety.MaxUnavailableSignerPercent)
	if err != nil {
		return nil, fmt.Errorf("maxUnavailableSignerPercent: %w", err)
	}
	minerLimit, err := percentToBasisPoints(source.Spec.Safety.MaxUnavailableMinerPercent)
	if err != nil {
		return nil, fmt.Errorf("maxUnavailableMinerPercent: %w", err)
	}
	duration, err := time.ParseDuration(source.Spec.Fault.Duration)
	if err != nil || duration <= 0 {
		return nil, fmt.Errorf("fault duration %q must be a positive Go duration", source.Spec.Fault.Duration)
	}
	result := &attacknetv1beta1.FaultCampaign{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "FaultCampaign"},
		ObjectMeta: portableMetadata(source.ObjectMeta),
		Spec: attacknetv1beta1.FaultCampaignSpec{
			Template: source.Spec.Template, NetworkRef: source.Spec.NetworkRef,
			Stages: []attacknetv1beta1.FaultStageSpec{{
				ID: "fault",
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "fault",
					Target: attacknetv1beta1.FaultTarget{
						Actors: append([]string(nil), source.Spec.Target.Actors...),
						Roles:  append([]string(nil), source.Spec.Target.Roles...),
					},
					Fault: attacknetv1beta1.FaultSpec{
						Type: source.Spec.Fault.Type, Action: source.Spec.Fault.Action,
						Mode: source.Spec.Fault.Mode, Value: cloneIntOrString(source.Spec.Fault.Value),
						Duration: metav1.Duration{Duration: duration}, Parameters: *source.Spec.Fault.Parameters.DeepCopy(),
					},
				}},
			}},
			Safety: attacknetv1beta1.FaultSafety{
				MaxUnavailableSignerBasisPoints: signerLimit,
				MaxUnavailableMinerBasisPoints:  minerLimit,
				MaxConcurrentFaults:             1,
				AllowQuorumLoss:                 source.Spec.Safety.AllowQuorumLoss,
				AllowBurnchain:                  source.Spec.Safety.AllowBurnchain,
				AllowExtendedDuration:           source.Spec.Safety.AllowExtendedDuration,
				AllowExtremeSeverity:            source.Spec.Safety.AllowExtremeSeverity,
				AllowMinerMajorityOutage:        source.Spec.Safety.AllowMinerMajorityOutage,
				AllowUnenrolledTargets:          source.Spec.Safety.AllowUnenrolledTargets,
			},
			EffectAssertions:   convertAssertions(source.Spec.EffectAssertions),
			RecoveryAssertions: convertAssertions(source.Spec.RecoveryAssertions),
		},
	}
	return result, nil
}

// AttacknetRun converts the legacy serial sequence into explicit terminal
// dependencies. A non-zero delay on the final enabled instruction is refused
// because v1alpha1 charged it to the wall-time budget despite having no next
// execution to delay, and v1beta1 has no equivalent semantic.
func AttacknetRun(source *attacknetv1alpha1.AttacknetRun) (*attacknetv1beta1.AttacknetRun, error) {
	if source == nil {
		return nil, errors.New("source AttacknetRun is required")
	}
	result := &attacknetv1beta1.AttacknetRun{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun"},
		ObjectMeta: portableMetadata(source.ObjectMeta),
		Spec: attacknetv1beta1.AttacknetRunSpec{
			NetworkRef: source.Spec.NetworkRef, Seed: source.Spec.Seed,
			DecisionAlgorithm: source.Spec.DecisionAlgorithm,
			CampaignCatalog:   convertCatalog(source.Spec.CampaignCatalog),
			Budgets:           attacknetv1beta1.RunBudgets(source.Spec.Budgets),
			StopPolicy:        attacknetv1beta1.StopPolicy(source.Spec.StopPolicy),
			AttributionPolicy: attacknetv1beta1.AttributionPolicy{
				RequiredOnFailure:     source.Spec.AttributionPolicy.RequiredOnFailure,
				RequireIncidentBundle: source.Spec.AttributionPolicy.RequireIncidentBundle,
				AllowedTerminalStates: append([]string(nil), source.Spec.AttributionPolicy.AllowedTerminalStates...),
			},
			Replay: attacknetv1beta1.ReplaySpec(source.Spec.Replay),
			Resume: attacknetv1beta1.ResumeSpec{
				Enabled: source.Spec.Resume.Enabled, SourceRunRef: source.Spec.Resume.SourceRunRef,
				AfterExecutionID:          source.Spec.Resume.AfterInstructionID,
				RequireSameSeed:           source.Spec.Resume.RequireSameSeed,
				RequireSameResolvedImages: source.Spec.Resume.RequireSameResolvedImages,
			},
			Minimization: convertMinimization(source.Spec.Minimization),
		},
	}
	previousEnabled := -1
	for index := range source.Spec.Sequence {
		instruction := source.Spec.Sequence[index]
		execution := attacknetv1beta1.RunExecutionSpec{
			ID: instruction.ID, Campaign: instruction.Campaign, Enabled: cloneBool(instruction.Enabled),
		}
		if enabled(instruction.Enabled) {
			if previousEnabled >= 0 {
				prior := source.Spec.Sequence[previousEnabled]
				execution.DependsOn = []attacknetv1beta1.RunExecutionDependency{{
					Execution: prior.ID, State: "Terminal",
					Delay: metav1.Duration{Duration: time.Duration(prior.DelayAfterSeconds) * time.Second},
				}}
			}
			previousEnabled = index
		}
		result.Spec.Executions = append(result.Spec.Executions, execution)
	}
	if previousEnabled >= 0 && source.Spec.Sequence[previousEnabled].DelayAfterSeconds != 0 {
		return nil, fmt.Errorf("final enabled instruction %q has delayAfterSeconds=%d, whose legacy wall-time-budget semantics have no lossless v1beta1 mapping", source.Spec.Sequence[previousEnabled].ID, source.Spec.Sequence[previousEnabled].DelayAfterSeconds)
	}
	return result, nil
}

func envelope(data []byte) (typeEnvelope, map[string]json.RawMessage, error) {
	normalized, err := yaml.YAMLToJSON(data)
	if err != nil {
		return typeEnvelope{}, nil, fmt.Errorf("read legacy resource type: %w", err)
	}
	topLevel := map[string]json.RawMessage{}
	if err := json.Unmarshal(normalized, &topLevel); err != nil {
		return typeEnvelope{}, nil, fmt.Errorf("read legacy resource envelope: %w", err)
	}
	var result typeEnvelope
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	if err := decoder.Decode(&result); err != nil {
		return typeEnvelope{}, nil, fmt.Errorf("decode legacy resource envelope: %w", err)
	}
	if result.APIVersion == "" || result.Kind == "" {
		return typeEnvelope{}, nil, errors.New("apiVersion and kind are required")
	}
	return result, topLevel, nil
}

func percentToBasisPoints(percent float64) (int32, error) {
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 || percent > 100 {
		return 0, fmt.Errorf("must be finite and within 0..100, got %v", percent)
	}
	value := percent * 100
	rounded := math.Round(value)
	if math.Abs(value-rounded) > 1e-9 {
		return 0, fmt.Errorf("%v cannot be represented exactly in integer basis points", percent)
	}
	return int32(rounded), nil
}

func convertAssertions(source []attacknetv1alpha1.CampaignAssertion) []attacknetv1beta1.CampaignAssertion {
	result := make([]attacknetv1beta1.CampaignAssertion, len(source))
	for index := range source {
		result[index] = attacknetv1beta1.CampaignAssertion{
			Type: source[index].Type, Actor: source[index].Actor,
			TimeoutSeconds: source[index].TimeoutSeconds,
		}
	}
	return result
}

func convertCatalog(source []attacknetv1alpha1.CampaignCatalogEntry) []attacknetv1beta1.CampaignCatalogEntry {
	result := make([]attacknetv1beta1.CampaignCatalogEntry, len(source))
	for index := range source {
		result[index] = attacknetv1beta1.CampaignCatalogEntry{
			Name: source[index].Name, CampaignRef: source[index].CampaignRef,
			ExpectedUID:        source[index].ExpectedUID,
			ExpectedGeneration: cloneInt64(source[index].ExpectedGeneration),
			ExpectedSpecDigest: source[index].ExpectedSpecDigest,
		}
	}
	return result
}

func convertMinimization(source attacknetv1alpha1.MinimizationSpec) attacknetv1beta1.MinimizationSpec {
	result := attacknetv1beta1.MinimizationSpec{
		Enabled: source.Enabled, Strategy: source.Strategy, MaxAttempts: source.MaxAttempts,
		RequireFreshNetwork: source.RequireFreshNetwork, SourceRunRef: source.SourceRunRef,
		SourceScheduleDigest: source.SourceScheduleDigest, AttemptID: source.AttemptID,
		CandidateDigest:   source.CandidateDigest,
		ExpectedAssertion: source.ExpectedAssertion, ExpectedStatus: source.ExpectedStatus,
	}
	for _, retained := range source.Retained {
		result.Retained = append(result.Retained, attacknetv1beta1.RetainedExecution{
			ExecutionID:       retained.InstructionID,
			RemovedTargets:    append([]string(nil), retained.RemovedTargets...),
			RemovedParameters: append([]string(nil), retained.RemovedParameters...),
		})
	}
	return result
}

func portableMetadata(source metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: source.Name, Namespace: source.Namespace,
		Labels: cloneMap(source.Labels), Annotations: cloneMap(source.Annotations),
	}
}

func validatePortableMetadata(source metav1.ObjectMeta) error {
	if source.UID != "" || source.ResourceVersion != "" || source.Generation != 0 ||
		!source.CreationTimestamp.IsZero() || source.DeletionTimestamp != nil ||
		len(source.ManagedFields) != 0 || len(source.OwnerReferences) != 0 || len(source.Finalizers) != 0 {
		return errors.New("legacy input must omit server-assigned and controller-owned metadata")
	}
	return nil
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func enabled(value *bool) bool { return value == nil || *value }

func cloneBool(source *bool) *bool {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}

func cloneInt64(source *int64) *int64 {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}

func cloneIntOrString(source *intstr.IntOrString) *intstr.IntOrString {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}
