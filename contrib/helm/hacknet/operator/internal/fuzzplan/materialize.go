package fuzzplan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const fuzzLabelPrefix = "testing.stacks.org/"

// MaterializedTrial contains ordinary controller-owned resources for one
// source, confirmation, or reduction attempt.
type MaterializedTrial struct {
	Policies         []attacknetv1beta1.BurnchainPolicy `json:"policies"`
	FaultTemplates   []attacknetv1beta1.FaultCampaign   `json:"faultTemplates,omitempty"`
	UpgradeTemplates []attacknetv1beta1.UpgradeCampaign `json:"upgradeTemplates,omitempty"`
	Network          attacknetv1beta1.StacksNetwork     `json:"network"`
	Run              attacknetv1beta1.AttacknetRun      `json:"run"`
}

// MaterializeTrial renders one explicit trial without contacting Kubernetes.
func MaterializeTrial(
	descriptor Descriptor,
	ordinal int32,
	attemptID, attemptKind, namespace string,
) (MaterializedTrial, error) {
	if descriptor.SchemaVersion != DescriptorSchema ||
		descriptor.MaterializationAlgorithm != MaterializationAlgorithm || descriptor.Digest == "" ||
		namespace == "" || attemptID == "" ||
		attemptKind != "Source" && attemptKind != "Confirmation" && attemptKind != "Reduction" {
		return MaterializedTrial{}, errors.New("sealed descriptor, namespace, and valid attempt identity are required")
	}
	if ordinal < 1 || ordinal > int32(len(descriptor.Trials)) {
		return MaterializedTrial{}, errors.New("trial ordinal is outside the descriptor")
	}
	trial := descriptor.Trials[ordinal-1]
	if trial.Ordinal != ordinal || trial.DecisionDigest == "" {
		return MaterializedTrial{}, errors.New("descriptor trial identity is invalid")
	}
	networkName, err := FreshName(descriptor.SessionID, descriptor.Digest, ordinal, attemptID)
	if err != nil {
		return MaterializedTrial{}, err
	}
	labels := map[string]string{
		fuzzLabelPrefix + "fuzz-session":      descriptor.SessionID,
		fuzzLabelPrefix + "fuzz-trial":        strconv.Itoa(int(ordinal)),
		fuzzLabelPrefix + "fuzz-attempt":      attemptID,
		fuzzLabelPrefix + "fuzz-attempt-kind": strings.ToLower(attemptKind),
	}
	network := *descriptor.Network.Template.DeepCopy()
	network.TypeMeta = metav1.TypeMeta{
		APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork",
	}
	network.ObjectMeta = metav1.ObjectMeta{
		Name: networkName, Namespace: namespace, Labels: copyLabels(labels),
	}
	configureEvidenceProbe(&network)
	policyNames := make(map[string]string, len(descriptor.Network.Policies))
	policies := make([]attacknetv1beta1.BurnchainPolicy, 0, len(descriptor.Network.Policies))
	for index, source := range descriptor.Network.Policies {
		if source.Namespace != namespace {
			return MaterializedTrial{}, fmt.Errorf(
				"burnchain policy %s belongs to namespace %s, not %s",
				source.Name, source.Namespace, namespace,
			)
		}
		name := stableChildName(networkName, fmt.Sprintf("burn-%02d", index+1), 63)
		policyNames[source.Name] = name
		spec := *source.Spec.DeepCopy()
		spec.NetworkRef = networkName
		policies = append(policies, attacknetv1beta1.BurnchainPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: copyLabels(labels)},
			Spec:       spec,
		})
	}
	policyName, found := policyNames[network.Spec.Burnchain.PolicyRef.Name]
	if !found {
		return MaterializedTrial{}, errors.New("source network default burnchain policy was not resolved")
	}
	network.Spec.Burnchain.PolicyRef.Name = policyName
	for index := range network.Spec.Burnchain.Nodes {
		ref := network.Spec.Burnchain.Nodes[index].PolicyRef
		if ref == nil {
			continue
		}
		name, found := policyNames[ref.Name]
		if !found {
			return MaterializedTrial{}, fmt.Errorf("source network burnchain policy %s was not resolved", ref.Name)
		}
		ref.Name = name
	}
	resolved := make(map[string]ResolvedTemplate, len(descriptor.Templates))
	for _, template := range descriptor.Templates {
		if template.Namespace != namespace {
			return MaterializedTrial{}, fmt.Errorf(
				"template %s belongs to namespace %s, not %s",
				template.ID, template.Namespace, namespace,
			)
		}
		resolved[template.ID] = template
	}
	run := attacknetv1beta1.AttacknetRun{
		TypeMeta: metav1.TypeMeta{
			APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: stableChildName(networkName, "run", 63), Namespace: namespace, Labels: copyLabels(labels),
		},
		Spec: attacknetv1beta1.AttacknetRunSpec{
			NetworkRef: networkName, Seed: trial.Seed,
			DecisionAlgorithm: "dependency-trigger-scheduler/v1",
			Replay: attacknetv1beta1.ReplaySpec{
				RequireSameResolvedImages: true, VerifyExpectedFailure: true,
			},
			Resume: attacknetv1beta1.ResumeSpec{
				RequireSameSeed: true, RequireSameResolvedImages: true,
			},
			Minimization: attacknetv1beta1.MinimizationSpec{
				Strategy: "DeltaDebug", RequireFreshNetwork: true,
			},
			Budgets: descriptor.Run.Budgets, StopPolicy: descriptor.Run.StopPolicy,
			AttributionPolicy:  descriptor.Run.AttributionPolicy,
			BaselineAssertions: copyAssertionSet(descriptor.Run.BaselineAssertions),
			DuringAssertions:   copyAssertionSet(descriptor.Run.DuringAssertions),
			RecoveryAssertions: copyAssertionSet(descriptor.Run.RecoveryAssertions),
			FuzzProvenance: &attacknetv1beta1.FuzzProvenance{
				SessionDigest: descriptor.Digest, TrialOrdinal: ordinal,
				PlanDigest: descriptor.PlanDigest, DecisionDigest: trial.DecisionDigest,
				AttemptID: attemptID, AttemptKind: attemptKind,
			},
		},
	}
	executionByTemplate := make(map[string]string, len(trial.Executions))
	faultTemplateNames := make(map[string]string, len(trial.Executions))
	upgradeTemplateNames := make(map[string]string, len(trial.Executions))
	faultTemplates := make([]attacknetv1beta1.FaultCampaign, 0, len(trial.Executions))
	upgradeTemplates := make([]attacknetv1beta1.UpgradeCampaign, 0, len(trial.Executions))
	for _, execution := range trial.Executions {
		template, found := resolved[execution.Template]
		if !found || template.Kind != execution.Kind {
			return MaterializedTrial{}, fmt.Errorf(
				"trial execution %s references an unknown or mismatched template",
				execution.ID,
			)
		}
		dependencies := make([]attacknetv1beta1.RunExecutionDependency, 0, len(template.Requires))
		for _, required := range template.Requires {
			prior, selected := executionByTemplate[required]
			if !selected {
				return MaterializedTrial{}, fmt.Errorf(
					"trial execution %s requires unselected or later template %s",
					execution.ID, required,
				)
			}
			dependencies = append(dependencies, attacknetv1beta1.RunExecutionDependency{
				Execution: prior, State: "Terminal",
			})
		}
		spec := attacknetv1beta1.RunExecutionSpec{
			ID: execution.ID, Trigger: *execution.Trigger.DeepCopy(),
			DependsOn: dependencies,
		}
		switch template.Kind {
		case "FaultCampaign":
			spec.Campaign = template.ID
			name, exists := faultTemplateNames[template.ID]
			if !exists {
				name = stableChildName(networkName, "fault-"+template.ID, 63)
				faultTemplateNames[template.ID] = name
				materialized := attacknetv1beta1.FaultCampaign{
					TypeMeta: metav1.TypeMeta{
						APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "FaultCampaign",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: name, Namespace: namespace, Labels: copyLabels(labels),
					},
					Spec: *template.FaultSpec.DeepCopy(),
				}
				materialized.Spec.Template = true
				materialized.Spec.NetworkRef = ""
				faultTemplates = append(faultTemplates, materialized)
				run.Spec.CampaignCatalog = append(run.Spec.CampaignCatalog,
					attacknetv1beta1.CampaignCatalogEntry{
						Name: template.ID, CampaignRef: name,
						ExpectedSpecDigest: template.SpecDigest,
					})
			}
		case "UpgradeCampaign":
			spec.Upgrade = template.ID
			name, exists := upgradeTemplateNames[template.ID]
			if !exists {
				name = stableChildName(networkName, "upgrade-"+template.ID, 63)
				upgradeTemplateNames[template.ID] = name
				materialized := attacknetv1beta1.UpgradeCampaign{
					TypeMeta: metav1.TypeMeta{
						APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "UpgradeCampaign",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: name, Namespace: namespace, Labels: copyLabels(labels),
					},
					Spec: *template.UpgradeSpec.DeepCopy(),
				}
				materialized.Spec.Template = true
				materialized.Spec.NetworkRef = ""
				upgradeTemplates = append(upgradeTemplates, materialized)
				run.Spec.UpgradeCatalog = append(run.Spec.UpgradeCatalog,
					attacknetv1beta1.UpgradeCatalogEntry{
						Name: template.ID, UpgradeRef: name,
						ExpectedSpecDigest: template.SpecDigest,
					})
			}
		default:
			return MaterializedTrial{}, fmt.Errorf("unsupported template kind %s", template.Kind)
		}
		run.Spec.Executions = append(run.Spec.Executions, spec)
		executionByTemplate[template.ID] = execution.ID
	}
	return MaterializedTrial{
		Policies: policies, FaultTemplates: faultTemplates,
		UpgradeTemplates: upgradeTemplates, Network: network, Run: run,
	}, nil
}

func configureEvidenceProbe(network *attacknetv1beta1.StacksNetwork) {
	if network.Spec.Probe == nil || network.Spec.Probe.Enabled == nil || !*network.Spec.Probe.Enabled {
		return
	}
	services := network.Spec.Probe.AdditionalServices[:0]
	for _, service := range network.Spec.Probe.AdditionalServices {
		if service.Name != "prometheus" {
			services = append(services, service)
		}
	}
	network.Spec.Probe.AdditionalServices = append(services, attacknetv1beta1.ProbeService{
		Name: "prometheus", ServiceName: EvidencePrometheusServiceName(network.Name),
		Ports: []attacknetv1beta1.ProbePort{{Name: "http", Port: 9090}},
	})
}

// EvidencePrometheusServiceName returns the exact evidence endpoint published
// to an attempt's trusted probe configuration.
func EvidencePrometheusServiceName(network string) string {
	return stableChildName(network, "attacknet-prometheus", 52)
}

func stableChildName(parent, child string, limit int) string {
	candidate := parent + "-" + child
	if len(candidate) <= limit {
		return candidate
	}
	digest := sha256.Sum256([]byte(candidate))
	prefix := strings.TrimRight(candidate[:limit-9], "-")
	return prefix + "-" + hex.EncodeToString(digest[:4])
}

// FreshName derives a bounded attempt name from immutable inputs.
func FreshName(sessionID, sessionDigest string, ordinal int32, attemptID string) (string, error) {
	if problems := kubevalidation.IsDNS1123Label(sessionID); len(problems) != 0 ||
		!digestPattern.MatchString(sessionDigest) ||
		ordinal < 1 || ordinal > 256 ||
		len(kubevalidation.IsDNS1123Label(attemptID)) != 0 {
		return "", errors.New("invalid fresh-network identity inputs")
	}
	suffix := fmt.Sprintf("-%03d-%s-%s", ordinal, attemptID, sessionDigest[7:15])
	maximumPrefix := 63 - len(suffix)
	if maximumPrefix < 1 {
		return "", errors.New("attempt identity cannot fit a DNS label")
	}
	prefix := sessionID
	if len(prefix) > maximumPrefix {
		prefix = strings.TrimRight(prefix[:maximumPrefix], "-")
	}
	name := prefix + suffix
	if len(kubevalidation.IsDNS1123Label(name)) != 0 {
		return "", errors.New("derived fresh-network name is invalid")
	}
	return name, nil
}

func copyLabels(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func copyAssertionSet(value *attacknetv1beta1.ProtocolAssertionSetSpec) *attacknetv1beta1.ProtocolAssertionSetSpec {
	if value == nil {
		return nil
	}
	return value.DeepCopy()
}
