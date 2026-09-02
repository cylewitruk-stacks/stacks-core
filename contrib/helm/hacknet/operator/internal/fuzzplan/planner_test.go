package fuzzplan

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestFuzzNetworkRequiresDigestBoundExternalConfiguration(t *testing.T) {
	network := testResolvedInput(t).Network.Template
	network.Spec.Nodes = []attacknetv1beta1.StacksNodeSpec{{
		Name: "follower", Config: attacknetv1beta1.ConfigSource{
			ConfigMapRef: &attacknetv1beta1.ConfigObjectRef{Name: "follower-config"},
		},
	}}
	err := validateNetworkConfigurationBoundary(network)
	if err == nil || !strings.Contains(err.Error(), "requires expectedDigest") {
		t.Fatalf("unsealed external config error = %v", err)
	}
	network.Spec.Nodes[0].Config.ExpectedDigest = "sha256:" + strings.Repeat("a", 64)
	if err := validateNetworkConfigurationBoundary(network); err != nil {
		t.Fatalf("digest-bound external config rejected: %v", err)
	}
}

func TestFuzzNetworkRejectsUnsealedAdvancedEnvironmentSource(t *testing.T) {
	network := testResolvedInput(t).Network.Template
	network.Spec.Nodes = []attacknetv1beta1.StacksNodeSpec{{
		Name: "follower",
		Advanced: &attacknetv1beta1.AdvancedWorkloadOverride{Env: []corev1.EnvVar{{
			Name: "RUNTIME_POLICY", ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "mutable-policy"}, Key: "value"},
			},
		}}},
	}}
	err := validateNetworkConfigurationBoundary(network)
	if err == nil || !strings.Contains(err.Error(), "unsealed valueFrom") {
		t.Fatalf("unsealed environment error = %v", err)
	}
}

func TestCompileIsStableAcrossInputOrderingAndCarriesAdvisory(t *testing.T) {
	input := testResolvedInput(t)
	first, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Plan.Templates[0], input.Plan.Templates[2] =
		input.Plan.Templates[2], input.Plan.Templates[0]
	input.Templates[0], input.Templates[2] =
		input.Templates[2], input.Templates[0]
	input.PlanDigest, err = PlanDigest(input.Plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("input ordering changed descriptor: %s != %s", first.Digest, second.Digest)
	}
	if want := "sha256:45dd3ab988c52bc269d522a44658e474a720fce34a551374a240b92bec7f9de2"; first.Digest != want {
		t.Fatalf("descriptor compatibility vector changed: got %s, want %s", first.Digest, want)
	}
	if first.Trials[0].AdvisoryDigest == "" ||
		first.Trials[0].Executions[0].Template != "alpha" {
		t.Fatalf("advisory was not retained or applied: %#v", first.Trials[0])
	}
	for _, trial := range first.Trials {
		if trial.DecisionDigest == "" || len(trial.Receipts) != 5 {
			t.Fatalf("trial is not fully receipted: %#v", trial)
		}
		for _, receipt := range trial.Receipts {
			if receipt.Digest == "" || receipt.CandidateSetDigest == "" ||
				receipt.Selected == "" {
				t.Fatalf("decision receipt is incomplete: %#v", receipt)
			}
		}
	}
}

func TestAdvisorySealCompatibilityVector(t *testing.T) {
	sealed, err := SealAdvisory(AdvisoryArtifact{
		SchemaVersion: "stacks-attacknet-advisory/v1", TrialOrdinal: 1,
		Candidates: []AdvisoryCandidate{
			{ID: "beta", Score: 1, Rationale: "bounded secondary choice"},
			{ID: "alpha", Score: 10, Rationale: "bounded preferred choice"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:58f51cec23674efc8accad74a4475d5061fdcc83e2ca54e84b0b806cfde03e4d"
	if sealed.Digest != expected {
		t.Fatalf("advisory digest = %s, want %s", sealed.Digest, expected)
	}
}

func TestCompileDifferentSeedChangesInstructions(t *testing.T) {
	input := testResolvedInput(t)
	first, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Plan.Seed = "different-seed"
	input.PlanDigest, err = PlanDigest(input.Plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest ||
		first.Trials[0].DecisionDigest == second.Trials[0].DecisionDigest {
		t.Fatal("different seed did not change deterministic instructions")
	}
}

func TestVerifyDescriptorRejectsReceiptsReboundToDifferentContext(t *testing.T) {
	descriptor, err := Compile(testResolvedInput(t))
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Trials[0].Receipts[0].ContextDigest = "sha256:" + strings.Repeat("0", 64)
	if err := sealReceipt(&descriptor.Trials[0].Receipts[0]); err != nil {
		t.Fatal(err)
	}
	descriptor.Trials[0].DecisionDigest, err = canonical.Digest(descriptor.Trials[0].Receipts)
	if err != nil {
		t.Fatal(err)
	}
	view := descriptor
	view.Digest = ""
	descriptor.Digest, err = canonical.Digest(view)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDescriptor(descriptor); err == nil ||
		!strings.Contains(err.Error(), "differs from deterministic replay") {
		t.Fatalf("got %v, want deterministic-replay rejection", err)
	}
}

func TestVerifyDescriptorRejectsResealedSemanticContradictions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Descriptor) error
	}{
		{
			name: "execution differs from receipt",
			mutate: func(descriptor *Descriptor) error {
				descriptor.Trials[0].Executions[0].Template = "beta"
				descriptor.Trials[0].Executions[0].Kind = "FaultCampaign"
				return nil
			},
		},
		{
			name: "trial seed differs",
			mutate: func(descriptor *Descriptor) error {
				descriptor.Trials[0].Seed = strings.Repeat("0", 64)
				return nil
			},
		},
		{
			name: "advisory digest differs",
			mutate: func(descriptor *Descriptor) error {
				descriptor.Trials[0].AdvisoryDigest = ""
				return nil
			},
		},
		{
			name: "receipt is self-consistent but not selected by HMAC",
			mutate: func(descriptor *Descriptor) error {
				receipt := &descriptor.Trials[0].Receipts[1]
				receipt.Selected = "beta"
				if err := sealReceipt(receipt); err != nil {
					return err
				}
				digest, err := canonical.Digest(descriptor.Trials[0].Receipts)
				descriptor.Trials[0].DecisionDigest = digest
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := Compile(testResolvedInput(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyDescriptor(descriptor); err != nil {
				t.Fatalf("valid descriptor rejected before mutation: %v", err)
			}
			if err := test.mutate(&descriptor); err != nil {
				t.Fatal(err)
			}
			if err := resealDescriptor(&descriptor); err != nil {
				t.Fatal(err)
			}
			if err := VerifyDescriptor(descriptor); err == nil ||
				!strings.Contains(err.Error(), "differs from deterministic replay") {
				t.Fatalf("got %v, want deterministic-replay rejection", err)
			}
		})
	}
}

func TestCompileAvoidsSeededConstraintDeadEnds(t *testing.T) {
	for seed := 0; seed < 64; seed++ {
		input := testResolvedInput(t)
		input.Plan.Seed = "completion-seed-" + strconv.Itoa(seed)
		input.Plan.MaxTrials = 1
		input.Plan.Advisories = nil
		input.Advisories = nil
		input.Plan.Templates[0].ConflictGroups = []string{"exclusive"}
		input.Plan.Templates[1].Requires = []string{"alpha"}
		input.Plan.Templates[2].ConflictGroups = []string{"exclusive"}
		input.Templates[0].ConflictGroups = []string{"exclusive"}
		input.Templates[1].Requires = []string{"alpha"}
		input.Templates[2].ConflictGroups = []string{"exclusive"}
		var err error
		input.PlanDigest, err = PlanDigest(input.Plan)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := Compile(input)
		if err != nil {
			t.Fatalf("satisfiable plan failed for seed %d: %v", seed, err)
		}
		if got := descriptor.Trials[0].Executions[0].Template; got != "alpha" {
			t.Fatalf("seed %d selected dead-end template %s", seed, got)
		}
	}
}

func TestCompileUnlocksExactDependencyChain(t *testing.T) {
	for seed := 0; seed < 64; seed++ {
		input := testResolvedInput(t)
		input.Plan.Seed = "dependency-chain-seed-" + strconv.Itoa(seed)
		input.Plan.MaxTrials = 1
		input.Plan.Generation.MinExecutions = 3
		input.Plan.Generation.MaxExecutions = 3
		input.Plan.Advisories = nil
		input.Advisories = nil
		input.Plan.Templates[1].Requires = []string{"alpha"}
		input.Plan.Templates[2].Requires = []string{"beta"}
		input.Templates[1].Requires = []string{"alpha"}
		input.Templates[2].Requires = []string{"beta"}
		var err error
		input.PlanDigest, err = PlanDigest(input.Plan)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := Compile(input)
		if err != nil {
			t.Fatalf("dependency chain failed for seed %d: %v", seed, err)
		}
		got := []string{
			descriptor.Trials[0].Executions[0].Template,
			descriptor.Trials[0].Executions[1].Template,
			descriptor.Trials[0].Executions[2].Template,
		}
		if !reflect.DeepEqual(got, []string{"alpha", "beta", "gamma"}) {
			t.Fatalf("seed %d dependency order = %v", seed, got)
		}
	}
}

func TestVerifyDescriptorRechecksGenerationBounds(t *testing.T) {
	descriptor, err := Compile(testResolvedInput(t))
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Generation.MaxExecutions = 65
	if err := resealDescriptor(&descriptor); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDescriptor(descriptor); err == nil ||
		!strings.Contains(err.Error(), "descriptor bounds are invalid") {
		t.Fatalf("got %v, want descriptor-bound rejection", err)
	}
}

func resealDescriptor(descriptor *Descriptor) error {
	view := *descriptor
	view.Digest = ""
	digest, err := canonical.Digest(view)
	descriptor.Digest = digest
	return err
}

func TestMaterializeTrialUsesOrdinaryResourcesAndFreshNames(t *testing.T) {
	descriptor, err := Compile(testResolvedInput(t))
	if err != nil {
		t.Fatal(err)
	}
	source, err := MaterializeTrial(descriptor, 1, "source", "Source", "hacknet-system")
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := MaterializeTrial(descriptor, 1, "confirm-1", "Confirmation", "hacknet-system")
	if err != nil {
		t.Fatal(err)
	}
	if source.Network.Name == confirmation.Network.Name || source.Run.Spec.NetworkRef != source.Network.Name {
		t.Fatal("attempts did not receive fresh bound network names")
	}
	services := source.Network.Spec.Probe.AdditionalServices
	if len(services) != 1 || services[0].Name != "prometheus" ||
		services[0].ServiceName != EvidencePrometheusServiceName(source.Network.Name) ||
		len(services[0].Ports) != 1 || services[0].Ports[0].Port != 9090 {
		t.Fatalf("fresh network probe lacks its exact evidence-plane endpoint: %#v", services)
	}
	if len(source.Policies) != 1 || source.Policies[0].Spec.NetworkRef != source.Network.Name ||
		source.Policies[0].Name != source.Network.Spec.Burnchain.PolicyRef.Name ||
		source.Policies[0].Name == confirmation.Policies[0].Name {
		t.Fatalf("attempt policies were not cloned and rebound: %#v", source.Policies)
	}
	if source.Run.Spec.FuzzProvenance == nil ||
		source.Run.Spec.FuzzProvenance.SessionDigest != descriptor.Digest ||
		source.Run.Spec.FuzzProvenance.DecisionDigest != descriptor.Trials[0].DecisionDigest {
		t.Fatalf("run lost immutable fuzz provenance: %#v", source.Run.Spec.FuzzProvenance)
	}
	if len(source.Run.Spec.Executions) != len(descriptor.Trials[0].Executions) ||
		len(source.Run.Spec.CampaignCatalog)+len(source.Run.Spec.UpgradeCatalog) != len(source.Run.Spec.Executions) {
		t.Fatalf("run does not materialize the selected universe: %#v", source.Run.Spec)
	}
	if len(source.FaultTemplates)+len(source.UpgradeTemplates) !=
		len(source.Run.Spec.CampaignCatalog)+len(source.Run.Spec.UpgradeCatalog) ||
		len(source.FaultTemplates) == 0 ||
		source.Run.Spec.CampaignCatalog[0].CampaignRef != source.FaultTemplates[0].Name ||
		source.Run.Spec.CampaignCatalog[0].ExpectedUID != "" ||
		source.FaultTemplates[0].Name == confirmation.FaultTemplates[0].Name {
		t.Fatalf("attempt-local portable templates were not materialized: %#v", source)
	}
	for _, catalog := range source.Run.Spec.CampaignCatalog {
		if catalog.CampaignRef == "alpha-template" || catalog.CampaignRef == "beta-template" ||
			catalog.ExpectedUID != "" || catalog.ExpectedGeneration != nil {
			t.Fatalf("run retained a planning-namespace template identity: %#v", catalog)
		}
	}
	if source.Run.Spec.Replay.Enabled || source.Run.Spec.Resume.Enabled || source.Run.Spec.Minimization.Enabled ||
		source.Run.Spec.Minimization.Strategy != "DeltaDebug" || !source.Run.Spec.Minimization.RequireFreshNetwork {
		t.Fatalf("source run lacks API-valid inert replay controls: %#v", source.Run.Spec.Minimization)
	}
}

func TestMaterializeTrialClonesPortableUpgradeTemplate(t *testing.T) {
	input := testResolvedInput(t)
	input.Plan.Templates = append([]TemplatePlan(nil), input.Plan.Templates[2])
	input.Plan.Generation.MinExecutions = 1
	input.Plan.Generation.MaxExecutions = 1
	input.Templates = append([]ResolvedTemplate(nil), input.Templates[2])
	input.Advisories = nil
	var err error
	input.PlanDigest, err = PlanDigest(input.Plan)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := MaterializeTrial(
		descriptor, 1, "source", "Source", "hacknet-system",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized.FaultTemplates) != 0 || len(materialized.UpgradeTemplates) != 1 ||
		len(materialized.Run.Spec.UpgradeCatalog) != 1 || len(materialized.Run.Spec.CampaignCatalog) != 0 {
		t.Fatalf("upgrade-only trial materialized the wrong template inventory: %#v", materialized)
	}
	template := materialized.UpgradeTemplates[0]
	catalog := materialized.Run.Spec.UpgradeCatalog[0]
	if template.Name == input.Templates[0].Name || !template.Spec.Template ||
		template.Spec.NetworkRef != "" || catalog.UpgradeRef != template.Name ||
		catalog.ExpectedUID != "" || catalog.ExpectedGeneration != nil ||
		catalog.ExpectedSpecDigest != input.Templates[0].SpecDigest {
		t.Fatalf("portable upgrade template was not cloned and rebound: template=%#v catalog=%#v", template, catalog)
	}
}

func TestMaterializeTrialBoundsRunNameForMaximumSessionName(t *testing.T) {
	input := testResolvedInput(t)
	input.Plan.SessionID = strings.Repeat("a", 63)
	input.PlanDigest, _ = PlanDigest(input.Plan)
	descriptor, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := MaterializeTrial(descriptor, 1, "source", "Source", "hacknet-system")
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized.Network.Name) > 63 || len(materialized.Run.Name) > 63 {
		t.Fatalf("derived names exceed DNS limits: %q %q", materialized.Network.Name, materialized.Run.Name)
	}
}

func TestMaterializeTrialKeepsDescriptorIdentityInLongChildNames(t *testing.T) {
	firstInput := testResolvedInput(t)
	firstInput.Plan.SessionID = strings.Repeat("a", 63)
	firstInput.PlanDigest, _ = PlanDigest(firstInput.Plan)
	first, err := Compile(firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := testResolvedInput(t)
	secondInput.Plan.SessionID = firstInput.Plan.SessionID
	secondInput.Plan.Seed = "another-sealed-seed"
	secondInput.PlanDigest, _ = PlanDigest(secondInput.Plan)
	second, err := Compile(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	firstResources, err := MaterializeTrial(first, 1, "source", "Source", "hacknet-system")
	if err != nil {
		t.Fatal(err)
	}
	secondResources, err := MaterializeTrial(second, 1, "source", "Source", "hacknet-system")
	if err != nil {
		t.Fatal(err)
	}
	if firstResources.Network.Name == secondResources.Network.Name ||
		firstResources.Run.Name == secondResources.Run.Name ||
		firstResources.Policies[0].Name == secondResources.Policies[0].Name ||
		firstResources.FaultTemplates[0].Name == secondResources.FaultTemplates[0].Name {
		t.Fatalf("distinct descriptor identities collided:\nfirst=%#v\nsecond=%#v", firstResources, secondResources)
	}
}

func TestResolvedTemplateDriftFailsBeforePlanning(t *testing.T) {
	input := testResolvedInput(t)
	input.Templates[0].UID = "replacement"
	if _, err := Compile(input); err == nil ||
		!strings.Contains(err.Error(), "violates expected identity") {
		t.Fatalf("got %v, want identity rejection", err)
	}
}

func TestResolvedBurnchainPolicyDriftFailsBeforePlanning(t *testing.T) {
	input := testResolvedInput(t)
	input.Network.Policies[0].Spec.Cadence.Duration++
	if _, err := Compile(input); err == nil || !strings.Contains(err.Error(), "specification digest mismatch") {
		t.Fatalf("got %v, want policy-drift rejection", err)
	}
}

func TestDescriptorPreservesFullInt64GenesisBalances(t *testing.T) {
	input := testResolvedInput(t)
	input.Network.Template.Spec.Genesis = &attacknetv1beta1.StacksGenesisSpec{
		Balances: []attacknetv1beta1.GenesisBalanceSpec{{
			Address: "ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H",
			Amount:  10_000_000_000_000_000,
		}},
	}
	var err error
	input.Network.TemplateDigest, err = NetworkTemplateDigest(input.Network.Template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Descriptor
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDescriptor(decoded); err != nil {
		t.Fatalf("full-int64 descriptor did not round trip: %v", err)
	}
}

func TestMaterializeTrialRebindsEveryIndependentBurnchainPolicy(t *testing.T) {
	input := testResolvedInput(t)
	input.Network.Template.Spec.Burnchain.Nodes = append(
		input.Network.Template.Spec.Burnchain.Nodes,
		attacknetv1beta1.BitcoinNodeSpec{
			Name: "bitcoin-2", PolicyRef: &attacknetv1beta1.NamedObjectReference{Name: "network-template-clock-2"},
		},
	)
	spec := attacknetv1beta1.BurnchainPolicySpec{
		NetworkRef: "network-template", BitcoinNodeRef: "bitcoin-2",
	}
	digest, err := canonical.ArtifactDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	input.Network.Policies = append(input.Network.Policies, ResolvedPolicy{
		Name: "network-template-clock-2", Namespace: "hacknet-system", UID: "clock-2-uid",
		Generation: 1, SpecDigest: digest, Spec: spec,
	})
	input.Network.TemplateDigest, err = NetworkTemplateDigest(input.Network.Template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := MaterializeTrial(descriptor, 1, "source", "Source", "hacknet-system")
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized.Policies) != 2 ||
		materialized.Policies[0].Spec.NetworkRef != materialized.Network.Name ||
		materialized.Policies[1].Spec.NetworkRef != materialized.Network.Name ||
		materialized.Network.Spec.Burnchain.PolicyRef.Name ==
			materialized.Network.Spec.Burnchain.Nodes[1].PolicyRef.Name {
		t.Fatalf("independent burnchain policies were not rebound: %#v", materialized)
	}
}

func TestCompileFailsWhenUseBoundsCannotFillSession(t *testing.T) {
	input := testResolvedInput(t)
	for index := range input.Plan.Templates {
		input.Plan.Templates[index].MaxUses = 1
		input.Templates[index].MaxUses = 1
	}
	input.Plan.MaxTrials = 2
	input.PlanDigest, _ = PlanDigest(input.Plan)
	if _, err := Compile(input); err == nil ||
		!strings.Contains(err.Error(), "cannot satisfy") {
		t.Fatalf("got %v, want bounded exhaustion", err)
	}
}

func TestValidatePlanRejectsUnboundedAndUnknownDependencies(t *testing.T) {
	input := testResolvedInput(t)
	input.Plan.MaxTrials = 0
	if err := ValidatePlan(input.Plan); err == nil {
		t.Fatal("zero trials were accepted")
	}
	input = testResolvedInput(t)
	input.Plan.Templates[0].Requires = []string{"unknown"}
	if err := ValidatePlan(input.Plan); err == nil ||
		!strings.Contains(err.Error(), "requires unknown") {
		t.Fatalf("got %v, want unknown requirement rejection", err)
	}
	input = testResolvedInput(t)
	input.Plan.Run.AttributionPolicy.AllowedTerminalStates = []string{"Failed"}
	if err := ValidatePlan(input.Plan); err == nil ||
		!strings.Contains(err.Error(), "unsupported allowed terminal state") {
		t.Fatalf("got %v, want run-policy rejection", err)
	}
}

func testResolvedInput(t *testing.T) ResolvedInput {
	t.Helper()
	templates := []TemplatePlan{
		{ID: "alpha", Kind: "FaultCampaign", Name: "alpha-template", Weight: 3, MaxUses: 10, ExpectedUID: "alpha-uid"},
		{ID: "beta", Kind: "FaultCampaign", Name: "beta-template", Weight: 2, MaxUses: 10, ExpectedUID: "beta-uid"},
		{ID: "gamma", Kind: "UpgradeCampaign", Name: "gamma-template", Weight: 1, MaxUses: 10, ExpectedUID: "gamma-uid"},
	}
	plan := Plan{
		SchemaVersion: PlanSchema, SessionID: "session-one", Seed: "seed-one",
		MaxTrials: 2, MaxDuration: metav1.Duration{Duration: time.Hour},
		Network:   NetworkPlan{TemplateFile: "network.yaml"},
		Templates: templates,
		Generation: GenerationPlan{
			MinExecutions: 2, MaxExecutions: 2,
			Triggers: []attacknetv1beta1.RunTriggerSpec{
				{},
				{AfterRunStart: &metav1.Duration{Duration: 5 * time.Second}},
			},
		},
		Run: RunPlan{
			Budgets: attacknetv1beta1.RunBudgets{
				MaxCampaigns: 4, MaxWallTimeSeconds: 600,
				MaxCumulativeFaultSeconds: 300, MaxActiveFaults: 4,
				MaxSignerImpactPercent: 30, MaxBurnchainFaults: 1,
				MaxInconclusiveCampaigns: 1,
			},
			StopPolicy: attacknetv1beta1.StopPolicy{
				OnCampaignFailure: "Stop", OnInconclusive: "PauseForTriage",
				OnBudgetExhausted: "Stop", OnSuccess: "Continue",
			},
			AttributionPolicy: attacknetv1beta1.AttributionPolicy{
				RequiredOnFailure: true, RequireIncidentBundle: true,
				AllowedTerminalStates: []string{"Triaged", "Remediated", "Inconclusive"},
			},
		},
		Confirmation: ConfirmationPlan{RequiredMatches: 2, MaxAttempts: 3},
		Reduction: ReductionPlan{
			Enabled: true, MaxAttempts: 32,
			MaxDuration:      metav1.Duration{Duration: 2 * time.Hour},
			MaxEvidenceBytes: 1 << 30,
		},
		Capacity: CapacityPlan{
			MinimumNodeBytes: 1 << 30, MinimumImageBytes: 1 << 30,
			MinimumCorpusBytes: 1 << 30, StorageEscrowBytes: 1 << 20,
			EvidenceEscrowBytes: 1 << 20, RequirePhysicalEscrow: true,
		},
		Corpus: CorpusPlan{Root: "corpus", MaximumBytes: 1 << 40},
	}
	planDigest, err := PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	probeEnabled := true
	network := attacknetv1beta1.StacksNetwork{
		TypeMeta: metav1.TypeMeta{
			APIVersion: attacknetv1beta1.GroupVersion.String(),
			Kind:       "StacksNetwork",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "network-template", Namespace: "hacknet-system"},
		Spec: attacknetv1beta1.StacksNetworkSpec{Probe: &attacknetv1beta1.ProbeSpec{Enabled: &probeEnabled}, Burnchain: attacknetv1beta1.BurnchainTopologySpec{
			PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "network-template-clock"},
			Nodes:     []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin"}},
		}},
	}
	networkDigest, err := NetworkTemplateDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	policySpec := attacknetv1beta1.BurnchainPolicySpec{
		NetworkRef: "network-template", BitcoinNodeRef: "bitcoin",
	}
	policyDigest, err := canonical.ArtifactDigest(policySpec)
	if err != nil {
		t.Fatal(err)
	}
	resolved := make([]ResolvedTemplate, 0, len(templates))
	for _, template := range templates {
		item := ResolvedTemplate{
			ID: template.ID, Kind: template.Kind, Name: template.Name,
			Namespace: "hacknet-system", UID: template.ExpectedUID,
			Generation: 1,
			Weight:     template.Weight, MaxUses: template.MaxUses,
		}
		if template.Kind == "FaultCampaign" {
			item.FaultSpec = &attacknetv1beta1.FaultCampaignSpec{}
			item.SpecDigest, err = canonical.ArtifactDigest(*item.FaultSpec)
		} else {
			item.UpgradeSpec = &attacknetv1beta1.UpgradeCampaignSpec{}
			item.SpecDigest, err = canonical.ArtifactDigest(*item.UpgradeSpec)
		}
		if err != nil {
			t.Fatal(err)
		}
		resolved = append(resolved, item)
	}
	advisory, err := SealAdvisory(AdvisoryArtifact{
		SchemaVersion: "stacks-attacknet-advisory/v1", TrialOrdinal: 1,
		Candidates: []AdvisoryCandidate{
			{ID: "beta", Score: 1, Rationale: "bounded secondary choice"},
			{ID: "alpha", Score: 10, Rationale: "bounded preferred choice"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ResolvedInput{
		Plan: plan, PlanDigest: planDigest,
		Network: ResolvedNetwork{TemplateDigest: networkDigest, Template: network, Policies: []ResolvedPolicy{{
			Name: "network-template-clock", Namespace: "hacknet-system", UID: "clock-uid",
			Generation: 1, SpecDigest: policyDigest, Spec: policySpec,
		}}},
		Templates: resolved, Advisories: []AdvisoryArtifact{advisory},
	}
}
