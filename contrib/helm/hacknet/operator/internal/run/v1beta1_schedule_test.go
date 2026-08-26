package run

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
)

func betaScheduleFixture() (*attacknetv1beta1.AttacknetRun, *attacknetv1beta1.StacksNetwork, attacknetv1beta1.NetworkInventory, map[string]*attacknetv1beta1.FaultCampaign, fault.Manifest) {
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid"), Generation: 3}}
	inventory := attacknetv1beta1.NetworkInventory{Digest: "sha256:" + repeat("a", 64), ObservedGeneration: 3, Actors: []attacknetv1beta1.AdmittedActorIdentity{{Name: "miner-1", Role: "miner", RequestedImage: "node:test", RuntimeImageID: "containerd://sha256:" + repeat("b", 64)}}}
	value := intstr.FromInt32(1)
	template := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "partition", Namespace: "test", UID: types.UID("template-uid"), Generation: 2},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			Template: true, NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{ID: "partition", Faults: []attacknetv1beta1.FaultActionSpec{{ID: "miner", Target: attacknetv1beta1.FaultTarget{Actors: []string{"miner-1"}, Mode: "count", Value: &value}, Fault: attacknetv1beta1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: metav1.Duration{Duration: 10 * time.Second}}}}}},
			Safety: attacknetv1beta1.FaultSafety{MaxConcurrentFaults: 1, MaxUnavailableMinerBasisPoints: 10_000, AllowMinerMajorityOutage: true},
		},
	}
	run := &attacknetv1beta1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", UID: types.UID("run-uid"), Generation: 1},
		Spec: attacknetv1beta1.AttacknetRunSpec{
			NetworkRef: "network", Seed: "seed", DecisionAlgorithm: betaDecisionAlgorithm,
			CampaignCatalog: []attacknetv1beta1.CampaignCatalogEntry{{Name: "partition", CampaignRef: "partition"}},
			Executions:      []attacknetv1beta1.RunExecutionSpec{{ID: "first", Campaign: "partition"}, {ID: "second", Campaign: "partition", DependsOn: []attacknetv1beta1.RunExecutionDependency{{Execution: "first", State: "Terminal"}}}},
			Budgets:         attacknetv1beta1.RunBudgets{MaxCampaigns: 2, MaxWallTimeSeconds: 120, MaxCumulativeFaultSeconds: 30, MaxActiveFaults: 1, MaxSignerImpactPercent: 30, MaxBurnchainFaults: 0, MaxInconclusiveCampaigns: 1},
			StopPolicy: attacknetv1beta1.StopPolicy{
				OnCampaignFailure: "Stop", OnInconclusive: "Stop", OnBudgetExhausted: "Stop", OnSuccess: "Continue",
			},
			AttributionPolicy: attacknetv1beta1.AttributionPolicy{
				RequiredOnFailure: true, RequireIncidentBundle: true,
				AllowedTerminalStates: []string{"Triaged", "Remediated", "Inconclusive"},
			},
		},
	}
	manifest := fault.Manifest{Network: "network", Actors: []fault.ManifestActor{{Name: "miner-1", Role: "miner"}}}
	return run, network, inventory, map[string]*attacknetv1beta1.FaultCampaign{"partition": template}, manifest
}

func TestBetaScheduleRoundTripPinsDAGAndTemplates(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	schedule, err := buildBetaSchedule(run, network, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if schedule.SchemaVersion != betaScheduleSchema || len(schedule.Executions) != 2 || schedule.Executions[1].Dependencies[0].Execution != "first" {
		t.Fatalf("schedule did not preserve the DAG: %#v", schedule)
	}
	if schedule.Network.ManifestDigest == "" {
		t.Fatal("schedule did not bind the admitted manifest")
	}
	encoded, err := encodeBetaSchedule(schedule)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBetaSchedule(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Integrity.Digest != schedule.Integrity.Digest || decoded.Executions[0].CampaignSpecDigest == "" {
		t.Fatalf("schedule round trip lost immutable inputs: %#v", decoded)
	}
	encoded[len(encoded)/2] ^= 0xff
	if _, err := decodeBetaSchedule(encoded); err == nil {
		t.Fatal("corrupt beta schedule decoded")
	}
}

func TestBetaScheduleBindsPortableTemplateToAdmittedNetwork(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	templates["partition"].Spec.NetworkRef = ""
	schedule, err := buildBetaSchedule(run, network, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, execution := range schedule.Executions {
		if execution.CampaignSpec.Template || execution.CampaignSpec.NetworkRef != run.Spec.NetworkRef {
			t.Fatalf("portable template was not bound in the sealed execution: %#v", execution.CampaignSpec)
		}
	}
}

func TestBetaScheduleRejectsInvalidPolicies(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	run.Spec.StopPolicy.OnCampaignFailure = "Maybe"
	if _, err := buildBetaSchedule(run, network, admitted, templates, manifest); err == nil {
		t.Fatal("unsupported stop policy was accepted")
	}
	run, network, admitted, templates, manifest = betaScheduleFixture()
	run.Spec.AttributionPolicy.AllowedTerminalStates = []string{"Passed"}
	if _, err := buildBetaSchedule(run, network, admitted, templates, manifest); err == nil {
		t.Fatal("unsupported attribution terminal state was accepted")
	}
}

func TestBetaReplayRejectsChangedSourceTemplateIdentity(t *testing.T) {
	source := []betaExecution{{ID: "one", Source: sourceIdentity{Name: "template", UID: "old", Generation: 1, SpecDigest: "sha256:old"}}}
	candidate := []betaExecution{{ID: "one", Source: sourceIdentity{Name: "template", UID: "new", Generation: 2, SpecDigest: "sha256:new"}}}
	if err := validateBetaSourceTemplates(source, candidate); err == nil {
		t.Fatal("replay accepted a changed source template identity")
	}
}

func TestBetaScheduleRejectsForwardDependencyAndCampaignOverBudget(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	run.Spec.Executions[0].DependsOn = []attacknetv1beta1.RunExecutionDependency{{Execution: "second", State: "Terminal"}}
	if _, err := buildBetaSchedule(run, network, admitted, templates, manifest); err == nil {
		t.Fatal("forward DAG dependency was accepted")
	}
	run, network, admitted, templates, manifest = betaScheduleFixture()
	run.Spec.Budgets.MaxActiveFaults = 0
	if _, err := buildBetaSchedule(run, network, admitted, templates, manifest); err == nil {
		t.Fatal("invalid active-fault budget was accepted")
	}
}

func TestBetaMinimizationIsRemovalOnly(t *testing.T) {
	_, _, _, templates, _ := betaScheduleFixture()
	spec := templates["partition"].Spec
	if _, _, err := minimizeBetaCampaign(spec, attacknetv1beta1.RetainedExecution{ExecutionID: "first"}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := minimizeBetaCampaign(spec, attacknetv1beta1.RetainedExecution{ExecutionID: "first", RemovedStages: []string{"partition"}}); err == nil || changed {
		t.Fatalf("removing the entire campaign was accepted: changed=%t err=%v", changed, err)
	}
	if _, err := minimizedBetaExecutions([]betaExecution{{ID: "first", CampaignSpec: spec}}, []attacknetv1beta1.RetainedExecution{{ExecutionID: "first"}}); err == nil {
		t.Fatal("non-material minimization was accepted")
	}
}

func TestBetaBudgetCountsOnlyMutatingChildrenAsActiveFaults(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	schedule, err := buildBetaSchedule(run, network, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	children := []attacknetv1beta1.FaultCampaign{
		betaBudgetChild(run, schedule, schedule.Executions[0], "Pending"),
		betaBudgetChild(run, schedule, schedule.Executions[1], "Admitted"),
	}
	usage, err := betaBudgetUsage(children, schedule, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.ActiveCampaigns != 2 || usage.ActiveFaults != 0 {
		t.Fatalf("queued campaigns were misreported as concurrent mutations: %#v", usage)
	}
	children[0].Status.Phase = "Injecting"
	usage, err = betaBudgetUsage(children, schedule, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.ActiveFaults != schedule.Executions[0].MaximumActiveFaults {
		t.Fatalf("mutating campaign fault budget was not counted: %#v", usage)
	}
}

func TestBetaReservedImpactAggregatesEveryNonterminalChild(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	schedule, err := buildBetaSchedule(run, network, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	schedule.Executions[0].SignerImpactBasisPoints = 1_200
	schedule.Executions[1].SignerImpactBasisPoints = 1_800
	children := []attacknetv1beta1.FaultCampaign{
		betaBudgetChild(run, schedule, schedule.Executions[0], "Pending"),
		betaBudgetChild(run, schedule, schedule.Executions[1], "Running"),
	}
	faults, signerImpact, err := betaReservedImpact(children, schedule, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if faults != 2 || signerImpact != 3_000 {
		t.Fatalf("nonterminal reservations were not cumulative: faults=%d signerImpact=%d", faults, signerImpact)
	}
	faults, signerImpact, err = betaReservedImpact(children, schedule, map[string]bool{"first": true})
	if err != nil {
		t.Fatal(err)
	}
	if faults != 1 || signerImpact != 1_800 {
		t.Fatalf("completed reservation was not released: faults=%d signerImpact=%d", faults, signerImpact)
	}
}

func TestBetaScheduleRejectsOverlappingClockMutationAcrossCampaigns(t *testing.T) {
	executions := []betaExecution{
		{ID: "first"},
		{ID: "second"},
	}
	clockTargets := map[string]map[string]struct{}{
		"first":  {"signer-1": {}},
		"second": {"signer-1": {}},
	}
	if err := validateBetaCrossExecutionCompatibility(executions, clockTargets); err == nil {
		t.Fatal("overlapping clock-policy mutations for the same actor were accepted")
	}
	executions[1].Dependencies = []attacknetv1beta1.RunExecutionDependency{{Execution: "first", State: "Terminal"}}
	if err := validateBetaCrossExecutionCompatibility(executions, clockTargets); err != nil {
		t.Fatalf("terminally ordered clock mutations were rejected: %v", err)
	}
	executions[1].Dependencies[0].State = "Effective"
	if err := validateBetaCrossExecutionCompatibility(executions, clockTargets); err == nil {
		t.Fatal("effect-triggered overlapping clock mutations were accepted")
	}
	clockTargets["second"] = map[string]struct{}{"signer-2": {}}
	if err := validateBetaCrossExecutionCompatibility(executions, clockTargets); err != nil {
		t.Fatalf("independent actor clock mutations were rejected: %v", err)
	}
}

func betaBudgetChild(run *attacknetv1beta1.AttacknetRun, schedule betaSchedule, execution betaExecution, phase string) attacknetv1beta1.FaultCampaign {
	return attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{
			Name:        betaChildName(run.Name, execution.ID),
			Annotations: map[string]string{betaExecutionAnnotation: execution.ID, betaScheduleAnnotation: schedule.Integrity.Digest},
		},
		Spec:   *execution.CampaignSpec.DeepCopy(),
		Status: attacknetv1beta1.FaultCampaignStatus{Phase: phase},
	}
}
