package run

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/document"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
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
	run.Labels = map[string]string{"testing.stacks.org/fuzz-session": "session"}
	run.Spec.FuzzProvenance = &attacknetv1beta1.FuzzProvenance{
		SessionDigest: "sha256:" + repeat("c", 64), TrialOrdinal: 2,
		PlanDigest:     "sha256:" + repeat("d", 64),
		DecisionDigest: "sha256:" + repeat("e", 64),
		AttemptID:      "source", AttemptKind: "Source",
	}
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
	if schedule.Run.FuzzProvenance == nil ||
		schedule.Run.FuzzProvenance.DecisionDigest != run.Spec.FuzzProvenance.DecisionDigest {
		t.Fatal("schedule did not bind fuzz provenance")
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

func TestValidateFuzzProvenanceFailsClosed(t *testing.T) {
	run, _, _, _, _ := betaScheduleFixture()
	run.Labels = map[string]string{"testing.stacks.org/fuzz-session": "session"}
	run.Spec.FuzzProvenance = &attacknetv1beta1.FuzzProvenance{
		SessionDigest: "sha256:" + repeat("a", 64), TrialOrdinal: 1,
		PlanDigest:     "sha256:" + repeat("b", 64),
		DecisionDigest: "sha256:" + repeat("c", 64),
		AttemptID:      "source", AttemptKind: "Source",
	}
	if err := ValidateV1Beta1Structure(run); err != nil {
		t.Fatal(err)
	}
	delete(run.Labels, "testing.stacks.org/fuzz-session")
	if err := ValidateV1Beta1Structure(run); err == nil {
		t.Fatal("fuzz provenance without its bounded session label was accepted")
	}
	run.Labels["testing.stacks.org/fuzz-session"] = "session"
	run.Spec.FuzzProvenance.DecisionDigest = "mutable"
	if err := ValidateV1Beta1Structure(run); err == nil {
		t.Fatal("invalid fuzz provenance was accepted")
	}
}

func TestBetaScheduleComposesUpgradeAndFaultExecutions(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	network.Spec.Nodes = []attacknetv1beta1.StacksNodeSpec{{Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner}}
	upgrade := &attacknetv1beta1.UpgradeCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "upgrade", UID: types.UID("upgrade-template"), Generation: 1},
		Spec: attacknetv1beta1.UpgradeCampaignSpec{
			Template: true, NetworkRef: "network",
			Profiles: []attacknetv1beta1.UpgradeProfileSpec{{Name: "next", Image: "node:next", ImageID: "sha256:" + repeat("c", 64), ProvenanceDigest: "sha256:" + repeat("d", 64), ConfigDigest: "sha256:" + repeat("e", 64), SourceKind: "prebuilt"}},
			Stages:   []attacknetv1beta1.UpgradeStageSpec{{Name: "miner", StableFor: metav1.Duration{Duration: time.Second}, Deadline: metav1.Duration{Duration: time.Minute}, Assignments: []attacknetv1beta1.UpgradeAssignment{{Actor: "miner-1", Profile: "next"}}}},
			Safety:   attacknetv1beta1.UpgradeSafetySpec{MaxParallelActors: 1, MaxMinerPercent: 100}, RollbackOnFailure: true,
		},
	}
	run.Spec.UpgradeCatalog = []attacknetv1beta1.UpgradeCatalogEntry{{Name: "next", UpgradeRef: "upgrade"}}
	run.Spec.Executions = []attacknetv1beta1.RunExecutionSpec{
		{ID: "upgrade", Upgrade: "next"},
		{ID: "partition", Campaign: "partition", DependsOn: []attacknetv1beta1.RunExecutionDependency{{Execution: "upgrade", State: "Terminal"}}},
	}
	schedule, err := buildBetaSchedule(run, network, admitted, templates, manifest, map[string]*attacknetv1beta1.UpgradeCampaign{"upgrade": upgrade})
	if err != nil {
		t.Fatal(err)
	}
	if schedule.Executions[0].Kind != "UpgradeCampaign" || schedule.Executions[0].UpgradeSpec == nil || schedule.Executions[1].Kind != "FaultCampaign" {
		t.Fatalf("mixed schedule lost typed children: %#v", schedule.Executions)
	}
	if schedule.Executions[0].CampaignSpecDigest == "" || schedule.Executions[0].Source.SpecDigest == "" {
		t.Fatal("upgrade execution was not immutably bound")
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

func TestBetaScheduleRoundTripPreservesSignerBehaviorContract(t *testing.T) {
	run, network, admitted, _, _ := betaScheduleFixture()
	policy := &attacknetv1beta1.AdversarialSignerPolicy{
		Profile: adversarial.ProfileV1, Behavior: "withhold", MaxMatches: 1, MaxEvaluations: 8,
		PatchDigest: "sha256:" + repeat("c", 64),
		Observer:    attacknetv1beta1.AdversarialObserverSpec{Image: "probe:test"},
		Egress:      attacknetv1beta1.AdversarialEgressSpec{Profile: "restricted"},
	}
	network.Spec.SignerSets = []attacknetv1beta1.SignerSetSpec{{Name: "active", Members: []attacknetv1beta1.SignerMemberSpec{{Name: "signer-1", NodeName: "signer-node-1", Index: 1, Weight: 1, Adversarial: policy}}}}
	_, policyDigest, err := adversarial.ResolveSigner(network, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	network.Status.Actors = []attacknetv1beta1.ActorStatus{{
		Name: "signer-1", Role: "signer", AdversarialPolicyDigest: policyDigest,
	}}
	template := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "withhold", Namespace: "test", UID: types.UID("withhold-template"), Generation: 1},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			Template: true, NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{ID: "observe", Faults: []attacknetv1beta1.FaultActionSpec{{
				ID: "signer", Target: attacknetv1beta1.FaultTarget{Actors: []string{"signer-1"}, Mode: "all"},
				Fault: attacknetv1beta1.FaultSpec{Type: "signer-behavior", Action: "withhold", Mode: "all", Duration: metav1.Duration{Duration: 10 * time.Second}, SignerBehavior: &attacknetv1beta1.SignerBehaviorFaultSpec{PolicyDigest: policyDigest}},
			}}}},
			Safety: attacknetv1beta1.FaultSafety{MaxConcurrentFaults: 1, MaxUnavailableSignerBasisPoints: 10_000},
		},
	}
	run.Spec.CampaignCatalog = []attacknetv1beta1.CampaignCatalogEntry{{Name: "withhold", CampaignRef: "withhold"}}
	run.Spec.Executions = []attacknetv1beta1.RunExecutionSpec{{ID: "withhold", Campaign: "withhold"}}
	run.Spec.Budgets.MaxCampaigns = 1
	run.Spec.Budgets.MaxSignerImpactPercent = 100
	manifest := canonicalBetaManifest(network, map[string]float64{"signer-1": 1})
	if manifest.Actors[0].AdversarialBehavior != "withhold" || manifest.Actors[0].AdversarialPolicyDigest != policyDigest {
		t.Fatalf("v1beta1 manifest lost adversarial policy: %#v", manifest.Actors[0])
	}
	schedule, err := buildBetaSchedule(run, network, admitted, map[string]*attacknetv1beta1.FaultCampaign{"withhold": template}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeBetaSchedule(schedule)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBetaSchedule(encoded)
	if err != nil {
		t.Fatal(err)
	}
	faultSpec := decoded.Executions[0].CampaignSpec.Stages[0].Faults[0].Fault
	if faultSpec.SignerBehavior == nil || faultSpec.SignerBehavior.PolicyDigest != policyDigest || faultSpec.Action != "withhold" {
		t.Fatalf("sealed schedule lost signer behavior identity: %#v", faultSpec)
	}
}

func TestBitcoinSplitViewExamplesCompileWithinDeclaredBudgets(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..")
	var network attacknetv1beta1.StacksNetwork
	decodeExample(t, filepath.Join(root, "helm", "hacknet", "examples", "multi-bitcoin.yaml"), &network)
	network.UID, network.Generation = types.UID("network-uid"), 1

	compiledNetwork, err := topology.CompileV1Beta1(&network)
	if err != nil {
		t.Fatalf("compile public multi-Bitcoin topology: %v", err)
	}
	manifest := fault.ManifestFromNetwork(compiledNetwork)
	inventory := attacknetv1beta1.NetworkInventory{
		Digest: "sha256:" + repeat("a", 64), ObservedGeneration: network.Generation,
		Actors: make([]attacknetv1beta1.AdmittedActorIdentity, 0, len(compiledNetwork.Spec.Actors)),
	}
	for _, actor := range compiledNetwork.Spec.Actors {
		inventory.Actors = append(inventory.Actors, attacknetv1beta1.AdmittedActorIdentity{
			Name: actor.Name, Role: actor.Role, RequestedImage: actor.Image,
			RuntimeImageID: "containerd://sha256:" + repeat("b", 64),
		})
	}

	var campaign attacknetv1beta1.FaultCampaign
	decodeExample(t, filepath.Join(root, "attacknet", "examples", "campaigns", "bitcoin-competing-branches.yaml"), &campaign)
	campaign.UID, campaign.Generation = types.UID("campaign-uid"), 1
	var run attacknetv1beta1.AttacknetRun
	decodeExample(t, filepath.Join(root, "attacknet", "examples", "runs", "bitcoin-split-view.yaml"), &run)
	run.UID, run.Generation = types.UID("run-uid"), 1

	schedule, err := buildBetaSchedule(&run, &network, inventory, map[string]*attacknetv1beta1.FaultCampaign{campaign.Name: &campaign}, manifest)
	if err != nil {
		t.Fatalf("compile public Bitcoin split-view run: %v", err)
	}
	if len(schedule.Executions) != 1 || schedule.Executions[0].BurnchainFaults != 2 {
		t.Fatalf("split-view example resolved unexpected burnchain impact: %#v", schedule.Executions)
	}

	var delay attacknetv1beta1.FaultCampaign
	decodeExample(t, filepath.Join(root, "attacknet", "examples", "campaigns", "bitcoin-propagation-delay.yaml"), &delay)
	delay.Spec.NetworkRef = network.Name
	if _, err := fault.CompileV1Beta1(&delay, manifest); err != nil {
		t.Fatalf("compile public Bitcoin propagation-delay campaign: %v", err)
	}
}

func TestAdversarialSignerExamplesBindOneCanonicalPolicy(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..")
	var network attacknetv1beta1.StacksNetwork
	decodeExample(t, filepath.Join(root, "helm", "hacknet", "examples", "adversarial-signer.yaml"), &network)
	var campaign attacknetv1beta1.FaultCampaign
	decodeExample(t, filepath.Join(root, "attacknet", "examples", "campaigns", "signer-withhold-window.yaml"), &campaign)
	_, digest, err := adversarial.ResolveSigner(&network, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	bound := campaign.Spec.Stages[0].Faults[0].Fault.SignerBehavior
	if bound == nil || bound.PolicyDigest != digest {
		t.Fatalf("campaign digest %v does not bind rendered signer policy %s", bound, digest)
	}
}

func TestA12QualificationCampaignsBindCanonicalPolicies(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..")
	qualification := filepath.Join(root, "attacknet", "release", "amendments", "a12", "qualification")
	var network attacknetv1beta1.StacksNetwork
	decodeExample(t, filepath.Join(qualification, "network.yaml"), &network)

	loadCampaign := func(name string) attacknetv1beta1.FaultCampaign {
		t.Helper()
		var campaign attacknetv1beta1.FaultCampaign
		decodeExample(t, filepath.Join(qualification, name), &campaign)
		if !campaign.Spec.Template || campaign.Spec.NetworkRef != "" {
			t.Fatalf("%s must remain an inert campaign template", name)
		}
		return campaign
	}
	boundDigest := func(campaign attacknetv1beta1.FaultCampaign) string {
		t.Helper()
		return campaign.Spec.Stages[0].Faults[0].Fault.SignerBehavior.PolicyDigest
	}
	below := boundDigest(loadCampaign("below-quorum-campaign.yaml"))
	quorum := boundDigest(loadCampaign("quorum-loss-campaign.yaml"))
	for _, expected := range []struct {
		signer string
		digest string
	}{{"signer-1", below}, {"signer-2", quorum}, {"signer-3", quorum}} {
		_, digest, err := adversarial.ResolveSigner(&network, expected.signer)
		if err != nil {
			t.Fatal(err)
		}
		if digest != expected.digest {
			t.Fatalf("%s campaign digest %s does not bind policy %s", expected.signer, expected.digest, digest)
		}
	}
}

func decodeExample(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := document.DecodeOne(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
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

func TestBetaReplayAllowsFreshIdentityWithSameTemplateSpec(t *testing.T) {
	source := []betaExecution{{
		ID: "one", Kind: "FaultCampaign", CampaignAlias: "template",
		Source: sourceIdentity{Name: "source-template", UID: "old", Generation: 1, SpecDigest: "sha256:same"},
	}}
	candidate := []betaExecution{{
		ID: "one", Kind: "FaultCampaign", CampaignAlias: "template",
		Source: sourceIdentity{Name: "fresh-template", UID: "new", Generation: 1, SpecDigest: "sha256:same"},
	}}
	if err := validateBetaSourceTemplates(source, candidate); err != nil {
		t.Fatalf("replay rejected a fresh template with the same immutable spec: %v", err)
	}
}

func TestBetaReplayRejectsTemplateSpecDriftAndMissingAlias(t *testing.T) {
	source := []betaExecution{{
		ID: "one", Kind: "FaultCampaign", CampaignAlias: "template",
		Source: sourceIdentity{Name: "source-template", UID: "old", Generation: 1, SpecDigest: "sha256:source"},
	}}
	tests := []struct {
		name      string
		candidate []betaExecution
	}{
		{name: "spec drift", candidate: []betaExecution{{
			ID: "one", Kind: "FaultCampaign", CampaignAlias: "template",
			Source: sourceIdentity{Name: "fresh-template", UID: "new", Generation: 1, SpecDigest: "sha256:changed"},
		}}},
		{name: "missing alias", candidate: []betaExecution{{
			ID: "one", Kind: "FaultCampaign", CampaignAlias: "other",
			Source: sourceIdentity{Name: "fresh-template", UID: "new", Generation: 1, SpecDigest: "sha256:source"},
		}}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if err := validateBetaSourceTemplates(source, testCase.candidate); err == nil {
				t.Fatal("replay accepted template drift")
			}
		})
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
