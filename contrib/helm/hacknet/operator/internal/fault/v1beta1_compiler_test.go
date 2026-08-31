package fault

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestCompileV1Beta1EnforcesAggregateSignerSafety(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults = append(campaign.Spec.Stages[0].Faults, betaPodAction("stop-signer-2", "signer-2"))
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 3_000
	campaign.Spec.Safety.MaxConcurrentFaults = 2
	_, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err == nil || !strings.Contains(err.Error(), "aggregate signer impact 4000 basis points") {
		t.Fatalf("expected aggregate signer safety rejection, got %v", err)
	}
}

func TestCompileV1Beta1CountsSignerAndBoundNodeAsOneWeightUnit(t *testing.T) {
	campaign := betaCampaignFixture()
	manifest := betaManifestFixture()
	index, weight := int32(1), 1.0
	manifest.Actors = append(manifest.Actors, ManifestActor{
		Name: "signer-node-1", Role: "companion", SignerIndex: &index, SignerWeight: &weight,
	})
	compiled, err := CompileV1Beta1(campaign, manifest)
	if err != nil {
		t.Fatal(err)
	}
	impact := compiled.AggregateImpact
	if impact.SignerTotalWeight != 5 || impact.SignerAffectedWeight != 1 || impact.SignerAffectedBasisPoints != 2_000 {
		t.Fatalf("bound signer node was double-counted in aggregate safety: %#v", impact)
	}
}

func TestCompileV1Beta1TerminalBarrierPermitsSequentialStages(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages = append(campaign.Spec.Stages, attacknetv1beta1.FaultStageSpec{
		ID:      "second",
		Trigger: attacknetv1beta1.StageTriggerSpec{AfterStage: &attacknetv1beta1.StageDependency{Stage: "first", State: "Terminal"}},
		Faults:  []attacknetv1beta1.FaultActionSpec{betaPodAction("stop-signer-2", "signer-2")},
	})
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 2_500
	campaign.Spec.Safety.MaxConcurrentFaults = 1
	compiled, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.AggregateImpact.ConcurrentFaults != 1 || compiled.AggregateImpact.SignerAffectedBasisPoints != 2_000 {
		t.Fatalf("completed stage barrier did not bound overlap: %#v", compiled.AggregateImpact)
	}
}

func TestCompileV1Beta1EffectiveDependencyCanOverlap(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages = append(campaign.Spec.Stages, attacknetv1beta1.FaultStageSpec{
		ID:      "second",
		Trigger: attacknetv1beta1.StageTriggerSpec{AfterStage: &attacknetv1beta1.StageDependency{Stage: "first", State: "Effective"}},
		Faults:  []attacknetv1beta1.FaultActionSpec{betaPodAction("stop-signer-2", "signer-2")},
	})
	campaign.Spec.Safety.MaxConcurrentFaults = 1
	_, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err == nil || !strings.Contains(err.Error(), "aggregate concurrent faults 2") {
		t.Fatalf("expected overlapping-stage concurrency rejection, got %v", err)
	}
}

func TestCompileV1Beta1ProducesDistinctBoundedMutationNames(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Name = strings.Repeat("campaign", 10)
	campaign.Spec.Stages[0].Faults = append(campaign.Spec.Stages[0].Faults, betaPodAction("stop-signer-2", "signer-2"))
	campaign.Spec.Safety.MaxConcurrentFaults = 2
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 5_000
	compiled, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	left := compiled.Stages[0].Actions[0].Resource.GetName()
	right := compiled.Stages[0].Actions[1].Resource.GetName()
	if left == right || len(left) > 63 || len(right) > 63 {
		t.Fatalf("mutation names are not distinct bounded DNS labels: %q %q", left, right)
	}
}

func TestCompileV1Beta1RejectsUnsupportedCompletionPolicy(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].CompletionPolicy = "any"
	_, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err == nil || !strings.Contains(err.Error(), "completionPolicy must be all") {
		t.Fatalf("expected unsupported completion policy rejection, got %v", err)
	}
}

func TestCompileV1Beta1RejectsAssertionForUnknownAction(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.EffectAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "NetworkDegraded", Action: "missing"}}
	_, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err == nil || !strings.Contains(err.Error(), `assertion references unknown action "missing"`) {
		t.Fatalf("expected unknown assertion action rejection, got %v", err)
	}
}

func TestCompileV1Beta1BurnchainReorgIsOneSemanticWorker(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults[0] = attacknetv1beta1.FaultActionSpec{
		ID: "replace-tip", Target: attacknetv1beta1.FaultTarget{Actors: []string{"bitcoin-1"}, Mode: "one"},
		Fault: attacknetv1beta1.FaultSpec{
			Type: "burnchain-reorg", Mode: "one", Duration: metav1.Duration{Duration: time.Minute},
			BurnchainReorg: &attacknetv1beta1.BurnchainReorgFaultSpec{Depth: 6, ReplacementBlocks: 7, ReplacementInterval: metav1.Duration{Duration: time.Second}},
		},
	}
	campaign.Spec.Safety.AllowBurnchain = true
	campaign.Spec.Safety.MaxBurnchainReorgDepth = 6
	campaign.Spec.Safety.MaxBurnchainReplacementBlocks = 7
	manifest := betaManifestFixture()
	manifest.Actors = append(manifest.Actors, ManifestActor{Name: "bitcoin-1", Role: "burnchain"})
	compiled, err := CompileV1Beta1(campaign, manifest)
	if err != nil {
		t.Fatal(err)
	}
	action := compiled.Stages[0].Actions[0]
	if action.Resource.GetKind() != "BurnchainReorgWorker" || len(action.Evidence.SelectedActors) != 1 || action.Evidence.SelectedActors[0] != "bitcoin-1" {
		t.Fatalf("unexpected semantic worker: %#v", action)
	}
}

func TestCompileV1Beta1RejectsOverlappingReorgsOnOneBitcoinPolicy(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults = []attacknetv1beta1.FaultActionSpec{
		betaReorgAction("replace-a", "bitcoin-1"), betaReorgAction("replace-b", "bitcoin-1"),
	}
	campaign.Spec.Safety.AllowBurnchain = true
	campaign.Spec.Safety.MaxBurnchainReorgDepth = 2
	campaign.Spec.Safety.MaxBurnchainReplacementBlocks = 3
	campaign.Spec.Safety.MaxConcurrentFaults = 2
	manifest := betaManifestFixture()
	manifest.Actors = append(manifest.Actors, ManifestActor{Name: "bitcoin-1", Role: "burnchain"})
	_, err := CompileV1Beta1(campaign, manifest)
	if err == nil || !strings.Contains(err.Error(), "overlapping burnchain-reorg actions") {
		t.Fatalf("expected shared burnchain-policy rejection, got %v", err)
	}
}

func TestCompileV1Beta1RejectsUnknownAssertionVocabulary(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults[0].RecoveryAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "ActorReady"}}
	_, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err == nil || !strings.Contains(err.Error(), `assertion type "ActorReady" is unsupported`) {
		t.Fatalf("expected unknown assertion type rejection, got %v", err)
	}
}

func TestCompileV1Beta1RequiresAssertionScopeForMultipleActions(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults = append(campaign.Spec.Stages[0].Faults, betaPodAction("stop-signer-2", "signer-2"))
	campaign.Spec.Stages[0].EffectAssertions = []attacknetv1beta1.CampaignAssertion{{Type: "PodUnavailable"}}
	campaign.Spec.Safety.MaxConcurrentFaults = 2
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 5_000
	_, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err == nil || !strings.Contains(err.Error(), "assertion must name an action") {
		t.Fatalf("expected ambiguous assertion scope rejection, got %v", err)
	}
}

func TestCompileV1Beta1MaximumSchemaShape(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages = make([]attacknetv1beta1.FaultStageSpec, maximumCampaignStages)
	for stageIndex := range campaign.Spec.Stages {
		stage := &campaign.Spec.Stages[stageIndex]
		stage.ID = fmt.Sprintf("stage-%02d", stageIndex)
		stage.Faults = make([]attacknetv1beta1.FaultActionSpec, 32)
		for actionIndex := range stage.Faults {
			stage.Faults[actionIndex] = betaPodAction(fmt.Sprintf("fault-%02d", actionIndex), "signer-1")
		}
	}
	campaign.Spec.Safety.MaxConcurrentFaults = 512
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 10_000
	compiled, err := CompileV1Beta1(campaign, betaManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.AggregateImpact.ConcurrentFaults != 512 || len(compiled.AggregateImpact.PotentiallyOverlappingStages) != maximumCampaignStages {
		t.Fatalf("maximum-shape impact = %#v", compiled.AggregateImpact)
	}
}

func TestCompileV1Beta1SignerBehaviorBindsAdmittedPolicyAndWeight(t *testing.T) {
	manifest := betaManifestFixture()
	policyDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for index := range manifest.Actors {
		if manifest.Actors[index].Name == "signer-1" {
			manifest.Actors[index].AdversarialPolicyDigest = policyDigest
			manifest.Actors[index].AdversarialBehavior = "withhold"
		}
	}
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults = []attacknetv1beta1.FaultActionSpec{{
		ID: "withhold", Target: attacknetv1beta1.FaultTarget{Actors: []string{"signer-1"}, Mode: "all"},
		Fault: attacknetv1beta1.FaultSpec{Type: "signer-behavior", Action: "withhold", Mode: "all", Duration: metav1.Duration{Duration: 30 * time.Second}, SignerBehavior: &attacknetv1beta1.SignerBehaviorFaultSpec{PolicyDigest: policyDigest}},
	}}
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 10_000
	compiled, err := CompileV1Beta1(campaign, manifest)
	if err != nil {
		t.Fatal(err)
	}
	action := compiled.Stages[0].Actions[0]
	if action.Resource.GetKind() != "SignerBehaviorSession" || action.Evidence.SelectedActors[0] != "signer-1" || action.Evidence.SignerImpact.AffectedWeight <= 0 {
		t.Fatalf("unexpected signer behavior compilation: %#v", action)
	}
	for index := range manifest.Actors {
		if manifest.Actors[index].Name == "signer-1" {
			manifest.Actors[index].AdversarialPolicyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}
	}
	if _, err := CompileV1Beta1(campaign, manifest); err == nil || !strings.Contains(err.Error(), "policy digest") {
		t.Fatalf("policy drift was accepted: %v", err)
	}
	for index := range manifest.Actors {
		if manifest.Actors[index].Name == "signer-1" {
			manifest.Actors[index].AdversarialPolicyDigest = policyDigest
			manifest.Actors[index].AdversarialBehavior = "delay"
		}
	}
	if _, err := CompileV1Beta1(campaign, manifest); err == nil || !strings.Contains(err.Error(), "policy behavior") {
		t.Fatalf("policy action drift was accepted: %v", err)
	}
}

func TestCompileV1Beta1RequiresOneSignerPerBehaviorAction(t *testing.T) {
	policyDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	weight := 1.0
	manifest := Manifest{Network: "network"}
	actors := make([]string, 2)
	for index := range actors {
		actors[index] = fmt.Sprintf("signer-%02d", index)
		manifest.Actors = append(manifest.Actors, ManifestActor{Name: actors[index], Role: "signer", SignerWeight: &weight, AdversarialPolicyDigest: policyDigest, AdversarialBehavior: "withhold"})
	}
	campaign := betaCampaignFixture()
	campaign.Spec.NetworkRef = manifest.Network
	campaign.Spec.Stages[0].Faults = []attacknetv1beta1.FaultActionSpec{{
		ID: "withhold", Target: attacknetv1beta1.FaultTarget{Actors: actors, Mode: "all"},
		Fault: attacknetv1beta1.FaultSpec{Type: "signer-behavior", Action: "withhold", Mode: "all", Duration: metav1.Duration{Duration: 30 * time.Second}, SignerBehavior: &attacknetv1beta1.SignerBehaviorFaultSpec{PolicyDigest: policyDigest}},
	}}
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 10_000
	if _, err := CompileV1Beta1(campaign, manifest); err == nil || !strings.Contains(err.Error(), "exactly one signer") {
		t.Fatalf("multi-signer behavior action was accepted: %v", err)
	}
}

func TestMaximumAggregateImpactMatchesExhaustiveReference(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages = append(campaign.Spec.Stages,
		attacknetv1beta1.FaultStageSpec{ID: "second", Trigger: attacknetv1beta1.StageTriggerSpec{AfterStage: &attacknetv1beta1.StageDependency{Stage: "first", State: "Effective"}}, Faults: []attacknetv1beta1.FaultActionSpec{betaPodAction("stop-signer-2", "signer-2")}},
		attacknetv1beta1.FaultStageSpec{ID: "third", Trigger: attacknetv1beta1.StageTriggerSpec{AfterStage: &attacknetv1beta1.StageDependency{Stage: "second", State: "Terminal"}}, Faults: []attacknetv1beta1.FaultActionSpec{betaPodAction("stop-signer-3", "signer-3")}},
		attacknetv1beta1.FaultStageSpec{ID: "fourth", Faults: []attacknetv1beta1.FaultActionSpec{betaPodAction("stop-signer-4", "signer-4")}},
	)
	campaign.Spec.Safety.MaxConcurrentFaults = 4
	campaign.Spec.Safety.MaxUnavailableSignerBasisPoints = 10_000
	manifest := betaManifestFixture()
	compiled, err := CompileV1Beta1(campaign, manifest)
	if err != nil {
		t.Fatal(err)
	}
	want := exhaustiveAggregateImpact(compiled.Stages, campaign.Spec.Stages, manifest)
	if !reflect.DeepEqual(compiled.AggregateImpact, want) {
		t.Fatalf("optimized aggregate differs from exhaustive reference:\n got %#v\nwant %#v", compiled.AggregateImpact, want)
	}
}

func exhaustiveAggregateImpact(compiled []CompiledStage, specs []attacknetv1beta1.FaultStageSpec, manifest Manifest) AggregateImpact {
	maximum := AggregateImpact{}
	for mask := 1; mask < 1<<len(compiled); mask++ {
		indexes := make([]int, 0, len(compiled))
		for index := range compiled {
			if mask&(1<<index) != 0 {
				indexes = append(indexes, index)
			}
		}
		if !stagesCanOverlap(indexes, specs) {
			continue
		}
		impact := AggregateImpact{}
		weights := map[int32]float64{}
		for _, actor := range manifest.Actors {
			if actor.SignerIndex != nil && actor.SignerWeight != nil {
				weights[*actor.SignerIndex] = *actor.SignerWeight
			}
			if actor.Role == "miner" {
				impact.MinerTotalCount++
			}
		}
		for _, weight := range weights {
			impact.SignerTotalWeight += weight
		}
		for _, index := range indexes {
			impact.PotentiallyOverlappingStages = append(impact.PotentiallyOverlappingStages, compiled[index].ID)
			for _, action := range compiled[index].Actions {
				impact.ConcurrentFaults++
				impact.SignerAffectedWeight += action.Evidence.SignerImpact.AffectedWeight
				impact.MinerAffectedCount += int32(action.Evidence.MinerImpact.AffectedCount)
			}
		}
		impact.SignerAffectedWeight = min(impact.SignerAffectedWeight, impact.SignerTotalWeight)
		impact.MinerAffectedCount = min(impact.MinerAffectedCount, impact.MinerTotalCount)
		if impact.SignerTotalWeight > 0 {
			impact.SignerAffectedBasisPoints = int32(impact.SignerAffectedWeight * 10_000 / impact.SignerTotalWeight)
		}
		if impact.MinerTotalCount > 0 {
			impact.MinerAffectedBasisPoints = impact.MinerAffectedCount * 10_000 / impact.MinerTotalCount
		}
		sort.Strings(impact.PotentiallyOverlappingStages)
		maximum.SignerTotalWeight, maximum.MinerTotalCount = impact.SignerTotalWeight, impact.MinerTotalCount
		if impact.ConcurrentFaults > maximum.ConcurrentFaults {
			maximum.ConcurrentFaults = impact.ConcurrentFaults
			maximum.PotentiallyOverlappingStages = append([]string(nil), impact.PotentiallyOverlappingStages...)
		}
		if impact.SignerAffectedBasisPoints > maximum.SignerAffectedBasisPoints {
			maximum.SignerAffectedBasisPoints, maximum.SignerAffectedWeight = impact.SignerAffectedBasisPoints, impact.SignerAffectedWeight
		}
		if impact.MinerAffectedBasisPoints > maximum.MinerAffectedBasisPoints {
			maximum.MinerAffectedBasisPoints, maximum.MinerAffectedCount = impact.MinerAffectedBasisPoints, impact.MinerAffectedCount
		}
	}
	return maximum
}

func betaCampaignFixture() *attacknetv1beta1.FaultCampaign {
	return &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "campaign", Namespace: "test"},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{
				ID: "first", Faults: []attacknetv1beta1.FaultActionSpec{betaPodAction("stop-signer-1", "signer-1")},
			}},
			Safety: attacknetv1beta1.FaultSafety{
				MaxUnavailableSignerBasisPoints: 3_000,
				MaxUnavailableMinerBasisPoints:  10_000,
				MaxConcurrentFaults:             1,
			},
		},
	}
}

func betaPodAction(id, actor string) attacknetv1beta1.FaultActionSpec {
	return attacknetv1beta1.FaultActionSpec{
		ID:     id,
		Target: attacknetv1beta1.FaultTarget{Actors: []string{actor}},
		Fault: attacknetv1beta1.FaultSpec{
			Type: "pod", Action: "pod-failure", Mode: "one",
			Duration: metav1.Duration{Duration: 30 * time.Second},
		},
	}
}

func betaReorgAction(id, actor string) attacknetv1beta1.FaultActionSpec {
	return attacknetv1beta1.FaultActionSpec{
		ID: id, Target: attacknetv1beta1.FaultTarget{Actors: []string{actor}, Mode: "one"},
		Fault: attacknetv1beta1.FaultSpec{
			Type: "burnchain-reorg", Mode: "one", Duration: metav1.Duration{Duration: time.Minute},
			BurnchainReorg: &attacknetv1beta1.BurnchainReorgFaultSpec{Depth: 2, ReplacementBlocks: 3},
		},
	}
}

func betaManifestFixture() Manifest {
	actors := make([]ManifestActor, 0, 6)
	for index := int32(1); index <= 5; index++ {
		weight := 1.0
		copyIndex := index
		actors = append(actors, ManifestActor{Name: "signer-" + string(rune('0'+index)), Role: "signer", SignerIndex: &copyIndex, SignerWeight: &weight})
	}
	actors = append(actors, ManifestActor{Name: "miner-1", Role: "miner"})
	return Manifest{Network: "network", Namespace: "test", Actors: actors}
}
