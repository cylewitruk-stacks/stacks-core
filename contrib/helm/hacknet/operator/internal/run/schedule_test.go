package run

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
)

func scheduleFixture() (*attacknetv1alpha1.AttacknetRun, *attacknetv1alpha1.StacksNetwork, attacknetv1alpha1.NetworkInventory, map[string]*attacknetv1alpha1.FaultCampaign) {
	network := &attacknetv1alpha1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "attacknet", Namespace: "test", UID: types.UID("network-2"), Generation: 3}, Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{{Name: "miner-1", Role: "miner", Image: "node:test"}}}}
	inventory := attacknetv1alpha1.NetworkInventory{Digest: "sha256:" + repeat("a", 64), ObservedGeneration: 3, Actors: []attacknetv1alpha1.AdmittedActorIdentity{{Name: "miner-1", Role: "miner", RequestedImage: "node:test", RuntimeImageID: "docker-pullable://node@sha256:" + repeat("b", 64)}}}
	template := &attacknetv1alpha1.FaultCampaign{ObjectMeta: metav1.ObjectMeta{Name: "kill-miner", Namespace: "test", UID: types.UID("template-uid"), Generation: 2}, Spec: attacknetv1alpha1.FaultCampaignSpec{Template: true, NetworkRef: "attacknet", Target: attacknetv1alpha1.FaultTarget{Actors: []string{"miner-1"}}, Fault: attacknetv1alpha1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: "10s"}, Safety: attacknetv1alpha1.FaultSafety{MaxUnavailableSignerPercent: 30, MaxUnavailableMinerPercent: 100, AllowMinerMajorityOutage: true}}}
	run := &attacknetv1alpha1.AttacknetRun{ObjectMeta: metav1.ObjectMeta{Name: "run-1", Namespace: "test", UID: types.UID("run-uid"), Generation: 1}, Spec: attacknetv1alpha1.AttacknetRunSpec{NetworkRef: "attacknet", Seed: "seed", DecisionAlgorithm: "hmac-sha256-decisions/v1", CampaignCatalog: []attacknetv1alpha1.CampaignCatalogEntry{{Name: "kill", CampaignRef: "kill-miner"}}, Sequence: []attacknetv1alpha1.RunInstruction{{ID: "one", Campaign: "kill", DelayAfterSeconds: 2}, {ID: "two", Campaign: "kill"}}, Budgets: attacknetv1alpha1.RunBudgets{MaxCampaigns: 2, MaxWallTimeSeconds: 60, MaxCumulativeFaultSeconds: 30, MaxActiveFaults: 1, MaxSignerImpactPercent: 30, MaxBurnchainFaults: 0, MaxInconclusiveCampaigns: 1}}}
	return run, network, inventory, map[string]*attacknetv1alpha1.FaultCampaign{"kill-miner": template}
}

func TestScheduleRoundTripAndIntegrity(t *testing.T) {
	run, network, inventory, templates := scheduleFixture()
	schedule, err := buildSchedule(run, network, inventory, templates, fault.ManifestFromNetwork(network))
	if err != nil {
		t.Fatal(err)
	}
	if schedule.SchemaVersion != scheduleSchema || len(schedule.Actions) != 2 || schedule.Actions[0].Resolved.CampaignSpecDigest == "" {
		t.Fatalf("invalid schedule: %#v", schedule)
	}
	encoded, err := encodeSchedule(schedule)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSchedule(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Integrity.Digest != schedule.Integrity.Digest {
		t.Fatal("schedule digest changed")
	}
	encoded[len(encoded)/2] ^= 0xff
	if _, err := decodeSchedule(encoded); err == nil {
		t.Fatal("corrupt schedule decoded")
	}
}

func TestMinimizationIsRemovalOnlyAndRequiresFreshImages(t *testing.T) {
	run, network, inventory, templates := scheduleFixture()
	source, err := buildSchedule(run, network, inventory, templates, fault.ManifestFromNetwork(network))
	if err != nil {
		t.Fatal(err)
	}
	network.UID = "fresh-network"
	retained := []attacknetv1alpha1.RetainedInstruction{{InstructionID: "one"}}
	run.Spec.Minimization = attacknetv1alpha1.MinimizationSpec{Enabled: true, Strategy: "DeltaDebug", MaxAttempts: 1, RequireFreshNetwork: true, Retained: retained, SourceScheduleDigest: source.Integrity.Digest, CandidateDigest: retainedDigest(t, retained)}
	candidate, err := applyReplay(source, run, network, inventory, fault.ManifestFromNetwork(network), templates, true)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Network.UID != "fresh-network" || len(candidate.Actions) != 1 {
		t.Fatalf("bad counterfactual: %#v", candidate)
	}
}

func TestReplayRequiresFreshMatchingImmutableInputs(t *testing.T) {
	run, network, inventory, templates := scheduleFixture()
	source, err := buildSchedule(run, network, inventory, templates, fault.ManifestFromNetwork(network))
	if err != nil {
		t.Fatal(err)
	}
	run.Spec.Replay = attacknetv1alpha1.ReplaySpec{Enabled: true, SourceRunRef: "source", DescriptorDigest: source.Integrity.Digest, RequireSameResolvedImages: true}
	if _, err := applyReplay(source, run, network, inventory, fault.ManifestFromNetwork(network), templates, false); err == nil {
		t.Fatal("replay reused the source network UID")
	}
	network.UID = "fresh"
	replayed, err := applyReplay(source, run, network, inventory, fault.ManifestFromNetwork(network), templates, false)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Network.UID != "fresh" || replayed.Integrity.Digest == source.Integrity.Digest {
		t.Fatalf("source schedule was not rebound and resealed: %#v", replayed)
	}
	changedInventory := inventory
	changedInventory.Actors = append([]attacknetv1alpha1.AdmittedActorIdentity(nil), inventory.Actors...)
	changedInventory.Actors[0].RuntimeImageID = "docker-pullable://node@sha256:" + repeat("c", 64)
	if _, err := applyReplay(source, run, network, changedInventory, fault.ManifestFromNetwork(network), templates, false); err == nil {
		t.Fatal("replay accepted changed runtime image identity")
	}
	changedTemplates := map[string]*attacknetv1alpha1.FaultCampaign{"kill-miner": templates["kill-miner"].DeepCopy()}
	changedTemplates["kill-miner"].Generation++
	if _, err := applyReplay(source, run, network, inventory, fault.ManifestFromNetwork(network), changedTemplates, false); err == nil {
		t.Fatal("replay accepted changed source template identity")
	}
}

func TestMinimizationRejectsUnknownOrNonMaterialRemoval(t *testing.T) {
	run, network, inventory, templates := scheduleFixture()
	source, err := buildSchedule(run, network, inventory, templates, fault.ManifestFromNetwork(network))
	if err != nil {
		t.Fatal(err)
	}
	network.UID = "fresh"
	retained := []attacknetv1alpha1.RetainedInstruction{{InstructionID: "one"}, {InstructionID: "two"}}
	run.Spec.Minimization = attacknetv1alpha1.MinimizationSpec{Enabled: true, Strategy: "DeltaDebug", MaxAttempts: 1, RequireFreshNetwork: true, SourceScheduleDigest: source.Integrity.Digest, CandidateDigest: retainedDigest(t, retained), Retained: retained}
	if _, err := applyReplay(source, run, network, inventory, fault.ManifestFromNetwork(network), templates, true); err == nil {
		t.Fatal("non-material minimization was accepted")
	}
	run.Spec.Minimization.Retained = []attacknetv1alpha1.RetainedInstruction{{InstructionID: "missing"}}
	run.Spec.Minimization.CandidateDigest = retainedDigest(t, run.Spec.Minimization.Retained)
	if _, err := applyReplay(source, run, network, inventory, fault.ManifestFromNetwork(network), templates, true); err == nil {
		t.Fatal("unknown minimization instruction was accepted")
	}
}

func retainedDigest(t *testing.T, value any) string {
	t.Helper()
	digest, err := canonical.Digest(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func repeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
