package upgrade

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateEnforcesSignerWeightAndMinerLimits(t *testing.T) {
	network := networkFixture()
	campaign := campaignFixture()
	if err := Validate(campaign, network); err != nil {
		t.Fatal(err)
	}
	campaign.Spec.Safety.MaxSignerWeightPercent = 20
	if err := Validate(campaign, network); err == nil || !strings.Contains(err.Error(), "signer-weight") {
		t.Fatalf("got %v, want signer weight rejection", err)
	}
	campaign = campaignFixture()
	campaign.Spec.Stages[0].Assignments = append(campaign.Spec.Stages[0].Assignments, attacknetv1beta1.UpgradeAssignment{Actor: "miner-1", Profile: "next"})
	campaign.Spec.Safety.MaxParallelActors = 2
	if err := Validate(campaign, network); err == nil || !strings.Contains(err.Error(), "miner safety") {
		t.Fatalf("got %v, want miner safety rejection", err)
	}
}

func TestApplyOverlayIsCumulativeAndRollingBackRestoresSpec(t *testing.T) {
	network := networkFixture()
	campaign := campaignFixture()
	campaign.Spec.Stages = append(campaign.Spec.Stages, attacknetv1beta1.UpgradeStageSpec{
		Name: "node", StableFor: metav1.Duration{Duration: time.Second}, Deadline: metav1.Duration{Duration: time.Minute},
		Assignments: []attacknetv1beta1.UpgradeAssignment{{Actor: "signer-node-1", Profile: "next"}},
	})
	campaign.Status = attacknetv1beta1.UpgradeCampaignStatus{Phase: "Running", CurrentStage: 1, BaselineInventory: &attacknetv1beta1.NetworkInventory{Digest: digest}}
	effective, err := ApplyOverlay(network, campaign)
	if err != nil {
		t.Fatal(err)
	}
	member := effective.Spec.SignerSets[0].Members[0]
	if member.SignerImage != "stacks:next" || member.NodeImage != "stacks:next" {
		t.Fatalf("cumulative overlay missing: %#v", member)
	}
	campaign.Status.Phase = "RollingBack"
	effective, err = ApplyOverlay(network, campaign)
	if err != nil {
		t.Fatal(err)
	}
	member = effective.Spec.SignerSets[0].Members[0]
	if member.SignerImage != "" || member.NodeImage != "" {
		t.Fatalf("rollback retained overlay: %#v", member)
	}
}

func TestEffectiveAssignmentsPreservesFailedDeploymentUntilCleanup(t *testing.T) {
	campaign := campaignFixture()
	campaign.Status = attacknetv1beta1.UpgradeCampaignStatus{
		Phase:             "Failed",
		CurrentStage:      0,
		BaselineInventory: &attacknetv1beta1.NetworkInventory{Digest: digest},
	}
	if got := EffectiveAssignments(campaign); len(got) != 1 || got[0].Actor != "signer-1" {
		t.Fatalf("failed campaign did not preserve its admitted overlay: %#v", got)
	}
	campaign.Status.RollbackComplete = true
	if got := EffectiveAssignments(campaign); len(got) != 0 {
		t.Fatalf("completed rollback retained assignments: %#v", got)
	}
	campaign.Status.RollbackComplete = false
	campaign.Status.BaselineInventory = nil
	if got := EffectiveAssignments(campaign); len(got) != 0 {
		t.Fatalf("failed admission applied an unadmitted stage: %#v", got)
	}
}

func networkFixture() *attacknetv1beta1.StacksNetwork {
	return &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network"}, Spec: attacknetv1beta1.StacksNetworkSpec{
		Nodes: []attacknetv1beta1.StacksNodeSpec{{Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner}},
		SignerSets: []attacknetv1beta1.SignerSetSpec{{Name: "set", Members: []attacknetv1beta1.SignerMemberSpec{
			{Name: "signer-1", NodeName: "signer-node-1", Weight: 30},
			{Name: "signer-2", NodeName: "signer-node-2", Weight: 70},
		}}},
	}}
}

func campaignFixture() *attacknetv1beta1.UpgradeCampaign {
	return &attacknetv1beta1.UpgradeCampaign{Spec: attacknetv1beta1.UpgradeCampaignSpec{
		NetworkRef: "network", Profiles: []attacknetv1beta1.UpgradeProfileSpec{{Name: "next", Image: "stacks:next", ImageID: digest, ProvenanceDigest: digest, ConfigDigest: digest, SourceKind: "prebuilt"}},
		Stages: []attacknetv1beta1.UpgradeStageSpec{{Name: "signer", StableFor: metav1.Duration{Duration: time.Second}, Deadline: metav1.Duration{Duration: time.Minute}, Assignments: []attacknetv1beta1.UpgradeAssignment{{Actor: "signer-1", Profile: "next"}}}},
		Safety: attacknetv1beta1.UpgradeSafetySpec{MaxParallelActors: 1, MaxSignerWeightPercent: 30, MaxMinerPercent: 50}, RollbackOnFailure: true,
	}}
}
