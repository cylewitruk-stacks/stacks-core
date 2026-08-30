package topology

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestCampaignMaintainsOverlayForFailedTriageState(t *testing.T) {
	campaign := &attacknetv1beta1.UpgradeCampaign{Status: attacknetv1beta1.UpgradeCampaignStatus{
		Phase: "Failed", BaselineInventory: &attacknetv1beta1.NetworkInventory{Digest: "baseline"},
	}}
	if !campaignMaintainsOverlay(campaign) {
		t.Fatal("failed rollout was not preserved for triage")
	}
	campaign.Status.RollbackComplete = true
	if campaignMaintainsOverlay(campaign) {
		t.Fatal("completed rollback retained the failed overlay")
	}
}

func TestDeletingCampaignRestoresBaseDespiteGenerationTransition(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.Now()
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{
		Name: "network", Namespace: "attacknet", UID: types.UID("network-uid"),
	}, Spec: attacknetv1beta1.StacksNetworkSpec{Nodes: []attacknetv1beta1.StacksNodeSpec{{
		Name: "follower-1", Role: "follower", Image: "stable:sealed",
	}}}}
	campaign := &attacknetv1beta1.UpgradeCampaign{ObjectMeta: metav1.ObjectMeta{
		Name: "upgrade", Namespace: network.Namespace, Generation: 2, DeletionTimestamp: &now,
		Finalizers: []string{"testing.stacks.org/upgrade-cleanup"},
	}, Spec: attacknetv1beta1.UpgradeCampaignSpec{NetworkRef: network.Name}, Status: attacknetv1beta1.UpgradeCampaignStatus{
		Phase: "Running", NetworkUID: string(network.UID), ObservedGeneration: 1,
		BaselineInventory: &attacknetv1beta1.NetworkInventory{Digest: "sha256:" + strings.Repeat("a", 64)},
	}}
	reconciler := &V1Beta1Reconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(campaign).Build()}
	effective, err := reconciler.networkWithUpgradeOverlay(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Spec.Nodes[0].Image != "stable:sealed" {
		t.Fatalf("deleting campaign did not restore the declared topology: %#v", effective.Spec.Nodes)
	}

	campaign.DeletionTimestamp = nil
	reconciler.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(campaign).Build()
	if _, err := reconciler.networkWithUpgradeOverlay(context.Background(), network); err == nil {
		t.Fatal("non-deleting campaign with a generation mismatch was admitted")
	}
}
