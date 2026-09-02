package topology

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/upgrade"
)

// networkWithUpgradeOverlay resolves the one topology-owned active upgrade.
func (r *V1Beta1Reconciler) networkWithUpgradeOverlay(ctx context.Context, network *attacknetv1beta1.StacksNetwork) (*attacknetv1beta1.StacksNetwork, error) {
	list := &attacknetv1beta1.UpgradeCampaignList{}
	if err := r.List(ctx, list, client.InNamespace(network.Namespace)); err != nil {
		return nil, err
	}
	var active *attacknetv1beta1.UpgradeCampaign
	restoringBaseline := false
	for index := range list.Items {
		campaign := &list.Items[index]
		if campaign.Spec.NetworkRef != network.Name || campaign.Spec.Template {
			continue
		}
		restoresOnDeletion := campaign.DeletionTimestamp != nil && campaign.Status.NetworkUID == string(network.UID) &&
			campaign.Status.BaselineInventory != nil && !campaign.Status.RollbackComplete
		if restoresOnDeletion || campaignMaintainsOverlay(campaign) {
			if !restoresOnDeletion && (campaign.Status.NetworkUID != string(network.UID) || campaign.Status.ObservedGeneration != campaign.Generation) {
				return nil, fmt.Errorf("UpgradeCampaign %s is not admitted to StacksNetwork UID %s at its current generation", campaign.Name, network.UID)
			}
			if active != nil {
				return nil, fmt.Errorf("multiple active UpgradeCampaigns target network %s", network.Name)
			}
			active = campaign
			restoringBaseline = restoresOnDeletion
		}
	}
	if restoringBaseline {
		// Deletion is an unconditional request to restore the StacksNetwork
		// declaration. Do not validate or consume a campaign spec that may have
		// changed in the same generation transition as its deletion request.
		return network.DeepCopy(), nil
	}
	return upgrade.ApplyOverlay(network, active)
}

func campaignMaintainsOverlay(campaign *attacknetv1beta1.UpgradeCampaign) bool {
	switch campaign.Status.Phase {
	case "Running", "Passed", "RollingBack":
		return true
	case "Failed", "Inconclusive":
		return campaign.Status.BaselineInventory != nil && !campaign.Status.RollbackComplete
	default:
		return false
	}
}
