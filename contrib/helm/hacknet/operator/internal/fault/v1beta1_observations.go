package fault

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

// KubernetesTriggerObservationReader supplies trusted controller-owned trigger
// observations. Unsupported observation families stay absent and therefore
// cannot make a stage eligible.
type KubernetesTriggerObservationReader struct {
	Reader client.Reader
}

// ReadTriggerSnapshot returns the current identity-bound burn height.
func (r *KubernetesTriggerObservationReader) ReadTriggerSnapshot(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork) (trigger.Snapshot, error) {
	if r == nil || r.Reader == nil {
		return trigger.Snapshot{}, errors.New("trusted trigger observations require an uncached Kubernetes API reader")
	}
	height, err := trigger.ReadBurnchainHeight(ctx, r.Reader, campaign.Namespace, network)
	return trigger.Snapshot{BurnHeight: height}, err
}
