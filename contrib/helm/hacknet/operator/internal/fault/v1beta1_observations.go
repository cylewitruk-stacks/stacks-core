package fault

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

// KubernetesTriggerObservationReader supplies controller-owned burnchain state
// and finite identity-bound actor observations. Unsupported families stay
// absent and therefore cannot make a stage eligible.
type KubernetesTriggerObservationReader struct {
	Reader   client.Reader
	Protocol *protocolobservation.Reader
}

// ReadTriggerSnapshot returns controller-owned burn height and identity-bound
// protocol observations from the shared finite metrics bridge.
func (r *KubernetesTriggerObservationReader) ReadTriggerSnapshot(ctx context.Context, campaign *attacknetv1beta1.FaultCampaign, network *attacknetv1beta1.StacksNetwork) (trigger.Snapshot, error) {
	if r == nil || r.Reader == nil || r.Protocol == nil {
		return trigger.Snapshot{}, errors.New("trusted trigger observations require an uncached Kubernetes API reader")
	}
	height, err := trigger.ReadBurnchainHeight(ctx, r.Reader, campaign.Namespace, network)
	if err != nil {
		return trigger.Snapshot{}, err
	}
	snapshot, err := r.Protocol.Read(ctx, network)
	if err != nil {
		return trigger.Snapshot{BurnHeight: height}, nil
	}
	derived, err := protocolobservation.Derive(snapshot)
	if err != nil {
		return trigger.Snapshot{}, err
	}
	return trigger.Snapshot{
		BurnHeight: height, StacksHeight: derived.StacksHeight,
		Observations: derived.Observations,
	}, nil
}
