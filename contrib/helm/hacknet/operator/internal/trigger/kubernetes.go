package trigger

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

// ReadBurnchainHeight obtains an uncached, identity-bound BurnchainPolicy
// observation for the network's currently referenced policy.
func ReadBurnchainHeight(ctx context.Context, reader client.Reader, namespace string, network *attacknetv1beta1.StacksNetwork) (*HeightObservation, error) {
	if reader == nil {
		return nil, errors.New("trusted burn-height observation requires an uncached Kubernetes API reader")
	}
	if network == nil || network.Spec.Burnchain.PolicyRef.Name == "" {
		return nil, nil
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	key := types.NamespacedName{Namespace: namespace, Name: network.Spec.Burnchain.PolicyRef.Name}
	if err := reader.Get(ctx, key, policy); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if policy.Status.Phase != "Ready" || policy.Status.ObservedGeneration != policy.Generation ||
		policy.Status.AdmittedNetworkUID != string(network.UID) || policy.Status.BitcoinObservationAt == nil ||
		policy.Status.BitcoinObservationError != "" {
		return nil, nil
	}
	return &HeightObservation{
		Height:     policy.Status.ObservedHeight,
		ObservedAt: policy.Status.BitcoinObservationAt.Time.UTC(),
		Source: Source{
			Kind: "BurnchainPolicy", Namespace: policy.Namespace, Name: policy.Name,
			UID: string(policy.UID), ResourceVersion: policy.ResourceVersion, Trusted: true,
		},
	}, nil
}
