package inventory

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	testingv1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

const networkLabel = "testing.stacks.org/network"

// LiveView is a directly-read network and its currently visible actor Pods.
// The two API requests are intentionally uncached but are not an atomic
// Kubernetes snapshot.
type LiveView struct {
	Network *testingv1.StacksNetwork
	Pods    []corev1.Pod
}

// ReadLiveView bypasses informer caches for an identity-sensitive decision.
func ReadLiveView(ctx context.Context, reader client.Reader, key client.ObjectKey) (LiveView, error) {
	if reader == nil {
		return LiveView{}, errors.New("uncached Kubernetes API reader is required")
	}
	network := &testingv1.StacksNetwork{}
	if err := reader.Get(ctx, key, network); err != nil {
		return LiveView{}, err
	}
	pods := &corev1.PodList{}
	if err := reader.List(ctx, pods, client.InNamespace(key.Namespace), client.MatchingLabels{networkLabel: key.Name}); err != nil {
		return LiveView{}, err
	}
	return LiveView{Network: network, Pods: pods.Items}, nil
}
