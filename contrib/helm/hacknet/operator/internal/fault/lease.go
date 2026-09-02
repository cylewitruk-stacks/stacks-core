package fault

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

const mutationLeaseOwnerKindAnnotation = "testing.stacks.org/mutation-lease-owner-kind"

func mutationLeaseOwner(campaign *attacknetv1alpha1.FaultCampaign) string {
	kind := campaign.Annotations[mutationLeaseOwnerKindAnnotation]
	if kind == "" {
		kind = "faultcampaign"
	}
	return kind + ":" + string(campaign.UID)
}

func (r *Reconciler) isSerializedTurn(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) (bool, error) {
	list := &attacknetv1alpha1.FaultCampaignList{}
	if err := r.List(ctx, list, client.InNamespace(campaign.Namespace)); err != nil {
		return false, err
	}
	active := []attacknetv1alpha1.FaultCampaign{}
	for _, item := range list.Items {
		if item.Spec.Template || item.Spec.NetworkRef != campaign.Spec.NetworkRef || terminalPhases[item.Status.Phase] || !item.DeletionTimestamp.IsZero() {
			continue
		}
		active = append(active, item)
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].CreationTimestamp.Equal(&active[j].CreationTimestamp) {
			return active[i].Name < active[j].Name
		}
		return active[i].CreationTimestamp.Before(&active[j].CreationTimestamp)
	})
	return len(active) == 0 || active[0].UID == campaign.UID, nil
}

func (r *Reconciler) holdMutationLease(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, acquire bool) (mutationLeaseState, error) {
	environment := &corev1.ConfigMap{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: environmentLease}, environment); err != nil {
		if apierrors.IsNotFound(err) {
			return mutationLeaseState{EnvironmentMessage: fmt.Sprintf("no active environment lease exists for network %s", campaign.Spec.NetworkRef)}, nil
		}
		return mutationLeaseState{}, err
	}
	if environment.Data["network"] != campaign.Spec.NetworkRef {
		return mutationLeaseState{EnvironmentMessage: fmt.Sprintf("active environment lease belongs to network %s, not %s", environment.Data["network"], campaign.Spec.NetworkRef)}, nil
	}
	state := mutationLeaseState{EnvironmentReady: true}
	lease := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: campaign.Namespace, Name: mutationLease}
	err := r.APIReader.Get(ctx, key, lease)
	if apierrors.IsNotFound(err) && acquire {
		owner := mutationLeaseOwner(campaign)
		lease = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: mutationLease, Namespace: campaign.Namespace}, Data: map[string]string{"network": campaign.Spec.NetworkRef, "owner": owner, "purpose": owner + ":" + campaign.Name, "token": string(campaign.UID), "acquiredAt": r.now().Format(time.RFC3339)}}
		err = r.Create(ctx, lease)
		if apierrors.IsAlreadyExists(err) {
			err = r.APIReader.Get(ctx, key, lease)
		}
	}
	if apierrors.IsNotFound(err) && !acquire {
		return state, nil
	}
	if err != nil {
		return mutationLeaseState{}, err
	}
	state.Held = lease.Data["network"] == campaign.Spec.NetworkRef && lease.Data["owner"] == mutationLeaseOwner(campaign) && lease.Data["token"] == string(campaign.UID)
	return state, nil
}

func (r *Reconciler) releaseMutationLease(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign) error {
	lease := &corev1.ConfigMap{}
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: mutationLease}, lease)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if lease.Data["owner"] != mutationLeaseOwner(campaign) || lease.Data["token"] != string(campaign.UID) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, lease))
}
