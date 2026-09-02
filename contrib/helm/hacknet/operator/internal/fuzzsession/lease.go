package fuzzsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coordinationclient "k8s.io/client-go/kubernetes/typed/coordination/v1"
)

const sessionLeaseName = "attacknet-fuzz-session"

var errLeaseOwnershipLost = errors.New("session lease ownership lost")

// LeaseManager serializes session ownership through the Kubernetes API.
type LeaseManager struct {
	client    coordinationclient.CoordinationV1Interface
	namespace string
	now       func() time.Time
	duration  time.Duration
}

// Current returns the exact current session Lease without modifying it.
func (manager *LeaseManager) Current(ctx context.Context) (*coordinationv1.Lease, error) {
	current, err := manager.client.Leases(manager.namespace).Get(
		ctx, sessionLeaseName, metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("read session lease: %w", err)
	}
	return current, nil
}

// NewLeaseManager constructs a fail-closed session lease manager.
func NewLeaseManager(
	client coordinationclient.CoordinationV1Interface,
	namespace string,
	now func() time.Time,
	duration time.Duration,
) (*LeaseManager, error) {
	if client == nil || namespace == "" || duration < 15*time.Second || duration > 5*time.Minute {
		return nil, errors.New("coordination client, namespace, and lease duration within 15s..5m are required")
	}
	if now == nil {
		now = time.Now
	}
	return &LeaseManager{client: client, namespace: namespace, now: now, duration: duration}, nil
}

// Acquire creates or renews a lease already owned by the exact session. It
// never steals an expired lease.
func (manager *LeaseManager) Acquire(ctx context.Context, holder string) (*coordinationv1.Lease, error) {
	if holder == "" || len(holder) > 256 {
		return nil, errors.New("bounded session holder identity is required")
	}
	leases := manager.client.Leases(manager.namespace)
	current, err := leases.Get(ctx, sessionLeaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		now := metav1.NewMicroTime(manager.now().UTC())
		durationSeconds := int32(manager.duration / time.Second)
		created, createErr := leases.Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: sessionLeaseName, Namespace: manager.namespace},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity: &holder, LeaseDurationSeconds: &durationSeconds,
				AcquireTime: &now, RenewTime: &now,
			},
		}, metav1.CreateOptions{})
		if createErr != nil {
			return nil, fmt.Errorf("acquire session lease: %w", createErr)
		}
		return created, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session lease: %w", err)
	}
	if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != holder {
		return nil, fmt.Errorf(
			"session lease is owned by %q; inspect and explicitly break it",
			valueOrEmpty(current.Spec.HolderIdentity),
		)
	}
	return manager.renew(ctx, current, holder)
}

// Renew proves that the exact acquired Lease remains under this holder.
func (manager *LeaseManager) Renew(
	ctx context.Context, acquired *coordinationv1.Lease, holder string,
) (*coordinationv1.Lease, error) {
	if acquired == nil || acquired.UID == "" || acquired.ResourceVersion == "" {
		return nil, errors.New("exact acquired lease identity is required")
	}
	current, err := manager.client.Leases(manager.namespace).Get(
		ctx, sessionLeaseName, metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: Lease no longer exists", errLeaseOwnershipLost)
	}
	if err != nil {
		return nil, fmt.Errorf("re-read session lease: %w", err)
	}
	if current.UID != acquired.UID ||
		current.Spec.HolderIdentity == nil ||
		*current.Spec.HolderIdentity != holder {
		return nil, fmt.Errorf("%w: identity or owner changed", errLeaseOwnershipLost)
	}
	return manager.renew(ctx, current, holder)
}

// Release deletes only the exact lease acquired by this session.
func (manager *LeaseManager) Release(
	ctx context.Context, acquired *coordinationv1.Lease, holder string,
) error {
	if acquired == nil || acquired.UID == "" || acquired.ResourceVersion == "" ||
		acquired.Spec.HolderIdentity == nil || *acquired.Spec.HolderIdentity != holder {
		return errors.New("exact owned lease identity is required")
	}
	leases := manager.client.Leases(manager.namespace)
	current, err := leases.Get(ctx, sessionLeaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("re-read session lease before release: %w", err)
	}
	// IntentReleaseSessionLease is journaled before this call. A different UID
	// therefore proves only that the old exact Lease is gone; it never grants
	// authority to delete the replacement session's Lease.
	if current.UID != acquired.UID {
		return nil
	}
	if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != holder {
		return errors.New("session lease owner changed before release")
	}
	err = leases.Delete(
		ctx, sessionLeaseName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{
			UID: ptrUID(acquired.UID), ResourceVersion: &acquired.ResourceVersion,
		}},
	)
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// Break deletes one exact stale lease. The caller must first journal holder,
// UID, resource version, and the operator's reason.
func (manager *LeaseManager) Break(
	ctx context.Context, expectedUID types.UID, expectedResourceVersion, expectedHolder, reason string,
) error {
	if expectedUID == "" || expectedResourceVersion == "" ||
		expectedHolder == "" || reason == "" || len(reason) > 512 {
		return errors.New("exact stale lease identity, holder, and bounded reason are required")
	}
	current, err := manager.client.Leases(manager.namespace).Get(
		ctx, sessionLeaseName, metav1.GetOptions{},
	)
	if err != nil {
		return err
	}
	if current.UID != expectedUID || current.ResourceVersion != expectedResourceVersion ||
		current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != expectedHolder {
		return errors.New("session lease no longer matches the stale owner")
	}
	return manager.client.Leases(manager.namespace).Delete(
		ctx, sessionLeaseName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{
			UID: &expectedUID, ResourceVersion: &expectedResourceVersion,
		}},
	)
}

func (manager *LeaseManager) renew(
	ctx context.Context, current *coordinationv1.Lease, holder string,
) (*coordinationv1.Lease, error) {
	copy := current.DeepCopy()
	now := metav1.NewMicroTime(manager.now().UTC())
	durationSeconds := int32(manager.duration / time.Second)
	copy.Spec.HolderIdentity = &holder
	copy.Spec.LeaseDurationSeconds = &durationSeconds
	copy.Spec.RenewTime = &now
	updated, err := manager.client.Leases(manager.namespace).Update(
		ctx, copy, metav1.UpdateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("renew session lease: %w", err)
	}
	return updated, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func ptrUID(value types.UID) *types.UID { return &value }
