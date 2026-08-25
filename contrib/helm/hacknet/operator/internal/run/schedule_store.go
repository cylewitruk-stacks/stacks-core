package run

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

const scheduleFormat = "stacks-attacknet-schedule-configmap/v1"

// scheduleStore persists and verifies immutable, owner-bound resolved schedules.
type scheduleStore struct {
	writer client.Client
	reader client.Reader
}

func (s scheduleStore) persist(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, schedule resolvedSchedule) (attacknetv1alpha1.ScheduleReference, error) {
	payload, err := encodeSchedule(schedule)
	if err != nil {
		return attacknetv1alpha1.ScheduleReference{}, err
	}
	name := stableName(run.Name, "resolved-schedule")
	specDigest, _ := canonical.ArtifactDigest(run.Spec)
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: run.Namespace, Name: name}
	err = s.reader.Get(ctx, key, cm)
	if apierrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: run.Namespace, Labels: map[string]string{fault.NetworkLabel: run.Spec.NetworkRef, "testing.stacks.org/run": run.Name, "testing.stacks.org/artifact": "resolved-schedule"}, Annotations: map[string]string{"testing.stacks.org/schedule-format": scheduleFormat, "testing.stacks.org/schedule-digest": schedule.Integrity.Digest, "testing.stacks.org/run-generation": fmt.Sprint(run.Generation), "testing.stacks.org/run-spec-digest": specDigest}, OwnerReferences: []metav1.OwnerReference{ownership.Reference(run, attacknetv1alpha1.GroupVersion.WithKind("AttacknetRun"))}}, BinaryData: map[string][]byte{"schedule.json.gz": payload}}
		if createErr := s.writer.Create(ctx, cm); createErr != nil {
			if !apierrors.IsAlreadyExists(createErr) {
				return attacknetv1alpha1.ScheduleReference{}, createErr
			}
			cm = &corev1.ConfigMap{}
			if err := s.reader.Get(ctx, key, cm); err != nil {
				return attacknetv1alpha1.ScheduleReference{}, err
			}
		}
	} else if err != nil {
		return attacknetv1alpha1.ScheduleReference{}, err
	}
	owner := metav1.GetControllerOf(cm)
	if owner == nil || owner.UID != run.UID {
		return attacknetv1alpha1.ScheduleReference{}, fmt.Errorf("refusing to adopt ConfigMap %s", name)
	}
	if cm.Annotations["testing.stacks.org/schedule-format"] != scheduleFormat ||
		cm.Annotations["testing.stacks.org/schedule-digest"] != schedule.Integrity.Digest ||
		cm.Annotations["testing.stacks.org/run-generation"] != fmt.Sprint(run.Generation) ||
		cm.Annotations["testing.stacks.org/run-spec-digest"] != specDigest {
		return attacknetv1alpha1.ScheduleReference{}, errors.New("immutable schedule already exists for different run inputs")
	}
	persisted, err := decodeSchedule(cm.BinaryData["schedule.json.gz"])
	if err != nil || persisted.Integrity.Digest != schedule.Integrity.Digest {
		return attacknetv1alpha1.ScheduleReference{}, errors.New("immutable schedule already exists with different contents")
	}
	return attacknetv1alpha1.ScheduleReference{Name: name, UID: string(cm.UID), Digest: persisted.Integrity.Digest, RunGeneration: run.Generation, RunSpecDigest: specDigest}, nil
}

func (s scheduleStore) read(ctx context.Context, run *attacknetv1alpha1.AttacknetRun, reference attacknetv1alpha1.ScheduleReference) (resolvedSchedule, error) {
	cm := &corev1.ConfigMap{}
	if err := s.reader.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: reference.Name}, cm); err != nil {
		return resolvedSchedule{}, err
	}
	owner := metav1.GetControllerOf(cm)
	if owner == nil || owner.UID != run.UID || string(cm.UID) != reference.UID {
		return resolvedSchedule{}, errors.New("resolved schedule ownership or UID changed")
	}
	if cm.Annotations["testing.stacks.org/schedule-format"] != scheduleFormat ||
		cm.Annotations["testing.stacks.org/schedule-digest"] != reference.Digest ||
		cm.Annotations["testing.stacks.org/run-generation"] != fmt.Sprint(reference.RunGeneration) ||
		cm.Annotations["testing.stacks.org/run-spec-digest"] != reference.RunSpecDigest ||
		reference.RunGeneration != run.Generation {
		return resolvedSchedule{}, errors.New("resolved schedule metadata changed or no longer matches the run")
	}
	specDigest, err := canonical.ArtifactDigest(run.Spec)
	if err != nil || specDigest != reference.RunSpecDigest {
		return resolvedSchedule{}, errors.New("resolved schedule run inputs changed")
	}
	schedule, err := decodeSchedule(cm.BinaryData["schedule.json.gz"])
	if err != nil {
		return schedule, err
	}
	if schedule.Integrity.Digest != reference.Digest {
		return schedule, errors.New("resolved schedule reference digest changed")
	}
	return schedule, nil
}
