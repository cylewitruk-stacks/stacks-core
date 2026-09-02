package run

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

const betaScheduleFormat = "stacks-attacknet-schedule-configmap/v2"

type betaScheduleStore struct {
	writer client.Client
	reader client.Reader
}

func (s betaScheduleStore) persist(ctx context.Context, run *attacknetv1beta1.AttacknetRun, schedule betaSchedule) (attacknetv1beta1.ScheduleReference, error) {
	payload, err := encodeBetaSchedule(schedule)
	if err != nil {
		return attacknetv1beta1.ScheduleReference{}, err
	}
	name := stableName(run.Name, "resolved-schedule-v2")
	specDigest, err := canonical.ArtifactDigest(run.Spec)
	if err != nil {
		return attacknetv1beta1.ScheduleReference{}, err
	}
	key := types.NamespacedName{Namespace: run.Namespace, Name: name}
	configMap := &corev1.ConfigMap{}
	err = s.reader.Get(ctx, key, configMap)
	if apierrors.IsNotFound(err) {
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: run.Namespace,
				Labels: map[string]string{fault.NetworkLabel: run.Spec.NetworkRef, "testing.stacks.org/run": run.Name, "testing.stacks.org/artifact": "resolved-schedule"},
				Annotations: map[string]string{
					"testing.stacks.org/schedule-format": betaScheduleFormat,
					"testing.stacks.org/schedule-digest": schedule.Integrity.Digest,
					"testing.stacks.org/run-generation":  fmt.Sprint(run.Generation),
					"testing.stacks.org/run-spec-digest": specDigest,
				},
				OwnerReferences: []metav1.OwnerReference{ownership.Reference(run, attacknetv1beta1.GroupVersion.WithKind("AttacknetRun"))},
			},
			BinaryData: map[string][]byte{"schedule.json.gz": payload},
		}
		if err = s.writer.Create(ctx, configMap); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return attacknetv1beta1.ScheduleReference{}, err
			}
			configMap = &corev1.ConfigMap{}
			if err = s.reader.Get(ctx, key, configMap); err != nil {
				return attacknetv1beta1.ScheduleReference{}, err
			}
		}
	} else if err != nil {
		return attacknetv1beta1.ScheduleReference{}, err
	}
	owner := metav1.GetControllerOf(configMap)
	if owner == nil || owner.UID != run.UID || owner.Kind != "AttacknetRun" || owner.APIVersion != attacknetv1beta1.GroupVersion.String() {
		return attacknetv1beta1.ScheduleReference{}, fmt.Errorf("refusing to adopt ConfigMap %s", name)
	}
	if configMap.Annotations["testing.stacks.org/schedule-format"] != betaScheduleFormat ||
		configMap.Annotations["testing.stacks.org/schedule-digest"] != schedule.Integrity.Digest ||
		configMap.Annotations["testing.stacks.org/run-generation"] != fmt.Sprint(run.Generation) ||
		configMap.Annotations["testing.stacks.org/run-spec-digest"] != specDigest {
		return attacknetv1beta1.ScheduleReference{}, errors.New("immutable schedule already exists for different run inputs")
	}
	persisted, err := decodeBetaSchedule(configMap.BinaryData["schedule.json.gz"])
	if err != nil || persisted.Integrity.Digest != schedule.Integrity.Digest {
		return attacknetv1beta1.ScheduleReference{}, errors.New("immutable schedule already exists with different contents")
	}
	return attacknetv1beta1.ScheduleReference{Name: name, UID: string(configMap.UID), Digest: schedule.Integrity.Digest, RunGeneration: run.Generation, RunSpecDigest: specDigest}, nil
}

func (s betaScheduleStore) read(ctx context.Context, run *attacknetv1beta1.AttacknetRun, reference attacknetv1beta1.ScheduleReference) (betaSchedule, error) {
	configMap := &corev1.ConfigMap{}
	if err := s.reader.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: reference.Name}, configMap); err != nil {
		return betaSchedule{}, err
	}
	owner := metav1.GetControllerOf(configMap)
	if owner == nil || owner.UID != run.UID || owner.Kind != "AttacknetRun" ||
		owner.APIVersion != attacknetv1beta1.GroupVersion.String() || string(configMap.UID) != reference.UID {
		return betaSchedule{}, errors.New("resolved schedule ownership or UID changed")
	}
	if configMap.Annotations["testing.stacks.org/schedule-format"] != betaScheduleFormat ||
		configMap.Annotations["testing.stacks.org/schedule-digest"] != reference.Digest ||
		configMap.Annotations["testing.stacks.org/run-generation"] != fmt.Sprint(reference.RunGeneration) ||
		configMap.Annotations["testing.stacks.org/run-spec-digest"] != reference.RunSpecDigest || reference.RunGeneration != run.Generation {
		return betaSchedule{}, errors.New("resolved schedule metadata changed or no longer matches the run")
	}
	specDigest, err := canonical.ArtifactDigest(run.Spec)
	if err != nil || specDigest != reference.RunSpecDigest {
		return betaSchedule{}, errors.New("resolved schedule run inputs changed")
	}
	schedule, err := decodeBetaSchedule(configMap.BinaryData["schedule.json.gz"])
	if err != nil {
		return betaSchedule{}, err
	}
	if schedule.Integrity.Digest != reference.Digest {
		return betaSchedule{}, errors.New("resolved schedule reference digest changed")
	}
	return schedule, nil
}

func encodeBetaSchedule(schedule betaSchedule) ([]byte, error) {
	if err := validateBetaSchedule(schedule); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(schedule)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&output, gzip.BestCompression)
	writer.Header.OS = 255
	if _, err = writer.Write(plain); err != nil {
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	if output.Len() > 900_000 {
		return nil, errors.New("compressed resolved schedule exceeds 900 KiB")
	}
	return output.Bytes(), nil
}

func decodeBetaSchedule(payload []byte) (betaSchedule, error) {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return betaSchedule{}, err
	}
	defer reader.Close()
	decoder := json.NewDecoder(io.LimitReader(reader, 8<<20))
	decoder.DisallowUnknownFields()
	var schedule betaSchedule
	if err := decoder.Decode(&schedule); err != nil {
		return betaSchedule{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return betaSchedule{}, errors.New("resolved schedule contains trailing JSON")
	}
	if err := validateBetaSchedule(schedule); err != nil {
		return betaSchedule{}, err
	}
	return schedule, nil
}
