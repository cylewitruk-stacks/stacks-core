package fault

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/ownership"
)

func (r *Reconciler) buildIOPressurePod(campaign *attacknetv1alpha1.FaultCampaign, pods []corev1.Pod, compiled Compiled) (*corev1.Pod, error) {
	if r.IOPressureImage == "" {
		return nil, errors.New("trusted I/O-pressure image is not configured")
	}
	if len(campaign.Status.ResolvedTargets) != 1 {
		return nil, errors.New("disk-pressure requires exactly one admitted target")
	}
	target := campaign.Status.ResolvedTargets[0]
	var source *corev1.Pod
	for index := range pods {
		if string(pods[index].UID) == target.PodUID {
			source = &pods[index]
		}
	}
	if source == nil || source.Spec.NodeName != target.Node {
		return nil, errors.New("exact admitted disk-pressure target changed")
	}
	claim := ""
	for _, container := range source.Spec.Containers {
		if container.Name != "actor" {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/data" {
				continue
			}
			for _, volume := range source.Spec.Volumes {
				if volume.Name == mount.Name && volume.PersistentVolumeClaim != nil {
					claim = volume.PersistentVolumeClaim.ClaimName
				}
			}
		}
	}
	if claim == "" {
		return nil, errors.New("admitted actor has no persistent /data claim")
	}
	workers := parameterNumber(compiled.Evidence.Parameters, "workers")
	bytesMiB := parameterNumber(compiled.Evidence.Parameters, "bytesMiB")
	writeKiB := parameterNumber(compiled.Evidence.Parameters, "writeSizeKiB")
	duration, _ := time.ParseDuration(campaign.Spec.Fault.Duration)
	runAs := int64(65532)
	grace := int64(10)
	readOnly := true
	allow := false
	nonRoot := true
	seccomp := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	fsGroup := runAs
	if source.Spec.SecurityContext != nil && source.Spec.SecurityContext.FSGroup != nil {
		fsGroup = *source.Spec.SecurityContext.FSGroup
	}
	if fsGroup <= 0 {
		return nil, errors.New("target Pod fsGroup must be a positive non-root integer")
	}
	pull := r.IOPressurePull
	if pull == "" {
		pull = corev1.PullIfNotPresent
	}
	contractJSON, err := json.Marshal(compiled.Evidence.IOPressure)
	if err != nil {
		return nil, err
	}
	fsPolicy := corev1.FSGroupChangeOnRootMismatch
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: stableFaultName("io-pressure", campaign.Name), Namespace: campaign.Namespace, Labels: map[string]string{NetworkLabel: campaign.Spec.NetworkRef, "testing.stacks.org/campaign": campaign.Name, "testing.stacks.org/mechanism": "controller-owned-io-pressure-pod"}, Annotations: map[string]string{"testing.stacks.org/io-pressure-contract": string(contractJSON), "testing.stacks.org/target-pod-uid": target.PodUID, "testing.stacks.org/target-pvc": claim}, OwnerReferences: []metav1.OwnerReference{ownership.Reference(campaign, attacknetv1alpha1.GroupVersion.WithKind("FaultCampaign"))}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: ptr(false), RestartPolicy: corev1.RestartPolicyNever, TerminationGracePeriodSeconds: &grace, NodeName: target.Node, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonRoot, FSGroup: &fsGroup, FSGroupChangePolicy: &fsPolicy, SeccompProfile: seccomp}, Containers: []corev1.Container{{Name: "io-pressure", Image: r.IOPressureImage, ImagePullPolicy: pull, Args: []string{"--duration-seconds", fmt.Sprint(int64(duration.Seconds())), "--workers", fmt.Sprint(workers), "--bytes-mib", fmt.Sprint(bytesMiB), "--write-size-kib", fmt.Sprint(writeKiB), "--scratch-path", "/data/.attacknet-io-pressure-" + string(campaign.UID)}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &allow, ReadOnlyRootFilesystem: &readOnly, RunAsNonRoot: &nonRoot, RunAsUser: &runAs, RunAsGroup: &runAs, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: seccomp}, Resources: ioPressureResources(fmt.Sprint(compiled.Evidence.IOPressure["severity"])), VolumeMounts: []corev1.VolumeMount{{Name: "actor-data", MountPath: "/data"}}}}, Volumes: []corev1.Volume{{Name: "actor-data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}}}}
	return pod, nil
}

func ioPressureResources(severity string) corev1.ResourceRequirements {
	values := map[string][4]string{
		"low":    {"25m", "24Mi", "250m", "64Mi"},
		"medium": {"50m", "24Mi", "500m", "64Mi"},
		"high":   {"100m", "24Mi", "1", "96Mi"},
	}[severity]
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(values[0]), corev1.ResourceMemory: resource.MustParse(values[1])},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(values[2]), corev1.ResourceMemory: resource.MustParse(values[3])},
	}
}
