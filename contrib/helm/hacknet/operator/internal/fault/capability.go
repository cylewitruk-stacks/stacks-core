package fault

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

type capabilityObservation struct {
	Actor        string `json:"actor"`
	PodUID       string `json:"podUid"`
	Source       string `json:"source"`
	ObservedAt   string `json:"observedAt"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Supported    bool   `json:"supported"`
	Reason       string `json:"reason"`
}

func (r *Reconciler) capabilityEvidence(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, pods []corev1.Pod, targets []attacknetv1alpha1.ResolvedTarget) []capabilityObservation {
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	if definition.Capability == noCapability {
		return nil
	}
	result := make([]capabilityObservation, 0, len(targets))
	for _, target := range targets {
		base := capabilityObservation{Actor: target.Actor, PodUID: target.PodUID, Source: "attacknet-run-operator/v1", ObservedAt: r.now().Format("2006-01-02T15:04:05.000Z07:00")}
		switch definition.Capability {
		case ioPressureCapability:
			base.Platform, base.Architecture = "kubernetes-core-pod", "native-image"
			base.Supported = r.IOPressureImage != ""
			base.Reason = "controller-owned bounded I/O-pressure image is configured"
			if !base.Supported {
				base.Reason = "trusted I/O-pressure image is not configured"
			}
		case clockPolicyCapabilityKind:
			base.Platform, base.Architecture = "application-clock-policy", "image-contract"
			base.Supported, base.Reason = clockPodCapability(campaign, target, pods)
			policy := &corev1.ConfigMap{}
			if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef + "-clock-policy"}, policy); err != nil {
				base.Supported = false
				base.Reason = "application clock policy could not be read"
			} else if supported, reason := clockPolicyCapability(campaign, target, policy); !supported {
				base.Supported = false
				base.Reason = reason
			}
		default:
			probe := r.Probes
			if probe == nil {
				probe = HTTPProbeClient{}
			}
			response, err := probe.Probe(ctx, target, map[string]any{"kind": "system"})
			observation, _ := response["observation"].(map[string]any)
			base.Source = "attacknet-probe/v1"
			base.Platform, _ = observation["platform"].(string)
			base.Architecture, _ = observation["architecture"].(string)
			allowed := r.IOChaosArchitectures
			mechanism := "IOChaos"
			if definition.Capability == timeChaosCapability {
				allowed, mechanism = r.TimeChaosArchitectures, "TimeChaos"
			}
			if len(allowed) == 0 {
				allowed = map[string]bool{"x64": true}
			}
			base.Supported = err == nil && base.Platform == "linux" && allowed[base.Architecture]
			architectures := make([]string, 0, len(allowed))
			for architecture := range allowed {
				architectures = append(architectures, architecture)
			}
			sort.Strings(architectures)
			base.Reason = fmt.Sprintf("%s supports linux/%s; target reports %s/%s", mechanism, strings.Join(architectures, ","), base.Platform, base.Architecture)
			if err != nil {
				base.Reason = mechanism + " capability could not be established: " + truncate(err.Error(), 512)
			}
		}
		result = append(result, base)
	}
	return result
}

func clockPodCapability(campaign *attacknetv1alpha1.FaultCampaign, target attacknetv1alpha1.ResolvedTarget, pods []corev1.Pod) (bool, string) {
	policyName := campaign.Spec.NetworkRef + "-clock-policy"
	for _, pod := range pods {
		if string(pod.UID) != target.PodUID {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.Name != "actor" {
				continue
			}
			environment := map[string]string{}
			for _, variable := range container.Env {
				environment[variable.Name] = variable.Value
			}
			policyVolume := ""
			for _, mount := range container.VolumeMounts {
				if mount.MountPath == "/run/attacknet-clock" {
					policyVolume = mount.Name
					break
				}
			}
			mountedPolicy := false
			for _, volume := range pod.Spec.Volumes {
				if volume.Name == policyVolume && volume.ConfigMap != nil && volume.ConfigMap.Name == policyName {
					mountedPolicy = true
					break
				}
			}
			supported := mountedPolicy && environment["LD_PRELOAD"] == "/usr/lib/stacks-attacknet/libfaketime.so.1" && environment["FAKETIME_TIMESTAMP_FILE"] == "/run/attacknet-clock/"+target.Actor && environment["FAKETIME_DONT_FAKE_MONOTONIC"] == "1" && environment["FAKETIME_NO_CACHE"] == "1"
			if supported {
				return true, "libfaketime/v1 image environment and bound policy mount are present"
			}
		}
	}
	return false, "libfaketime/v1 image environment or bound policy mount is incomplete for " + campaign.Spec.NetworkRef
}

func clockPolicyCapability(campaign *attacknetv1alpha1.FaultCampaign, target attacknetv1alpha1.ResolvedTarget, policy *corev1.ConfigMap) (bool, string) {
	if policy.Labels[NetworkLabel] != campaign.Spec.NetworkRef || policy.Labels["testing.stacks.org/clock-policy"] != "true" {
		return false, "application clock policy has the wrong identity"
	}
	if len(policy.Data) == 0 {
		return false, "application clock policy has no actor entries"
	}
	for _, value := range policy.Data {
		if value != clockPolicyZero {
			return false, "application clock policy is not globally at zero offset"
		}
	}
	if policy.Data[target.Actor] != clockPolicyZero {
		return false, "application clock policy does not contain the target at zero offset"
	}
	return true, "application clock policy identity and global zero-offset state are established"
}
