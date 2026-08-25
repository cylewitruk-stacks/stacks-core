package fault

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func (r *Reconciler) transition(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, phase, reason, message string) error {
	return r.patchStatus(ctx, campaign, statusTransition(campaign.Status, campaign.Generation, phase, reason, message, r.now()))
}

func (r *Reconciler) fail(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, reason string, err error) error {
	log.FromContext(ctx).Error(err, "campaign failed", "reason", reason)
	next := statusTransition(campaign.Status, campaign.Generation, "Failed", reason, truncate(err.Error(), 1000), r.now())
	completed := metav1.NewTime(r.now())
	next.CompletedAt = &completed
	return r.patchStatus(ctx, campaign, next)
}

func (r *Reconciler) patchStatus(ctx context.Context, campaign *attacknetv1alpha1.FaultCampaign, next attacknetv1alpha1.FaultCampaignStatus) error {
	if reflect.DeepEqual(campaign.Status, next) {
		return nil
	}
	base := campaign.DeepCopy()
	campaign.Status = next
	return r.Status().Patch(ctx, campaign, client.MergeFrom(base))
}

func statusTransition(status attacknetv1alpha1.FaultCampaignStatus, generation int64, phase, reason, message string, now time.Time) attacknetv1alpha1.FaultCampaignStatus {
	status = *status.DeepCopy()
	changed := status.Phase != phase || status.Reason != reason
	status.ObservedGeneration = generation
	status.Phase, status.Reason, status.Message = phase, reason, message
	if changed || status.LastTransitionTime == nil {
		at := metav1.NewTime(now)
		status.LastTransitionTime = &at
	}
	conditionStatus := metav1.ConditionFalse
	if phase == "Passed" {
		conditionStatus = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Succeeded", Status: conditionStatus, ObservedGeneration: generation, Reason: reason, Message: message})
	return status
}

func rawJSON(value any) (apixv1.JSON, error) {
	encoded, err := json.Marshal(value)
	return apixv1.JSON{Raw: encoded}, err
}

func elapsed(timestamp *metav1.Time, now time.Time) time.Duration {
	if timestamp == nil {
		return 0
	}
	return now.Sub(timestamp.Time)
}

func assertionTimeout(assertions []attacknetv1alpha1.CampaignAssertion, fallback time.Duration) time.Duration {
	result := time.Duration(0)
	for _, assertion := range assertions {
		if assertion.TimeoutSeconds > 0 && time.Duration(assertion.TimeoutSeconds)*time.Second > result {
			result = time.Duration(assertion.TimeoutSeconds) * time.Second
		}
	}
	if result == 0 {
		return fallback
	}
	return result
}

func podEffectResults(campaign *attacknetv1alpha1.FaultCampaign, pods []corev1.Pod, observedAt time.Time) []apixv1.JSON {
	assertion := map[string]string{"pod-kill": "PodRestarted", "pod-failure": "PodUnavailable", "container-kill": "ContainerRestarted"}[campaign.Spec.Fault.Action]
	results := make([]apixv1.JSON, 0, len(campaign.Status.ResolvedTargets))
	for _, target := range campaign.Status.ResolvedTargets {
		var same *corev1.Pod
		for index := range pods {
			pod := &pods[index]
			if pod.DeletionTimestamp == nil && pod.Labels[NetworkLabel] == campaign.Spec.NetworkRef && pod.Labels[ActorLabel] == target.Actor && string(pod.UID) == target.PodUID {
				same = pod
				break
			}
		}
		outcome, message := "Failed", "admitted Pod state did not exhibit the requested effect"
		switch campaign.Spec.Fault.Action {
		case "pod-kill":
			if same == nil {
				outcome, message = "Proven", "the admitted Pod UID disappeared after injection"
			}
		case "pod-failure":
			if same == nil {
				outcome, message = "Inconclusive", "the admitted Pod disappeared instead of exhibiting pod-failure state"
			} else if !podIsReady(*same) {
				outcome, message = "Proven", "the admitted Pod became unavailable after injection"
			}
		case "container-kill":
			if same == nil {
				outcome, message = "Inconclusive", "the admitted Pod UID changed, so a container restart cannot be attributed"
			} else if actorRestartCount(*same) > target.RestartCount {
				outcome, message = "Proven", "the actor container restart count increased after injection"
			}
		}
		value, _ := rawJSON(map[string]any{"assertion": assertion, "outcome": outcome, "actor": target.Actor, "podUid": target.PodUID, "observedAt": observedAt, "message": message})
		results = append(results, value)
	}
	return results
}

func actorRestartCount(pod corev1.Pod) int32 {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "actor" {
			return status.RestartCount
		}
	}
	return -1
}

func provenResults(results []apixv1.JSON) int {
	count := 0
	for _, raw := range results {
		value := map[string]any{}
		if json.Unmarshal(raw.Raw, &value) == nil && value["outcome"] == "Proven" {
			count++
		}
	}
	return count
}

func minimumAffected(spec attacknetv1alpha1.FaultSpec, candidates int) int {
	value := 0
	if spec.Value != nil {
		value, _ = strconv.Atoi(spec.Value.String())
	}
	switch spec.Mode {
	case "all":
		return candidates
	case "fixed":
		return value
	case "fixed-percent":
		return int(math.Ceil(float64(candidates) * float64(value) / 100))
	default:
		return 1
	}
}

func evaluationResults(campaign *attacknetv1alpha1.FaultCampaign, report effectReport, observedAt time.Time) ([]apixv1.JSON, []apixv1.JSON) {
	effectAssertion := map[string]string{
		"network": "NetworkDegraded", "dns": "DNSDegraded", "io": "IODegraded",
		"io-pressure": "IOPressureObserved", "time": "ClockSkewObserved", "clock-skew": "ClockSkewObserved",
	}[campaign.Spec.Fault.Type]
	recoveryAssertion := map[string]string{
		"network": "NetworkRecovered", "dns": "DNSRecovered", "io": "IORecovered",
		"io-pressure": "IOPressureRecovered", "time": "ClockSkewCleared", "clock-skew": "ClockSkewCleared",
	}[campaign.Spec.Fault.Type]
	targets := map[string]string{}
	for _, target := range campaign.Status.ResolvedTargets {
		targets[target.Actor] = target.PodUID
	}
	effects, recoveries := make([]apixv1.JSON, 0, len(report.Evaluations)), make([]apixv1.JSON, 0, len(report.Evaluations))
	for _, evaluation := range report.Evaluations {
		effect, _ := rawJSON(map[string]any{"assertion": effectAssertion, "outcome": title(evaluation.Effect), "actor": evaluation.Actor, "podUid": targets[evaluation.Actor], "observedAt": observedAt, "message": evaluation.Reason})
		recoveryMessage := evaluation.RecoveryReason
		if recoveryMessage == "" {
			recoveryMessage = "trusted after-fault probe classified recovery=" + evaluation.Recovery
		}
		recovery, _ := rawJSON(map[string]any{"assertion": recoveryAssertion, "outcome": title(evaluation.Recovery), "actor": evaluation.Actor, "podUid": targets[evaluation.Actor], "observedAt": observedAt, "message": recoveryMessage})
		effects, recoveries = append(effects, effect), append(recoveries, recovery)
	}
	return effects, recoveries
}

func assertionsSatisfied(required []attacknetv1alpha1.CampaignAssertion, results []apixv1.JSON) bool {
	if len(required) == 0 {
		return true
	}
	for _, assertion := range required {
		matched := false
		for _, raw := range results {
			value := map[string]any{}
			if json.Unmarshal(raw.Raw, &value) == nil && value["outcome"] == "Proven" && value["assertion"] == assertion.Type && (assertion.Actor == "" || value["actor"] == assertion.Actor) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func title(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
