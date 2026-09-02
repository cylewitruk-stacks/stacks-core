package run

import (
	"fmt"
	"testing"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestTerminalClassificationFailsClosedOnMissingAndConflictingEvidence(t *testing.T) {
	run := &attacknetv1alpha1.AttacknetRun{ObjectMeta: metav1.ObjectMeta{Name: "replay", UID: types.UID("run-uid")}, Spec: attacknetv1alpha1.AttacknetRunSpec{Replay: attacknetv1alpha1.ReplaySpec{Enabled: true, VerifyExpectedFailure: true, AttemptID: "attempt-1", DescriptorDigest: "sha256:" + repeat("a", 64), ExpectedAssertion: "NetworkDegraded", ExpectedStatus: "Proven"}}, Status: attacknetv1alpha1.AttacknetRunStatus{ScheduleRef: &attacknetv1alpha1.ScheduleReference{Digest: "sha256:" + repeat("b", 64)}}}
	classification := classify(run, nil)
	if classification.Outcome != "Inconclusive" || classification.Reason != "ExpectedAssertionNotEvaluated" {
		t.Fatalf("missing evidence was not inconclusive: %#v", classification)
	}
	children := []attacknetv1alpha1.FaultCampaign{
		{ObjectMeta: metav1.ObjectMeta{Name: "a", UID: types.UID("a")}, Status: attacknetv1alpha1.FaultCampaignStatus{EffectResults: []apixv1.JSON{jsonResult(t, "NetworkDegraded", "Proven")}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "b", UID: types.UID("b")}, Status: attacknetv1alpha1.FaultCampaignStatus{EffectResults: []apixv1.JSON{jsonResult(t, "NetworkDegraded", "Failed")}}},
	}
	classification = classify(run, children)
	if classification.Outcome != "Inconclusive" || classification.Reason != "ConflictingExpectedAssertionEvidence" || classification.ObservationCount != 2 {
		t.Fatalf("conflicting evidence was misclassified: %#v", classification)
	}
}

func TestTerminalClassificationBoundsStoredEvidence(t *testing.T) {
	run := &attacknetv1alpha1.AttacknetRun{ObjectMeta: metav1.ObjectMeta{Name: "ddmin", UID: types.UID("run-uid")}, Spec: attacknetv1alpha1.AttacknetRunSpec{Minimization: attacknetv1alpha1.MinimizationSpec{Enabled: true, AttemptID: "attempt", CandidateDigest: "sha256:" + repeat("c", 64), ExpectedAssertion: "TargetReady", ExpectedStatus: "Failed"}}, Status: attacknetv1alpha1.AttacknetRunStatus{ScheduleRef: &attacknetv1alpha1.ScheduleReference{Digest: "sha256:" + repeat("d", 64)}}}
	results := make([]apixv1.JSON, 257)
	for index := range results {
		results[index] = jsonResult(t, "TargetReady", "Failed")
	}
	classification := classify(run, []attacknetv1alpha1.FaultCampaign{{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprint("child")}, Status: attacknetv1alpha1.FaultCampaignStatus{RecoveryResults: results}}})
	if classification.Outcome != "Inconclusive" || classification.Reason != "AssertionEvidenceLimitExceeded" || len(classification.Observations) != 256 || classification.ObservationCount != 257 {
		t.Fatalf("evidence limit was not enforced: %#v", classification)
	}
}

func jsonResult(t *testing.T, assertion, outcome string) apixv1.JSON {
	t.Helper()
	value, err := jsonValue(map[string]any{"assertion": assertion, "outcome": outcome, "actor": "actor"})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
