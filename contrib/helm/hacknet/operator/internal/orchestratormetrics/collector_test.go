package orchestratormetrics

import (
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestCollectorPreservesOrchestratorMetricContract(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(map[string]any{"actor": "signer-1", "assertion": "PodRestarted", "outcome": "Proven"})
	if err != nil {
		t.Fatal(err)
	}
	protocolEvidence, err := json.Marshal(map[string]any{"sources": []any{map[string]any{
		"actor": "signer-1", "role": "signer", "podName": "network-signer-1-0",
		"podUID": "pod-uid", "runtimeImageID": "sha256:image", "serviceName": "network-signer-1",
		"observedAt": "2026-08-26T12:00:00Z", "evidenceClass": "actor_self_reported",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "partition", Namespace: "test"},
		Spec:       attacknetv1beta1.FaultCampaignSpec{NetworkRef: "network"},
		Status: attacknetv1beta1.FaultCampaignStatus{
			Phase: "Passed", Reason: "AssertionsPassed",
			Stages: []attacknetv1beta1.FaultStageStatus{{ID: "stage-1", Actions: []attacknetv1beta1.FaultActionStatus{{
				ID: "action-1", ResolvedTargets: []attacknetv1beta1.ResolvedTarget{{Actor: "signer-1", Role: "signer", Node: "worker-1"}},
				EffectResults: []apixv1.JSON{{Raw: result}},
			}}}},
		},
	}
	run := &attacknetv1beta1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test"},
		Spec: attacknetv1beta1.AttacknetRunSpec{
			NetworkRef: "network", Minimization: attacknetv1beta1.MinimizationSpec{Enabled: true},
		},
		Status: attacknetv1beta1.AttacknetRunStatus{
			Phase: "Passed", Reason: "SequenceCompleted", Attribution: "NotRequired",
			ScheduleRef:     &attacknetv1beta1.ScheduleReference{Digest: "sha256:schedule"},
			ScheduleSummary: &attacknetv1beta1.ScheduleSummary{Replay: true},
			BudgetUsage:     &attacknetv1beta1.BudgetUsage{CampaignsStarted: 1, CumulativeFaultMillis: 30_000},
			TerminalClassification: &attacknetv1beta1.TerminalClassification{
				AttemptID: "attempt-1", CandidateScheduleDigest: "sha256:candidate",
				ExpectedAssertion: "ChainProgress", ExpectedStatus: "failed",
				Outcome: "reproduced", Reason: "ExpectedFailureObserved", EvidenceDigest: "sha256:evidence",
			},
			ProtocolAssertions: &attacknetv1beta1.ProtocolAssertionsStatus{
				Baseline: &attacknetv1beta1.ProtocolAssertionSetStatus{
					Outcome: "Proven",
					Results: []attacknetv1beta1.ProtocolAssertionResult{{
						ID: "telemetry-complete", Type: "TelemetryCompleteness", Outcome: "Proven", Reason: "AssertionSatisfied",
						Evidence: apixv1.JSON{Raw: protocolEvidence},
					}},
				},
			},
		},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(campaign, run).Build()
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(reader))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for _, family := range families {
		byName[family.GetName()] = len(family.Metric)
	}
	want := map[string]int{
		"attacknet_fault_campaign_info":                                      1,
		"attacknet_fault_campaign_target_info":                               1,
		"attacknet_fault_campaign_assertion_outcome":                         1,
		"attacknet_run_info":                                                 1,
		"attacknet_run_budget_usage":                                         11,
		"attacknet_run_minimization_outcome":                                 1,
		"attacknet_run_protocol_assertion":                                   1,
		"attacknet_run_protocol_assertion_source_info":                       1,
		"attacknet_run_protocol_assertion_source_observed_timestamp_seconds": 1,
		"attacknet_orchestrator_metrics_collection_success":                  1,
	}
	for name, count := range want {
		if byName[name] != count {
			t.Fatalf("metric family %s has %d samples, want %d; all=%v", name, byName[name], count, byName)
		}
	}
}

func TestCollectorFailsClosedWithoutAReader(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(nil))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 1 || families[0].GetName() != "attacknet_orchestrator_metrics_collection_success" || families[0].Metric[0].Gauge.GetValue() != 0 {
		t.Fatalf("nil reader did not expose a failed collection watchdog: %#v", families)
	}
}

func TestCollectorWatchdogFailsClosedOnMalformedEvidence(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "malformed", Namespace: "test"},
		Spec:       attacknetv1beta1.FaultCampaignSpec{NetworkRef: "network"},
		Status: attacknetv1beta1.FaultCampaignStatus{
			Stages: []attacknetv1beta1.FaultStageStatus{{ID: "stage-1", EffectResults: []apixv1.JSON{{Raw: []byte(`{"assertion":"NetworkDegraded"}`)}}}},
		},
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(fake.NewClientBuilder().WithScheme(scheme).WithObjects(campaign).Build()))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "attacknet_orchestrator_metrics_collection_success" {
			if family.Metric[0].Gauge.GetValue() != 0 {
				t.Fatal("malformed durable evidence was silently reported as a successful collection")
			}
			return
		}
	}
	t.Fatal("collection watchdog metric is absent")
}
