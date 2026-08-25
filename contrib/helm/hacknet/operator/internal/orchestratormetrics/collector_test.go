package orchestratormetrics

import (
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func TestCollectorPreservesOrchestratorMetricContract(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(map[string]any{"actor": "signer-1", "assertion": "PodRestarted", "outcome": "Proven"})
	if err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "partition", Namespace: "test"},
		Spec: attacknetv1alpha1.FaultCampaignSpec{
			NetworkRef: "network", Fault: attacknetv1alpha1.FaultSpec{Type: "pod"},
		},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			Phase: "Passed", Reason: "AssertionsPassed",
			ResolvedTargets: []attacknetv1alpha1.ResolvedTarget{{Actor: "signer-1", Role: "signer", Node: "worker-1"}},
			EffectResults:   []apixv1.JSON{{Raw: result}},
		},
	}
	run := &attacknetv1alpha1.AttacknetRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test"},
		Spec: attacknetv1alpha1.AttacknetRunSpec{
			NetworkRef: "network", Minimization: attacknetv1alpha1.MinimizationSpec{Enabled: true},
		},
		Status: attacknetv1alpha1.AttacknetRunStatus{
			Phase: "Passed", Reason: "SequenceCompleted", Attribution: "NotRequired",
			ScheduleRef:     &attacknetv1alpha1.ScheduleReference{Digest: "sha256:schedule"},
			ScheduleSummary: &attacknetv1alpha1.ScheduleSummary{Replay: true},
			BudgetUsage:     &attacknetv1alpha1.BudgetUsage{CampaignsStarted: 1, CumulativeFaultSeconds: 30},
			TerminalClassification: &attacknetv1alpha1.TerminalClassification{
				AttemptID: "attempt-1", CandidateScheduleDigest: "sha256:candidate",
				ExpectedAssertion: "ChainProgress", ExpectedStatus: "failed",
				Outcome: "reproduced", Reason: "ExpectedFailureObserved", EvidenceDigest: "sha256:evidence",
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
		"attacknet_fault_campaign_info":                     1,
		"attacknet_fault_campaign_target_info":              1,
		"attacknet_fault_campaign_assertion_outcome":        1,
		"attacknet_run_info":                                1,
		"attacknet_run_budget_usage":                        10,
		"attacknet_run_minimization_outcome":                1,
		"attacknet_orchestrator_metrics_collection_success": 1,
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
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	campaign := &attacknetv1alpha1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "malformed", Namespace: "test"},
		Spec:       attacknetv1alpha1.FaultCampaignSpec{NetworkRef: "network"},
		Status: attacknetv1alpha1.FaultCampaignStatus{
			EffectResults: []apixv1.JSON{{Raw: []byte(`{"assertion":"NetworkDegraded"}`)}},
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
