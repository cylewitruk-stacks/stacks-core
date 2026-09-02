package orchestratormetrics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/versionmatrix"
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
	branchEvidence, err := json.Marshal(map[string]any{
		"sources": []any{map[string]any{
			"actor": "miner-1", "role": "miner", "podName": "network-miner-1-0",
			"podUID": "miner-pod-uid", "runtimeImageID": "sha256:miner-image", "serviceName": "network-miner-1",
			"observedAt": "2026-08-26T12:00:01Z", "evidenceClass": "actor_self_reported",
		}},
		"stacksObservations": map[string]any{"miner-1": map[string]any{
			"burnBlockHeight": 31, "burnConsensusHash": "123456789abcdeffedcba9876543210012345678", "bitcoinNodeRef": "bitcoin-a",
		}},
	})
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
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "test", Labels: map[string]string{"testing.stacks.org/fuzz-session": "nightly-one"}},
		Spec: attacknetv1beta1.AttacknetRunSpec{
			NetworkRef: "network", Minimization: attacknetv1beta1.MinimizationSpec{Enabled: true},
			FuzzProvenance: &attacknetv1beta1.FuzzProvenance{
				SessionDigest: "sha256:" + strings.Repeat("a", 64), TrialOrdinal: 1,
				PlanDigest: "sha256:" + strings.Repeat("b", 64), DecisionDigest: "sha256:" + strings.Repeat("c", 64),
				AttemptID: "source", AttemptKind: "Source",
			},
		},
		Status: attacknetv1beta1.AttacknetRunStatus{
			Phase: "Passed", Reason: "SequenceCompleted", Attribution: "NotRequired",
			ScheduleRef:     &attacknetv1beta1.ScheduleReference{Digest: "sha256:schedule"},
			ScheduleSummary: &attacknetv1beta1.ScheduleSummary{Replay: true},
			BudgetUsage:     &attacknetv1beta1.BudgetUsage{CampaignsStarted: 1, CumulativeFaultMillis: 30_000},
			TerminalClassification: &attacknetv1beta1.TerminalClassification{
				AttemptID: "attempt-1", CandidateDigest: "sha256:candidate",
				ExpectedAssertion: "ChainProgress", ExpectedStatus: "failed",
				Outcome: "reproduced", Reason: "ExpectedFailureObserved", EvidenceDigest: "sha256:evidence",
			},
			ProtocolAssertions: &attacknetv1beta1.ProtocolAssertionsStatus{
				Baseline: &attacknetv1beta1.ProtocolAssertionSetStatus{
					Outcome: "Proven",
					Results: []attacknetv1beta1.ProtocolAssertionResult{{
						ID: "telemetry-complete", Type: "TelemetryCompleteness", Outcome: "Proven", Reason: "AssertionSatisfied",
						Evidence: apixv1.JSON{Raw: protocolEvidence},
					}, {
						ID: "stacks-views", Type: "StacksBurnchainCohort", Outcome: "Proven", Reason: "BranchDivergenceObserved",
						Evidence: apixv1.JSON{Raw: branchEvidence},
					}},
				},
			},
		},
	}
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test"},
		Status: attacknetv1beta1.StacksNetworkStatus{BurnchainTopology: &attacknetv1beta1.AdmittedBurnchainTopology{
			Digest: "sha256:topology", ObservedGeneration: 7,
			Nodes: []attacknetv1beta1.AdmittedBitcoinNode{
				{Name: "bitcoin-a", ServiceName: "network-bitcoin-a", PolicyRef: "policy-a", PolicyUID: "uid-a", PolicyServiceName: "network-policy-a", PeerRefs: []string{"bitcoin-b"}},
				{Name: "bitcoin-b", ServiceName: "network-bitcoin-b", PolicyRef: "policy-b", PolicyUID: "uid-b", PolicyServiceName: "network-policy-b", PeerRefs: []string{"bitcoin-a"}},
			},
			Bindings: []attacknetv1beta1.BurnchainActorBinding{{Actor: "miner-1", BitcoinNodeRef: "bitcoin-a"}},
		}},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(campaign, run, network).Build()
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
		"attacknet_fuzz_run_info":                                            1,
		"attacknet_run_budget_usage":                                         11,
		"attacknet_run_minimization_outcome":                                 1,
		"attacknet_run_protocol_assertion":                                   2,
		"attacknet_run_protocol_assertion_source_info":                       2,
		"attacknet_run_protocol_assertion_source_observed_timestamp_seconds": 2,
		"attacknet_run_stacks_burn_view_height":                              1,
		"attacknet_run_stacks_burn_view_fingerprint":                         1,
		"attacknet_burnchain_topology_info":                                  1,
		"attacknet_burnchain_topology_observed_generation":                   1,
		"attacknet_burnchain_node_info":                                      2,
		"attacknet_burnchain_topology_edge_info":                             2,
		"attacknet_burnchain_actor_binding_info":                             1,
		"attacknet_orchestrator_metrics_collection_success":                  1,
	}
	for name, count := range want {
		if byName[name] != count {
			t.Fatalf("metric family %s has %d samples, want %d; all=%v", name, byName[name], count, byName)
		}
	}
	for _, family := range families {
		if family.GetName() != "attacknet_run_stacks_burn_view_fingerprint" {
			continue
		}
		labels := family.Metric[0].GetLabel()
		for _, label := range labels {
			if label.GetName() == "evidence_source" && label.GetValue() != actorEvidenceSource {
				t.Fatalf("Stacks burn-view value was mislabeled as %q evidence", label.GetValue())
			}
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

func TestCollectorExportsOnlyIdentityBoundAdversarialPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &attacknetv1beta1.AdversarialSignerPolicy{
		Profile: "stacks-signer-testing/v1", Behavior: "withhold", MaxMatches: 1, MaxEvaluations: 8,
		PatchDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Observer:    attacknetv1beta1.AdversarialObserverSpec{Image: "probe:test"},
		Egress:      attacknetv1beta1.AdversarialEgressSpec{Profile: "restricted"},
	}
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test"},
		Spec:       attacknetv1beta1.StacksNetworkSpec{SignerSets: []attacknetv1beta1.SignerSetSpec{{Name: "active", Members: []attacknetv1beta1.SignerMemberSpec{{Name: "signer-1", Adversarial: policy}}}}},
	}
	_, digest, err := adversarial.ResolveSigner(network, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	network.Status.Actors = []attacknetv1beta1.ActorStatus{
		{Name: "signer-1", IdentityReady: true, AdversarialPolicyDigest: digest, AdversarialEgressProfile: "restricted", EgressPolicyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{Name: "signer-1-observer", IdentityReady: true, AdversarialPolicyDigest: digest},
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(fake.NewClientBuilder().WithScheme(scheme).WithObjects(network).Build()))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "attacknet_adversarial_policy_info" {
			continue
		}
		labels := map[string]string{}
		for _, label := range family.Metric[0].GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}
		if labels["behavior"] != "withhold" || labels["egress_profile"] != "restricted" || labels["egress_policy_digest"] == "" || labels["observer_ready"] != "true" || labels["policy_digest"] != digest {
			t.Fatalf("adversarial metric was not identity-bound: %#v", labels)
		}
		return
	}
	t.Fatal("adversarial policy metric is absent")
}

func TestCollectorEmitsOneActuallyAdmittedVersionPerActor(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifest, err := json.Marshal(versionmatrix.RuntimeManifest{
		SchemaVersion: "stacks-attacknet-runtime-version-manifest/v1", DescriptorDigest: digest,
		Profiles:    []versionmatrix.RuntimeProfile{{Name: "base", SourceKind: "prebuilt", Image: "stacks:base", ImageID: digest, ProvenanceDigest: digest, ConfigDigest: digest, Capabilities: []string{"M01"}}},
		Assignments: []versionmatrix.RuntimeAssignment{{Actor: "miner-1", Profile: "base", ConfigDigest: digest}},
	})
	if err != nil {
		t.Fatal(err)
	}
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", Annotations: map[string]string{versionmatrix.RuntimeManifestAnnotation: string(manifest)}},
		Status:     attacknetv1beta1.StacksNetworkStatus{Actors: []attacknetv1beta1.ActorStatus{{Name: "miner-1", Image: "stacks:next", RuntimeImageID: "containerd://" + digest}}},
	}
	upgrade := &attacknetv1beta1.UpgradeCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "roll", Namespace: "test"},
		Spec:       attacknetv1beta1.UpgradeCampaignSpec{NetworkRef: "network", Profiles: []attacknetv1beta1.UpgradeProfileSpec{{Name: "next", SourceKind: "localGit", Image: "stacks:next", ImageID: digest, ProvenanceDigest: digest, ConfigDigest: digest, Capabilities: []string{"M02"}}}},
		Status:     attacknetv1beta1.UpgradeCampaignStatus{Phase: "Passed", BaselineInventory: &attacknetv1beta1.NetworkInventory{Digest: digest}, AppliedAssignments: []attacknetv1beta1.UpgradeAssignment{{Actor: "miner-1", Profile: "next"}}},
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(fake.NewClientBuilder().WithScheme(scheme).WithObjects(network, upgrade).Build()))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "attacknet_actor_version_info" {
			continue
		}
		labels := map[string]string{}
		if len(family.Metric) == 1 {
			for _, label := range family.Metric[0].GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
		}
		if len(family.Metric) != 1 || labels["profile"] != "next" || labels["campaign"] != "roll" {
			t.Fatalf("version series did not replace stale static profile: %#v", family.Metric)
		}
		return
	}
	t.Fatal("actor version metric is absent")
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

func TestProvenStacksBurnViewRequiresBoundedEvidence(t *testing.T) {
	if _, ok := decodeStacksBurnViews("StacksBurnchainCohort", "Proven", []byte(`{"stacksObservations":{}}`)); ok {
		t.Fatal("a proven Stacks burn-view assertion accepted empty evidence")
	}
	if _, ok := decodeStacksBurnViews("StacksBurnchainCohort", "Pending", []byte(`{"stacksObservations":{}}`)); !ok {
		t.Fatal("a pending Stacks burn-view assertion rejected an unavailable observation")
	}
}
