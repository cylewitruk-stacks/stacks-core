package run

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolassertion"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
)

func TestDuringAssertionsMeasureActiveFaultsAndFailClosedWhenWindowEnds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	reconciler := &V1Beta1Reconciler{Now: func() time.Time { return now }}
	assertions := &attacknetv1beta1.ProtocolAssertionSetSpec{
		Timeout: metav1.Duration{Duration: 30 * time.Second},
		Assertions: []attacknetv1beta1.ProtocolAssertionSpec{{
			ID:                    "complete",
			TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{Actors: []string{"node-1"}},
		}},
	}
	schedule := betaSchedule{
		Executions: []betaExecution{{ID: "one"}},
		Assertions: betaProtocolAssertions{During: assertions},
	}
	next := attacknetv1beta1.AttacknetRunStatus{}
	snapshot := protocolobservation.Snapshot{
		NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", ObservedAt: now,
		Actors: []protocolobservation.ActorSnapshot{{Source: protocolobservation.Source{
			Actor: "node-1", Role: "follower", ObservedAt: now,
			EvidenceClass: protocolobservation.EvidenceActorSelfReported,
		}}},
	}

	queued := &attacknetv1beta1.BudgetUsage{CampaignsStarted: 1, ActiveCampaigns: 1}
	gate, err := reconciler.evaluateProtocolAssertions(&next, schedule, queued, false, snapshot, false)
	if err != nil || gate != nil || next.ProtocolAssertions.During != nil {
		t.Fatalf("queued campaign was treated as an active fault: gate=%#v status=%#v err=%v", gate, next.ProtocolAssertions, err)
	}

	active := &attacknetv1beta1.BudgetUsage{CampaignsStarted: 1, ActiveCampaigns: 1, ActiveFaults: 1}
	gate, err = reconciler.evaluateProtocolAssertions(&next, schedule, active, true, snapshot, false)
	if err != nil || gate != nil || next.ProtocolAssertions.During == nil || next.ProtocolAssertions.During.Outcome != protocolassertion.OutcomeProven {
		t.Fatalf("active-fault observation was not proven: gate=%#v status=%#v err=%v", gate, next.ProtocolAssertions, err)
	}

	missed := attacknetv1beta1.AttacknetRunStatus{}
	completed := &attacknetv1beta1.BudgetUsage{CampaignsStarted: 1, CampaignsCompleted: 1}
	gate, err = reconciler.evaluateProtocolAssertions(&missed, schedule, completed, false, snapshot, false)
	if err != nil || gate == nil || gate.Outcome != protocolassertion.OutcomeInconclusive {
		t.Fatalf("missed active-fault window did not fail closed: gate=%#v status=%#v err=%v", gate, missed.ProtocolAssertions, err)
	}
}

func TestSuccessStopStillRequiresRecoveryAssertions(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	reconciler := &V1Beta1Reconciler{Now: func() time.Time { return now }}
	recovery := &attacknetv1beta1.ProtocolAssertionSetSpec{
		Timeout: metav1.Duration{Duration: 30 * time.Second},
		Assertions: []attacknetv1beta1.ProtocolAssertionSpec{{
			ID:                    "complete",
			TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{Actors: []string{"node-1"}},
		}},
	}
	schedule := betaSchedule{
		Executions: []betaExecution{{ID: "one"}, {ID: "two"}},
		Assertions: betaProtocolAssertions{Recovery: recovery},
	}
	next := attacknetv1beta1.AttacknetRunStatus{}
	usage := &attacknetv1beta1.BudgetUsage{CampaignsStarted: 1, CampaignsCompleted: 1}
	snapshot := protocolobservation.Snapshot{
		ObservedAt: now,
		Actors: []protocolobservation.ActorSnapshot{{
			Source: protocolobservation.Source{
				Actor: "node-1", Role: "follower", ObservedAt: now,
				EvidenceClass: protocolobservation.EvidenceActorSelfReported,
			},
		}},
	}
	gate, err := reconciler.evaluateProtocolAssertions(&next, schedule, usage, false, snapshot, true)
	if err != nil || gate != nil || next.ProtocolAssertions.Recovery == nil || next.ProtocolAssertions.Recovery.Outcome != protocolassertion.OutcomeProven {
		t.Fatalf("success-stop bypassed recovery assertions: gate=%#v status=%#v err=%v", gate, next.ProtocolAssertions, err)
	}
}

func TestSuccessStopWaitsForConcurrentCampaignRecovery(t *testing.T) {
	if !betaSuccessStopWaitsForActiveCampaigns("Passed", &attacknetv1beta1.BudgetUsage{ActiveCampaigns: 1}) {
		t.Fatal("success-stop was allowed to evaluate recovery while another campaign remained active")
	}
	for _, test := range []struct {
		name  string
		phase string
		usage *attacknetv1beta1.BudgetUsage
	}{
		{name: "no active campaign", phase: "Passed", usage: &attacknetv1beta1.BudgetUsage{}},
		{name: "ordinary execution", phase: "", usage: &attacknetv1beta1.BudgetUsage{ActiveCampaigns: 1}},
		{name: "nil usage", phase: "Passed", usage: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if betaSuccessStopWaitsForActiveCampaigns(test.phase, test.usage) {
				t.Fatal("pre-recovery wait was requested outside a concurrent success-stop")
			}
		})
	}
}

func TestProvenActiveFaultExcludesInjectionAndRecoveryTransitions(t *testing.T) {
	campaign := attacknetv1beta1.FaultCampaign{Status: attacknetv1beta1.FaultCampaignStatus{
		Stages: []attacknetv1beta1.FaultStageStatus{{
			ID: "stage", Actions: []attacknetv1beta1.FaultActionStatus{{ID: "action"}},
		}},
	}}
	action := &campaign.Status.Stages[0].Actions[0]
	for _, phase := range []string{"Pending", "Injecting", "Recovering", "Completed"} {
		action.Phase = phase
		if betaHasProvenActiveFault([]attacknetv1beta1.FaultCampaign{campaign}) {
			t.Fatalf("action phase %s was treated as independently proven active", phase)
		}
	}
	action.Phase = "Active"
	if !betaHasProvenActiveFault([]attacknetv1beta1.FaultCampaign{campaign}) {
		t.Fatal("independently proven Active action was not recognized")
	}
}
