package conversion

import (
	"errors"
	"strings"
	"testing"
	"time"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestFaultCampaignConversionPreservesPolicyAndPayload(t *testing.T) {
	input := []byte(`
apiVersion: testing.stacks.org/v1alpha1
kind: FaultCampaign
metadata:
  name: network-delay
  namespace: test
  labels: {purpose: migration}
spec:
  template: true
  networkRef: attacknet
  target:
    actors: [miner-1]
  fault:
    type: network
    action: delay
    mode: all
    duration: 15s
    parameters:
      delay: {latency: 250ms}
  safety:
    maxUnavailableSignerPercent: 30.25
    maxUnavailableMinerPercent: 50
    allowExtremeSeverity: true
  effectAssertions:
    - type: NetworkDegraded
      actor: miner-1
      timeoutSeconds: 90
`)
	object, err := V1Alpha1Document(input)
	if err != nil {
		t.Fatal(err)
	}
	campaign := object.(*attacknetv1beta1.FaultCampaign)
	if campaign.APIVersion != "testing.stacks.org/v1beta1" || campaign.Labels["purpose"] != "migration" {
		t.Fatalf("metadata not preserved: %#v", campaign.ObjectMeta)
	}
	if campaign.Spec.Safety.MaxUnavailableSignerBasisPoints != 3025 || campaign.Spec.Safety.MaxUnavailableMinerBasisPoints != 5000 || campaign.Spec.Safety.MaxConcurrentFaults != 1 {
		t.Fatalf("safety not preserved: %#v", campaign.Spec.Safety)
	}
	stage := campaign.Spec.Stages[0]
	if stage.ID != "fault" || len(stage.Faults) != 1 || stage.Faults[0].Fault.Duration.Duration != 15*time.Second {
		t.Fatalf("single-fault mapping = %#v", stage)
	}
	if string(stage.Faults[0].Fault.Parameters.Raw) != `{"delay":{"latency":"250ms"}}` {
		t.Fatalf("parameters = %s", stage.Faults[0].Fault.Parameters.Raw)
	}
	if campaign.Spec.EffectAssertions[0].Type != "NetworkDegraded" {
		t.Fatalf("assertions = %#v", campaign.Spec.EffectAssertions)
	}
}

func TestAttacknetRunConversionMakesSerialOrderExplicit(t *testing.T) {
	input := []byte(`
apiVersion: testing.stacks.org/v1alpha1
kind: AttacknetRun
metadata: {name: serial-run}
spec:
  networkRef: attacknet
  seed: seed
  campaignCatalog:
    - {name: first, campaignRef: first-template}
    - {name: second, campaignRef: second-template}
  sequence:
    - {id: one, campaign: first, delayAfterSeconds: 7}
    - {id: skipped, campaign: first, delayAfterSeconds: 30, enabled: false}
    - {id: two, campaign: second}
  budgets:
    maxCampaigns: 2
    maxWallTimeSeconds: 300
    maxCumulativeFaultSeconds: 100
    maxActiveFaults: 1
    maxSignerImpactPercent: 30
    maxBurnchainFaults: 0
    maxInconclusiveCampaigns: 0
  stopPolicy: {onCampaignFailure: Stop, onInconclusive: Stop, onBudgetExhausted: Stop, onSuccess: Continue}
  attributionPolicy: {requiredOnFailure: true, requireIncidentBundle: true, allowedTerminalStates: [Triaged]}
  replay: {enabled: false, requireSameResolvedImages: true, verifyExpectedFailure: true}
  resume: {enabled: true, afterInstructionId: one, requireSameSeed: true, requireSameResolvedImages: true}
  minimization:
    enabled: true
    strategy: FailurePrefix
    maxAttempts: 1
    requireFreshNetwork: true
    retained:
      - {instructionId: one, removedTargets: [miner-2]}
`)
	object, err := V1Alpha1Document(input)
	if err != nil {
		t.Fatal(err)
	}
	run := object.(*attacknetv1beta1.AttacknetRun)
	if len(run.Spec.Executions) != 3 || run.Spec.Executions[1].Enabled == nil || *run.Spec.Executions[1].Enabled {
		t.Fatalf("executions = %#v", run.Spec.Executions)
	}
	dependency := run.Spec.Executions[2].DependsOn
	if len(dependency) != 1 || dependency[0].Execution != "one" || dependency[0].State != "Terminal" || dependency[0].Delay.Duration != 7*time.Second {
		t.Fatalf("serial dependency = %#v", dependency)
	}
	if run.Spec.Resume.AfterExecutionID != "one" || run.Spec.Minimization.Retained[0].ExecutionID != "one" {
		t.Fatalf("renamed execution fields not converted: %#v %#v", run.Spec.Resume, run.Spec.Minimization)
	}
}

func TestConversionRefusesUnrepresentableOrUnsafeInputs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		message string
	}{
		{
			name:    "aggregate topology",
			input:   `{"apiVersion":"testing.stacks.org/v1alpha1","kind":"StacksNetwork","metadata":{"name":"network"},"spec":{}}`,
			message: "no lossless v1alpha1 mapping",
		},
		{
			name:    "controller status",
			input:   `{"apiVersion":"testing.stacks.org/v1alpha1","kind":"FaultCampaign","metadata":{"name":"fault"},"spec":{},"status":{}}`,
			message: "must omit the controller-owned status",
		},
		{
			name:    "final serial delay",
			input:   `{"apiVersion":"testing.stacks.org/v1alpha1","kind":"AttacknetRun","metadata":{"name":"run"},"spec":{"sequence":[{"id":"one","campaign":"fault","delayAfterSeconds":1}]}}`,
			message: "no lossless v1beta1 mapping",
		},
		{
			name:    "unknown field",
			input:   `{"apiVersion":"testing.stacks.org/v1alpha1","kind":"FaultCampaign","metadata":{"name":"fault"},"spec":{"surprise":true}}`,
			message: "unknown field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := V1Alpha1Document([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
			var unsupported UnsupportedKindError
			if test.name == "aggregate topology" && !errors.As(err, &unsupported) {
				t.Fatalf("error type = %T, want UnsupportedKindError", err)
			}
		})
	}
}
