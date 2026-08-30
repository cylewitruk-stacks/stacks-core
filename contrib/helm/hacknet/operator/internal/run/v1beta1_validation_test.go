package run

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestValidateV1Beta1StructureRejectsInvalidRunContracts(t *testing.T) {
	t.Run("budget relation", func(t *testing.T) {
		run, _, _, _, _ := betaScheduleFixture()
		run.Spec.Budgets.MaxCumulativeFaultSeconds = run.Spec.Budgets.MaxWallTimeSeconds + 1
		err := ValidateV1Beta1Structure(run)
		if err == nil || !strings.Contains(err.Error(), "cannot exceed") {
			t.Fatalf("got %v, want cumulative budget rejection", err)
		}
	})
	t.Run("unknown campaign alias", func(t *testing.T) {
		run, _, _, _, _ := betaScheduleFixture()
		run.Spec.Executions[0].Campaign = "missing"
		err := ValidateV1Beta1Structure(run)
		if err == nil || !strings.Contains(err.Error(), "unknown campaign alias") {
			t.Fatalf("got %v, want unknown campaign rejection", err)
		}
	})
	t.Run("replay resume conflict", func(t *testing.T) {
		run, _, _, _, _ := betaScheduleFixture()
		run.Spec.Replay.Enabled = true
		run.Spec.Resume.Enabled = true
		err := ValidateV1Beta1Structure(run)
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("got %v, want replay-mode rejection", err)
		}
	})
	t.Run("malformed protocol assertion", func(t *testing.T) {
		run, _, _, _, _ := betaScheduleFixture()
		run.Spec.BaselineAssertions = &attacknetv1beta1.ProtocolAssertionSetSpec{
			Timeout: metav1.Duration{Duration: time.Minute},
			Assertions: []attacknetv1beta1.ProtocolAssertionSpec{{
				ID: "ambiguous",
				ChainProgress: &attacknetv1beta1.ChainProgressAssertion{
					Chain: "stacks", Actors: []string{"miner-1"}, Window: metav1.Duration{Duration: 30 * time.Second}, MinimumDelta: 1,
				},
				TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{Actors: []string{"miner-1"}},
			}},
		}
		err := ValidateV1Beta1Structure(run)
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("got %v, want ambiguous assertion rejection", err)
		}
	})
	t.Run("multiple persistent upgrade overlays", func(t *testing.T) {
		run, _, _, _, _ := betaScheduleFixture()
		run.Spec.UpgradeCatalog = []attacknetv1beta1.UpgradeCatalogEntry{{Name: "upgrade", UpgradeRef: "upgrade-template"}}
		run.Spec.Executions = []attacknetv1beta1.RunExecutionSpec{
			{ID: "upgrade-one", Upgrade: "upgrade"},
			{ID: "upgrade-two", Upgrade: "upgrade"},
		}
		err := ValidateV1Beta1Structure(run)
		if err == nil || !strings.Contains(err.Error(), "one UpgradeCampaign execution") {
			t.Fatalf("got %v, want persistent-overlay rejection", err)
		}
	})
	t.Run("upgrade dependencies are terminal", func(t *testing.T) {
		run, _, _, _, _ := betaScheduleFixture()
		run.Spec.UpgradeCatalog = []attacknetv1beta1.UpgradeCatalogEntry{{Name: "upgrade", UpgradeRef: "upgrade-template"}}
		run.Spec.Executions = []attacknetv1beta1.RunExecutionSpec{
			{ID: "upgrade", Upgrade: "upgrade"},
			{ID: "fault", Campaign: run.Spec.CampaignCatalog[0].Name, DependsOn: []attacknetv1beta1.RunExecutionDependency{{Execution: "upgrade", State: "Recovered"}}},
		}
		err := ValidateV1Beta1Structure(run)
		if err == nil || !strings.Contains(err.Error(), "at Terminal") {
			t.Fatalf("got %v, want unsupported transition rejection", err)
		}
	})
}
