package run

import (
	"strings"
	"testing"
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
}
