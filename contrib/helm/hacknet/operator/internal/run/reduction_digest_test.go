package run

import (
	"testing"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestReductionCandidateDigestBindsRetainedInstructions(t *testing.T) {
	retained := []attacknetv1beta1.RetainedExecution{
		{ExecutionID: "first", RemovedStages: []string{"delay"}},
		{ExecutionID: "second", RemovedTargets: []string{"stage/fault/actor"}},
	}
	digest, err := canonical.Digest(retained)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReductionCandidateDigest(retained, digest); err != nil {
		t.Fatalf("exact retained instructions were rejected: %v", err)
	}
	changed := append([]attacknetv1beta1.RetainedExecution(nil), retained...)
	changed[1].ExecutionID = "changed"
	if err := validateReductionCandidateDigest(changed, digest); err == nil {
		t.Fatal("changed retained instructions kept the prior candidate digest")
	}
}
