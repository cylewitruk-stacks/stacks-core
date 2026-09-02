package run

import (
	"errors"
	"fmt"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

// validateReductionCandidateDigest binds a minimization request to its exact
// ordered retained instructions. Fresh-network resolved schedules are sealed
// independently after admission and therefore have a distinct digest.
func validateReductionCandidateDigest(retained any, expected string) error {
	if expected == "" {
		return errors.New("minimization candidateDigest is required")
	}
	actual, err := canonical.Digest(retained)
	if err != nil {
		return fmt.Errorf("digest minimization candidate: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("minimization candidateDigest %s does not match retained instructions %s", expected, actual)
	}
	return nil
}
