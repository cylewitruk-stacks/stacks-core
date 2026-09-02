package fuzzsession

import (
	"errors"
	"sort"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
)

// Classify interprets only bounded controller status and complete retained
// evidence. Free-form logs never influence the primary result.
func Classify(result TrialResult) (Classification, error) {
	if result.Phase == "" || result.Reason == "" || result.Attribution == "" {
		return Classification{}, errors.New("trial result is incomplete or invalid")
	}
	classification := Classification{Reason: result.Reason}
	switch {
	case !result.EvidenceComplete || !result.IncidentBundleSealed || !result.LokiExportComplete:
		classification.Class = "HarnessFailed"
		classification.Reason = "RequiredEvidenceIncomplete"
	case result.Phase == "Passed" &&
		(len(result.ViolatedAssertions) != 0 || result.IdentityDivergence != ""):
		classification.Class = "HarnessFailed"
		classification.Reason = "ContradictoryTerminalResult"
	case result.Phase == "Passed":
		classification.Class = "Clean"
	case result.Phase == "Inconclusive":
		classification.Class = "Inconclusive"
	case result.Phase == "Failed":
		if result.Attribution != "ProtocolAssertion" || len(result.ViolatedAssertions) == 0 {
			classification.Class = "HarnessFailed"
			break
		}
		classification.Class = "NetworkFailureCandidate"
	default:
		classification.Class = "HarnessFailed"
		classification.Reason = "UnexpectedTerminalPhase"
	}
	assertions := append([]string(nil), result.ViolatedAssertions...)
	families := append([]string(nil), result.MechanismFamilies...)
	sort.Strings(assertions)
	sort.Strings(families)
	fingerprint, err := fuzzcorpus.SemanticFingerprint(fuzzcorpus.FingerprintInput{
		SchemaVersion: fuzzcorpus.FingerprintSchema,
		Phase:         result.Phase, Reason: classification.Reason, Attribution: result.Attribution,
		AssertionResults: assertions, MechanismFamilies: families,
		IdentityDivergence:  result.IdentityDivergence,
		VersionCohortDigest: result.VersionCohortDigest,
	})
	if err != nil {
		return Classification{}, err
	}
	classification.Fingerprint = fingerprint
	return classification, nil
}
